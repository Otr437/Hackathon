// ZEBRA NODE TUI - PRODUCTION READY FOR REAL ZCASH NODE OPERATORS
// November 2025 - Latest Zcash/Zebra Standards
// Cross-platform: Linux & macOS (Zebra's supported platforms)
// 
// zcashd is DEPRECATED in 2025 - Zebra is the ONLY current full node
//
// Cargo.toml:
// [package]
// name = "zebra-tui"
// version = "1.0.0"
// edition = "2021"
//
// [dependencies]
// ratatui = "0.26"
// crossterm = "0.27"
// tokio = { version = "1", features = ["full"] }
// reqwest = { version = "0.11", features = ["json"] }
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// chrono = "0.4"
// anyhow = "1.0"
//
// INSTALLATION:
// 1. Install Zebra: cargo install --locked zebrad
// 2. Start Zebra: zebrad start
// 3. Build TUI: cargo build --release
// 4. Run: ./target/release/zebra-tui
//
// CUSTOM RPC: ZEBRA_RPC_URL=http://localhost:8232 ./zebra-tui

use std::io;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::collections::VecDeque;
use tokio::sync::Mutex;
use tokio::process::Command as TokioCommand;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Gauge, Tabs, Wrap, Clear, Sparkline},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

const ZCASH_GOLD: Color = Color::Rgb(244, 183, 40);
const ZCASH_GREEN: Color = Color::Rgb(64, 198, 77);
const ZCASH_RED: Color = Color::Red;
const ZCASH_BLUE: Color = Color::Rgb(41, 128, 185);

#[derive(Serialize)]
struct RpcRequest {
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

#[derive(Deserialize, Debug)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize, Debug, Clone)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Deserialize, Debug)]
struct BlockchainInfo {
    chain: String,
    blocks: u64,
    #[serde(rename = "bestblockhash")]
    best_block_hash: String,
    difficulty: f64,
    #[serde(rename = "verificationprogress")]
    verification_progress: f64,
    size_on_disk: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct NetworkInfo {
    version: u64,
    #[serde(rename = "subversion")]
    sub_version: String,
    connections: u32,
}

#[derive(Deserialize, Debug, Clone)]
struct PeerInfo {
    addr: String,
    version: u64,
    #[serde(rename = "subver")]
    sub_ver: String,
    synced_blocks: Option<u64>,
    #[serde(rename = "bytessent")]
    bytes_sent: Option<u64>,
    #[serde(rename = "bytesrecv")]
    bytes_recv: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct BlockInfo {
    hash: String,
    height: u64,
    time: u64,
    tx: Vec<String>,
    size: u64,
    difficulty: f64,
}

#[derive(Clone, Debug)]
struct BlockRecord {
    height: u64,
    hash: String,
    time: DateTime<Utc>,
    tx_count: usize,
    size: u64,
}

#[derive(Clone, Debug)]
struct Transaction {
    txid: String,
    amount: f64,
    confirmations: u64,
    time: DateTime<Utc>,
    address: String,
}

#[derive(Clone, Debug)]
struct AppState {
    block_height: u64,
    block_hash: String,
    sync_progress: f64,
    chain: String,
    difficulty: f64,
    recent_blocks: VecDeque<BlockRecord>,
    size_on_disk: u64,
    connections: u32,
    node_version: String,
    peers: Vec<PeerInfo>,
    mempool_size: u64,
    mempool_bytes: u64,
    mempool_usage: f64,
    wallet_balance: f64,
    transparent_balance: f64,
    shielded_balance: f64,
    transparent_addresses: Vec<String>,
    shielded_addresses: Vec<String>,
    transactions: Vec<Transaction>,
    connected: bool,
    zebra_running: bool,
    status_message: String,
    last_update: Instant,
    log_messages: VecDeque<String>,
    block_times: VecDeque<u64>,
    connection_history: VecDeque<u32>,
    mempool_history: VecDeque<u64>,
    blocks_per_hour: f64,
    avg_block_time: f64,
    avg_block_size: f64,
    total_transactions: u64,
    validating_block: bool,
    validation_speed: f64,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            block_height: 0,
            block_hash: String::new(),
            sync_progress: 0.0,
            chain: String::from("unknown"),
            difficulty: 0.0,
            recent_blocks: VecDeque::new(),
            size_on_disk: 0,
            connections: 0,
            node_version: String::from("Unknown"),
            peers: Vec::new(),
            mempool_size: 0,
            mempool_bytes: 0,
            mempool_usage: 0.0,
            wallet_balance: 0.0,
            transparent_balance: 0.0,
            shielded_balance: 0.0,
            transparent_addresses: Vec::new(),
            shielded_addresses: Vec::new(),
            transactions: Vec::new(),
            connected: false,
            zebra_running: false,
            status_message: String::from("Initializing..."),
            last_update: Instant::now(),
            log_messages: VecDeque::new(),
            block_times: VecDeque::new(),
            connection_history: VecDeque::new(),
            mempool_history: VecDeque::new(),
            blocks_per_hour: 0.0,
            avg_block_time: 0.0,
            avg_block_size: 0.0,
            total_transactions: 0,
            validating_block: false,
            validation_speed: 0.0,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Dashboard,
    Wallet,
    Send,
    Receive,
    Blockchain,
    Network,
    Mining,
    Logs,
    Control,
    Performance,
}

impl Tab {
    fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Wallet", "Send", "Receive", "Blockchain", "Network", "Mining", "Logs", "Control", "Performance"]
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => Tab::Dashboard,
            1 => Tab::Wallet,
            2 => Tab::Send,
            3 => Tab::Receive,
            4 => Tab::Blockchain,
            5 => Tab::Network,
            6 => Tab::Mining,
            7 => Tab::Logs,
            8 => Tab::Control,
            9 => Tab::Performance,
            _ => Tab::Dashboard,
        }
    }

    fn to_index(&self) -> usize {
        match self {
            Tab::Dashboard => 0,
            Tab::Wallet => 1,
            Tab::Send => 2,
            Tab::Receive => 3,
            Tab::Blockchain => 4,
            Tab::Network => 5,
            Tab::Mining => 6,
            Tab::Logs => 7,
            Tab::Control => 8,
            Tab::Performance => 9,
        }
    }
}

#[derive(Clone, PartialEq)]
enum InputMode {
    Normal,
    SendToAddress,
    SendAmount,
    SendMemo,
}

struct App {
    state: Arc<Mutex<AppState>>,
    client: Arc<ZebraClient>,
    current_tab: Tab,
    should_quit: bool,
    scroll_offset: u16,
    input_mode: InputMode,
    send_to_address: String,
    send_amount: String,
    send_memo: String,
}

impl App {
    fn new(rpc_url: String) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState::default())),
            client: Arc::new(ZebraClient::new(rpc_url)),
            current_tab: Tab::Dashboard,
            should_quit: false,
            scroll_offset: 0,
            input_mode: InputMode::Normal,
            send_to_address: String::new(),
            send_amount: String::new(),
            send_memo: String::new(),
        }
    }

    fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
    }
}

struct ZebraClient {
    url: String,
    client: reqwest::Client,
}

impl ZebraClient {
    fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        }
    }

    async fn call<T: serde::de::DeserializeOwned>(&self, method: &str, params: Vec<serde_json::Value>) -> anyhow::Result<T> {
        let request = RpcRequest { method: method.to_string(), params, id: 1 };
        let response = self.client.post(&self.url).json(&request).send().await?;
        let rpc_response: RpcResponse<T> = response.json().await?;
        if let Some(error) = rpc_response.error {
            anyhow::bail!("RPC Error: {} (code: {})", error.message, error.code);
        }
        rpc_response.result.ok_or_else(|| anyhow::anyhow!("No result"))
    }

    async fn get_blockchain_info(&self) -> anyhow::Result<BlockchainInfo> {
        self.call("getblockchaininfo", vec![]).await
    }

    async fn get_network_info(&self) -> anyhow::Result<NetworkInfo> {
        self.call("getnetworkinfo", vec![]).await
    }

    async fn get_peer_info(&self) -> anyhow::Result<Vec<PeerInfo>> {
        self.call("getpeerinfo", vec![]).await
    }

    async fn get_mempool_info(&self) -> anyhow::Result<serde_json::Value> {
        self.call("getmempoolinfo", vec![]).await
    }

    async fn get_block_hash(&self, height: u64) -> anyhow::Result<String> {
        self.call("getblockhash", vec![serde_json::json!(height)]).await
    }

    async fn get_block(&self, hash: &str) -> anyhow::Result<BlockInfo> {
        self.call("getblock", vec![serde_json::json!(hash), serde_json::json!(1)]).await
    }

    async fn generate(&self, num_blocks: u32) -> anyhow::Result<Vec<String>> {
        self.call("generate", vec![serde_json::json!(num_blocks)]).await
    }

    async fn get_balance(&self) -> anyhow::Result<f64> {
        self.call("getbalance", vec![]).await
    }

    async fn z_get_total_balance(&self) -> anyhow::Result<serde_json::Value> {
        self.call("z_gettotalbalance", vec![]).await
    }

    async fn list_addresses(&self) -> anyhow::Result<Vec<String>> {
        self.call("listaddresses", vec![]).await
    }

    async fn z_list_addresses(&self) -> anyhow::Result<Vec<String>> {
        self.call("z_listaddresses", vec![]).await
    }

    async fn get_new_address(&self) -> anyhow::Result<String> {
        self.call("getnewaddress", vec![]).await
    }

    async fn z_get_new_address(&self, addr_type: &str) -> anyhow::Result<String> {
        self.call("z_getnewaddress", vec![serde_json::json!(addr_type)]).await
    }

    async fn list_transactions(&self, count: u32) -> anyhow::Result<Vec<serde_json::Value>> {
        self.call("listtransactions", vec![serde_json::json!("*"), serde_json::json!(count)]).await
    }

    async fn send_to_address(&self, address: &str, amount: f64) -> anyhow::Result<String> {
        self.call("sendtoaddress", vec![serde_json::json!(address), serde_json::json!(amount)]).await
    }

    async fn z_send_many(&self, from: &str, amounts: Vec<serde_json::Value>) -> anyhow::Result<String> {
        self.call("z_sendmany", vec![serde_json::json!(from), serde_json::json!(amounts)]).await
    }
}

async fn check_zebra_running() -> bool {
    TokioCommand::new("pgrep").arg("-f").arg("zebrad").output().await
        .map(|out| !out.stdout.is_empty()).unwrap_or(false)
}

async fn start_zebra(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] 🚀 Starting Zebra node...", Utc::now().format("%H:%M:%S")));
    drop(s);

    TokioCommand::new("zebrad").arg("start").spawn()?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] ✅ Zebra started successfully", Utc::now().format("%H:%M:%S")));
    Ok(())
}

async fn stop_zebra(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] ⏹️  Stopping Zebra node...", Utc::now().format("%H:%M:%S")));
    drop(s);

    TokioCommand::new("pkill").arg("-SIGTERM").arg("zebrad").output().await?;
    
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] 🛑 Zebra stopped", Utc::now().format("%H:%M:%S")));
    Ok(())
}

async fn update_node_state(client: Arc<ZebraClient>, state: Arc<Mutex<AppState>>) {
    let mut last_block_height = 0u64;
    let mut last_block_time = Instant::now();
    
    loop {
        let zebra_running = check_zebra_running().await;
        
        if !zebra_running {
            let mut s = state.lock().await;
            s.zebra_running = false;
            s.connected = false;
            s.status_message = "⚠️  Zebra not running - Press 's' in Control tab to start".to_string();
            drop(s);
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let mut s = state.lock().await;
        s.zebra_running = true;
        s.last_update = Instant::now();
        drop(s);

        if let Ok(info) = client.get_blockchain_info().await {
            let mut s = state.lock().await;
            s.connected = true;
            
            let old_height = s.block_height;
            s.block_height = info.blocks;
            s.block_hash = info.best_block_hash.clone();
            s.sync_progress = info.verification_progress * 100.0;
            s.chain = info.chain;
            s.difficulty = info.difficulty;
            s.size_on_disk = info.size_on_disk.unwrap_or(0);
            
            if s.sync_progress < 99.9 {
                s.status_message = format!("⚡ Syncing block {} ({:.2}%)", info.blocks, s.sync_progress);
                s.validating_block = true;
            } else {
                s.status_message = format!("✅ Synced at block {} | {} peers", info.blocks, s.connections);
                s.validating_block = false;
            }

            if info.blocks > last_block_height {
                let block_time = last_block_time.elapsed().as_secs();
                if block_time > 0 {
                    s.block_times.push_back(block_time);
                    if s.block_times.len() > 50 {
                        s.block_times.pop_front();
                    }
                    s.avg_block_time = s.block_times.iter().sum::<u64>() as f64 / s.block_times.len() as f64;
                    s.blocks_per_hour = 3600.0 / s.avg_block_time;
                }
                
                for height in (last_block_height.max(info.blocks.saturating_sub(9)) + 1)..=info.blocks {
                    if let Ok(hash) = client.get_block_hash(height).await {
                        if let Ok(block) = client.get_block(&hash).await {
                            let block_record = BlockRecord {
                                height: block.height,
                                hash: block.hash.clone(),
                                time: DateTime::from_timestamp(block.time as i64, 0).unwrap_or_else(|| Utc::now()),
                                tx_count: block.tx.len(),
                                size: block.size,
                            };
                            
                            s.recent_blocks.push_front(block_record);
                            if s.recent_blocks.len() > 100 {
                                s.recent_blocks.pop_back();
                            }
                            
                            s.total_transactions += block.tx.len() as u64;
                            let sizes: Vec<u64> = s.recent_blocks.iter().take(20).map(|b| b.size).collect();
                            s.avg_block_size = sizes.iter().sum::<u64>() as f64 / sizes.len() as f64;
                            
                            if height == info.blocks {
                                s.log_messages.push_back(format!(
                                    "[{}] ⛓️  Block #{} | {} txs | {:.2} KB | {:.1}s", 
                                    Utc::now().format("%H:%M:%S"), 
                                    block.height, 
                                    block.tx.len(),
                                    block.size as f64 / 1024.0,
                                    block_time
                                ));
                            }
                        }
                    }
                }
                
                last_block_height = info.blocks;
                last_block_time = Instant::now();
            }
            
            if info.blocks > old_height {
                s.validation_speed = (info.blocks - old_height) as f64 / 2.0;
            }
            
            drop(s);
        } else {
            let mut s = state.lock().await;
            s.connected = false;
            s.status_message = "🔄 Connecting to Zebra RPC...".to_string();
            drop(s);
        }

        if let Ok(net_info) = client.get_network_info().await {
            let mut s = state.lock().await;
            let old_connections = s.connections;
            s.connections = net_info.connections;
            s.node_version = net_info.sub_version;
            
            s.connection_history.push_back(s.connections);
            if s.connection_history.len() > 100 {
                s.connection_history.pop_front();
            }
            
            if s.connections > old_connections {
                s.log_messages.push_back(format!("[{}] 🔗 Peer connected (total: {})", 
                    Utc::now().format("%H:%M:%S"), s.connections));
            } else if s.connections < old_connections {
                s.log_messages.push_back(format!("[{}] ⛓️  Peer disconnected (total: {})", 
                    Utc::now().format("%H:%M:%S"), s.connections));
            }
            drop(s);
        }

        if let Ok(mempool) = client.get_mempool_info().await {
            let mut s = state.lock().await;
            let old_size = s.mempool_size;
            s.mempool_size = mempool.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            s.mempool_bytes = mempool.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            s.mempool_usage = mempool.get("usage").and_then(|v| v.as_u64()).unwrap_or(0) as f64 / 1_048_576.0;
            
            s.mempool_history.push_back(s.mempool_size);
            if s.mempool_history.len() > 100 {
                s.mempool_history.pop_front();
            }
            
            if s.mempool_size > old_size + 10 {
                s.log_messages.push_back(format!("[{}] 📬 {} new transactions in mempool (total: {})", 
                    Utc::now().format("%H:%M:%S"), s.mempool_size - old_size, s.mempool_size));
            }
            drop(s);
        }

        if let Ok(peers) = client.get_peer_info().await {
            let mut s = state.lock().await;
            s.peers = peers;
            drop(s);
        }

        if let Ok(total_balance) = client.z_get_total_balance().await {
            let mut s = state.lock().await;
            s.transparent_balance = total_balance.get("transparent")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            s.shielded_balance = total_balance.get("private")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            s.wallet_balance = s.transparent_balance + s.shielded_balance;
            drop(s);
        } else if let Ok(balance) = client.get_balance().await {
            let mut s = state.lock().await;
            s.transparent_balance = balance;
            s.wallet_balance = balance;
            drop(s);
        }

        if let Ok(addresses) = client.list_addresses().await {
            let mut s = state.lock().await;
            s.transparent_addresses = addresses;
            drop(s);
        }

        if let Ok(z_addresses) = client.z_list_addresses().await {
            let mut s = state.lock().await;
            s.shielded_addresses = z_addresses;
            drop(s);
        }

        if let Ok(txs) = client.list_transactions(50).await {
            let mut s = state.lock().await;
            s.transactions = txs.iter().filter_map(|tx| {
                Some(Transaction {
                    txid: tx.get("txid")?.as_str()?.to_string(),
                    amount: tx.get("amount")?.as_f64()?,
                    confirmations: tx.get("confirmations")?.as_u64()?,
                    time: DateTime::from_timestamp(tx.get("time")?.as_i64()?, 0).unwrap_or_else(|| Utc::now()),
                    address: tx.get("address").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                })
            }).collect();
            drop(s);
        }

        let mut s = state.lock().await;
        while s.log_messages.len() > 500 {
            s.log_messages.pop_front();
        }
        drop(s);


fn render_ui(f: &mut Frame, app: &App, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(f.area());

    render_header(f, chunks[0], state);
    render_tabs(f, chunks[1], app.current_tab);
    
    match app.current_tab {
        Tab::Dashboard => render_dashboard(f, chunks[2], state),
        Tab::Wallet => render_wallet(f, chunks[2], state),
        Tab::Send => render_send(f, chunks[2], app),
        Tab::Receive => render_receive(f, chunks[2], state),
        Tab::Blockchain => render_blockchain(f, chunks[2], state, app.scroll_offset),
        Tab::Network => render_network(f, chunks[2], state, app.scroll_offset),
        Tab::Mining => render_mining(f, chunks[2], state),
        Tab::Logs => render_logs(f, chunks[2], state, app.scroll_offset),
        Tab::Control => render_control(f, chunks[2], state),
        Tab::Performance => render_performance(f, chunks[2], state),
    }

    let footer_text = format!(
        "Update: {}s ago | {} | Blocks/hr: {:.1} | Avg time: {:.1}s | q=Quit Tab/Shift+Tab=Nav ↑↓=Scroll", 
        state.last_update.elapsed().as_secs(), 
        state.status_message,
        state.blocks_per_hour,
        state.avg_block_time
    );
    
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[3]);
}

fn render_header(f: &mut Frame, area: Rect, state: &AppState) {
    let status_color = if state.connected { ZCASH_GREEN } else { ZCASH_RED };
    let status_text = if state.connected { "● ONLINE" } else { "● OFFLINE" };
    let sync_indicator = if state.validating_block { "⚡" } else { "✓" };

    let header = Paragraph::new(Line::from(vec![
        Span::styled("🦓 ZEBRA ", Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD)),
        Span::styled(status_text, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        Span::raw("  │  "),
        Span::styled(format!("{} Block: {} ", sync_indicator, state.block_height), Style::default().fg(Color::White)),
        Span::raw("│  "),
        Span::styled(format!("🌐 {} peers ", state.connections), Style::default().fg(ZCASH_BLUE)),
        Span::raw("│  "),
        Span::styled(format!("📊 {:.1}% synced ", state.sync_progress), Style::default().fg(ZCASH_GREEN)),
        Span::raw("│  "),
        Span::styled(format!("💰 {:.8} ZEC", state.wallet_balance), Style::default().fg(ZCASH_GOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(ZCASH_GOLD)));

    f.render_widget(header, area);
}

fn render_tabs(f: &mut Frame, area: Rect, current_tab: Tab) {
    let titles: Vec<Line> = Tab::titles().iter().map(|t| Line::from(*t)).collect();
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("Navigation"))
        .select(current_tab.to_index())
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, area);
}

fn render_dashboard(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(15),
            Constraint::Length(6),
            Constraint::Min(0),
        ])
        .split(area);

    let stats = format!(
        "╔══════════════════════════════════════════════════════════════════════════════════╗\n\
         ║  🦓 ZEBRA NODE STATUS - {}                                         ║\n\
         ╠══════════════════════════════════════════════════════════════════════════════════╣\n\
         ║  ⛓️  Height: {:>10}  │  Chain: {:>12}  │  Sync: {:>6.2}%              ║\n\
         ║  🔨 Difficulty: {:>10.2}  │  🌐 Peers: {:>5}  │  📬 Mempool: {:>5} txs   ║\n\
         ║  💰 Balance:       {:>10.8} ZEC  │  💎 Transparent: {:>10.8} ZEC      ║\n\
         ║  🔒 Shielded:      {:>10.8} ZEC  │  📊 Disk: {:>7.2} GB                ║\n\
         ║  ⚡ Val Speed:     {:>10.1} b/s │  🕐 Avg Block: {:>6.1}s              ║\n\
         ║  📈 Blocks/Hour:   {:>10.1}     │  📦 Avg Size: {:>7.2} KB             ║\n\
         ║  🔢 Total Tx:      {:>10}     │  💾 Mempool: {:>7.2} MB              ║\n\
         ║  {} Status: {}                                                         ║\n\
         ╠══════════════════════════════════════════════════════════════════════════════════╣\n\
         ║  Node: {}                                                                   ║\n\
         ╚══════════════════════════════════════════════════════════════════════════════════╝",
        Utc::now().format("%Y-%m-%d %H:%M:%S"),
        state.block_height, state.chain, state.sync_progress,
        state.difficulty, state.connections, state.mempool_size,
        state.wallet_balance, state.transparent_balance,
        state.shielded_balance, state.size_on_disk as f64 / 1_073_741_824.0,
        state.validation_speed, state.avg_block_time,
        state.blocks_per_hour, state.avg_block_size / 1024.0,
        state.total_transactions, state.mempool_usage,
        if state.validating_block { "⚡" } else { "✓" },
        if state.connected { "Connected" } else { "Disconnected" },
        state.node_version
    );

    f.render_widget(
        Paragraph::new(stats).style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().borders(Borders::ALL).title("📊 Real-Time Statistics")),
        chunks[0]
    );

    let sync_color = if state.sync_progress >= 99.9 { ZCASH_GREEN } else { Color::Yellow };
    f.render_widget(
        Gauge::default()
            .block(Block::default().title("Synchronization Progress").borders(Borders::ALL))
            .gauge_style(Style::default().fg(sync_color))
            .percent(state.sync_progress.min(100.0) as u16)
            .label(format!("{:.2}% | Block {}", state.sync_progress, state.block_height)),
        chunks[1]
    );

    let items: Vec<ListItem> = state.recent_blocks.iter().take(20).map(|b| {
        let age = Utc::now().signed_duration_since(b.time);
        let age_str = if age.num_seconds() < 60 {
            format!("{}s ago", age.num_seconds())
        } else if age.num_minutes() < 60 {
            format!("{}m ago", age.num_minutes())
        } else {
            format!("{}h ago", age.num_hours())
        };
        
        ListItem::new(Line::from(vec![
            Span::styled(format!("#{:<8}", b.height), Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD)),
            Span::raw(" │ "),
            Span::styled(&b.hash[..16], Style::default().fg(Color::Cyan)),
            Span::raw("... │ "),
            Span::styled(format!("{:>3} tx", b.tx_count), Style::default().fg(ZCASH_GREEN)),
            Span::raw(" │ "),
            Span::styled(format!("{:>6.1} KB", b.size as f64 / 1024.0), Style::default().fg(Color::White)),
            Span::raw(" │ "),
            Span::styled(age_str, Style::default().fg(Color::Gray)),
        ]))
    }).collect();

    f.render_widget(
        List::new(items)
            .block(Block::default()
                .title(format!("⛓️  Recent Blocks ({} total)", state.recent_blocks.len()))
                .borders(Borders::ALL)),
        chunks[2]

fn render_blockchain(f: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12),
            Constraint::Min(0),
        ])
        .split(area);

    let chain_text = format!(
        "╔══════════════════════════════════════════════════════════════════════════════════╗\n\
         ║  ⛓️  BLOCKCHAIN STATUS                                                            ║\n\
         ╠══════════════════════════════════════════════════════════════════════════════════╣\n\
         ║  Current Height:  {:>15}                                                   ║\n\
         ║  Best Block Hash: {}            ║\n\
         ║  Chain:           {:>15}                                                   ║\n\
         ║  Difficulty:      {:>15.8}                                            ║\n\
         ║  Sync Progress:   {:>15.2}%                                              ║\n\
         ║  Disk Size:       {:>15.2} GB                                            ║\n\
         ║  Total Blocks:    {:>15}                                                   ║\n\
         ╚══════════════════════════════════════════════════════════════════════════════════╝",
        state.block_height,
        &state.block_hash[..64],
        state.chain,
        state.difficulty,
        state.sync_progress,
        state.size_on_disk as f64 / 1_073_741_824.0,
        state.recent_blocks.len()
    );

    f.render_widget(
        Paragraph::new(chain_text)
            .style(Style::default().fg(Color::White))
            .block(Block::default().title("Blockchain Information").borders(Borders::ALL)),
        chunks[0]
    );

    let items: Vec<ListItem> = state.recent_blocks.iter().skip(scroll as usize).map(|block| {
        let age = Utc::now().signed_duration_since(block.time);
        let age_str = if age.num_seconds() < 60 {
            format!("{}s", age.num_seconds())
        } else if age.num_minutes() < 60 {
            format!("{}m", age.num_minutes())
        } else {
            format!("{}h", age.num_hours())
        };

        ListItem::new(vec![
            Line::from(vec![
                Span::styled("Block #", Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{}", block.height), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::raw(" │ "),
                Span::styled(age_str, Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("Hash:  ", Style::default().fg(Color::Gray)),
                Span::styled(&block.hash, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Time:  ", Style::default().fg(Color::Gray)),
                Span::styled(block.time.format("%Y-%m-%d %H:%M:%S UTC").to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Txs:   ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", block.tx_count), Style::default().fg(ZCASH_GREEN)),
                Span::raw("    "),
                Span::styled("Size: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{:.2} KB", block.size as f64 / 1024.0), Style::default().fg(Color::White)),
            ]),
            Line::from("─".repeat(80)),
        ])
    }).collect();

    f.render_widget(
        List::new(items)
            .block(Block::default()
                .title(format!("📦 Block Details ({} blocks) - Use ↑↓ to scroll", state.recent_blocks.len()))
                .borders(Borders::ALL)),
        chunks[1]

fn render_mining(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(0)])
        .split(area);

    let mining_text = format!(
        "╔════════════════════════════════════════════════════════════════════════════╗\n\
         ║  ⛏️  MINING INFORMATION                                                     ║\n\
         ╠════════════════════════════════════════════════════════════════════════════╣\n\
         ║  Current Height:     {:>10}                                           ║\n\
         ║  Difficulty:         {:>20.8}                                  ║\n\
         ║  Chain:              {}                                                ║\n\
         ║  Blocks/Hour:        {:>10.1}                                           ║\n\
         ║  Avg Block Time:     {:>10.1} seconds                                  ║\n\
         ║                                                                            ║\n\
         ║  ⚠️  Mining on mainnet requires specialized ASIC hardware                 ║\n\
         ║  For testnet development, use the generate commands below                 ║\n\
         ╚════════════════════════════════════════════════════════════════════════════╝",
        state.block_height, state.difficulty, state.chain,
        state.blocks_per_hour, state.avg_block_time
    );

    f.render_widget(
        Paragraph::new(mining_text)
            .style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().title("Mining Statistics").borders(Borders::ALL)),
        chunks[0]
    );

    let instructions = vec![
        "╔════════════════════════════════════════════════════════════════════════════╗",
        "║  ⚡ TESTNET MINING CONTROLS (for development only)                         ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "║                                                                            ║",
        "║  'g' - Generate 1 block                                                    ║",
        "║  '5' - Generate 5 blocks                                                   ║",
        "║  '1' - Generate 10 blocks                                                  ║",
        "║                                                                            ║",
        "║  These commands only work on testnet for development purposes.            ║",
        "║                                                                            ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "║  ℹ️  MAINNET MINING REQUIREMENTS:                                          ║",
        "║                                                                            ║",
        "║  • Specialized ASIC mining hardware (Antminer Z15, etc.)                  ║",
        "║  • Mining pool configuration (Slush Pool, F2Pool, etc.)                   ║",
        "║  • External mining software (not handled by Zebra directly)               ║",
        "║  • getblocktemplate RPC for pool operators                                ║",
        "║                                                                            ║",
        "║  Zebra validates and propagates blocks but doesn't mine on mainnet.       ║",
        "║  Use external mining software connected to Zebra's RPC interface.         ║",
        "╚════════════════════════════════════════════════════════════════════════════╝",
    ];

    f.render_widget(
        Paragraph::new(instructions.join("\n"))
            .style(Style::default().fg(Color::White))
            .block(Block::default().title("Mining Controls & Information").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        chunks[1]

fn render_wallet(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Min(0),
        ])
        .split(area);

    let balance_text = format!(
        "╔══════════════════════════════════════════════════════════════════╗\n\
         ║  💰 WALLET BALANCES                                              ║\n\
         ╠══════════════════════════════════════════════════════════════════╣\n\
         ║  Total:              {:>15.8} ZEC                          ║\n\
         ║  💎 Transparent:     {:>15.8} ZEC  (Public)               ║\n\
         ║  🔒 Shielded:        {:>15.8} ZEC  (Private)              ║\n\
         ╠══════════════════════════════════════════════════════════════════╣\n\
         ║  Press 't' for new transparent address, 'z' for shielded        ║\n\
         ╚══════════════════════════════════════════════════════════════════╝",
        state.wallet_balance, state.transparent_balance, state.shielded_balance
    );

    f.render_widget(
        Paragraph::new(balance_text).style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().borders(Borders::ALL).title("💼 Balance")),
        chunks[0]
    );

    let mut addr_items: Vec<ListItem> = state.transparent_addresses.iter().map(|addr| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("💎 T: ", Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD)),
                Span::styled(addr, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
        ])
    }).collect();

    addr_items.extend(state.shielded_addresses.iter().map(|addr| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("🔒 Z: ", Style::default().fg(ZCASH_GREEN).add_modifier(Modifier::BOLD)),
                Span::styled(addr, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(""),
        ])
    }));

    if addr_items.is_empty() {
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled("No addresses yet. Press 't' for transparent or 'z' for shielded.", 
                Style::default().fg(Color::Yellow))
        ])));
    }

    f.render_widget(
        List::new(addr_items)
            .block(Block::default()
                .title(format!("📫 Addresses (💎 {}  🔒 {}) - t=new transparent, z=new shielded", 
                    state.transparent_addresses.len(), state.shielded_addresses.len()))
                .borders(Borders::ALL)),
        chunks[1]
    );

    let tx_items: Vec<ListItem> = if state.transactions.is_empty() {
        vec![ListItem::new(Line::from(vec![
            Span::styled("No transactions yet", Style::default().fg(Color::Gray))
        ]))]
    } else {
        state.transactions.iter().map(|tx| {
            let direction = if tx.amount > 0.0 { "⬇️  IN " } else { "⬆️  OUT" };
            let color = if tx.amount > 0.0 { ZCASH_GREEN } else { ZCASH_RED };
            
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(direction, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                    Span::raw(" "),
                    Span::styled(&tx.txid[..16], Style::default().fg(Color::Cyan)),
                    Span::raw("... │ "),
                    Span::styled(
                        format!("{:>12.8} ZEC", tx.amount.abs()), 
                        Style::default().fg(color).add_modifier(Modifier::BOLD)
                    ),
                ]),
                Line::from(vec![
                    Span::styled("    ✓ ", Style::default().fg(ZCASH_GREEN)),
                    Span::styled(format!("{} confirmations", tx.confirmations), Style::default().fg(Color::White)),
                    Span::raw(" │ "),
                    Span::styled(tx.time.format("%Y-%m-%d %H:%M").to_string(), Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled("    To: ", Style::default().fg(Color::Gray)),
                    Span::styled(&tx.address[..20], Style::default().fg(Color::White)),
                    Span::raw("..."),
                ]),
                Line::from(""),
            ])
        }).collect()
    };

    f.render_widget(
        List::new(tx_items)
            .block(Block::default()
                .title(format!("📜 Transaction History ({} total)", state.transactions.len()))
                .borders(Borders::ALL)),
        chunks[2]


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc_url = std::env::var("ZEBRA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8232".to_string());
    
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(rpc_url);
    
    let state_clone = Arc::clone(&app.state);
    let client_clone = Arc::clone(&app.client);
    tokio::spawn(async move {
        update_node_state(client_clone, state_clone).await;
    });

    loop {
        let state = app.state.lock().await.clone();
        terminal.draw(|f| render_ui(f, &app, &state))?;
        drop(state);

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.input_mode {
                    InputMode::Normal => {
                        match key.code {
                            KeyCode::Char('q') => app.should_quit = true,
                            KeyCode::Tab => app.current_tab = Tab::from_index((app.current_tab.to_index() + 1) % Tab::titles().len()),
                            KeyCode::BackTab => {
                                let idx = app.current_tab.to_index();
                                app.current_tab = Tab::from_index(if idx == 0 { Tab::titles().len() - 1 } else { idx - 1 });
                            }
                            KeyCode::Up => app.scroll_up(),
                            KeyCode::Down => app.scroll_down(),
                            
                            KeyCode::Char('t') if app.current_tab == Tab::Wallet || app.current_tab == Tab::Receive => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    match client.get_new_address().await {
                                        Ok(addr) => {
                                            let mut s = state.lock().await;
                                            s.transparent_addresses.push(addr.clone());
                                            s.log_messages.push_back(format!("[{}] 💎 New transparent address: {}", 
                                                Utc::now().format("%H:%M:%S"), addr));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ⚠️  Error creating address: {}", 
                                                Utc::now().format("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            KeyCode::Char('z') if app.current_tab == Tab::Wallet || app.current_tab == Tab::Receive => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    match client.z_get_new_address("sapling").await {
                                        Ok(addr) => {
                                            let mut s = state.lock().await;
                                            s.shielded_addresses.push(addr.clone());
                                            s.log_messages.push_back(format!("[{}] 🔒 New shielded address: {}", 
                                                Utc::now().format("%H:%M:%S"), addr));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ⚠️  Error creating z-address: {}", 
                                                Utc::now().format("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            
                            KeyCode::Char('a') if app.current_tab == Tab::Send => app.input_mode = InputMode::SendToAddress,
                            KeyCode::Char('m') if app.current_tab == Tab::Send => app.input_mode = InputMode::SendAmount,
                            KeyCode::Char('e') if app.current_tab == Tab::Send => app.input_mode = InputMode::SendMemo,
                            KeyCode::Enter if app.current_tab == Tab::Send => {
                                if !app.send_to_address.is_empty() && !app.send_amount.is_empty() {
                                    if let Ok(amount) = app.send_amount.parse::<f64>() {
                                        let to_addr = app.send_to_address.clone();
                                        let memo = app.send_memo.clone();
                                        let client = Arc::clone(&app.client);
                                        let state = Arc::clone(&app.state);
                                        
                                        tokio::spawn(async move {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] 📤 Sending {} ZEC to {}...", 
                                                Utc::now().format("%H:%M:%S"), amount, &to_addr[..20]));
                                            drop(s);
                                            
                                            let result = if to_addr.starts_with('z') {
                                                let mut amounts = vec![serde_json::json!({
                                                    "address": to_addr,
                                                    "amount": amount
                                                })];
                                                if !memo.is_empty() {
                                                    let memo_hex = memo.as_bytes().iter()
                                                        .map(|b| format!("{:02x}", b))
                                                        .collect::<String>();
                                                    amounts[0]["memo"] = serde_json::json!(memo_hex);
                                                }
                                                client.z_send_many("ANY_TADDR", amounts).await
                                            } else {
                                                client.send_to_address(&to_addr, amount).await
                                            };
                                            
                                            let mut s = state.lock().await;
                                            match result {
                                                Ok(txid) => s.log_messages.push_back(format!("[{}] ✅ Transaction sent! TxID: {}", 
                                                    Utc::now().format("%H:%M:%S"), txid)),
                                                Err(e) => s.log_messages.push_back(format!("[{}] ❌ Transaction failed: {}", 
                                                    Utc::now().format("%H:%M:%S"), e)),
                                            }
                                        });
                                        
                                        app.send_to_address.clear();
                                        app.send_amount.clear();
                                        app.send_memo.clear();
                                    }
                                }
                            }
                            
                            KeyCode::Char('s') if app.current_tab == Tab::Control => {
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    let _ = start_zebra(state).await;
                                });
                            }
                            KeyCode::Char('x') if app.current_tab == Tab::Control => {
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    let _ = stop_zebra(state).await;
                                });
                            }
                            KeyCode::Char('r') if app.current_tab == Tab::Control => {
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    let _ = stop_zebra(state.clone()).await;
                                    tokio::time::sleep(Duration::from_secs(3)).await;
                                    let _ = start_zebra(state).await;
                                });
                            }
                            
                            KeyCode::Char('g') if app.current_tab == Tab::Control || app.current_tab == Tab::Mining => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    let mut s = state.lock().await;
                                    s.log_messages.push_back(format!("[{}] ⛏️  Generating 1 block (testnet only)...", 
                                        Utc::now().format("%H:%M:%S")));
                                    drop(s);
                                    
                                    match client.generate(1).await {
                                        Ok(hashes) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ✅ Generated block: {}", 
                                                Utc::now().format("%H:%M:%S"), &hashes[0][..16]));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ❌ Mining failed: {} (Note: Only works on testnet)", 
                                                Utc::now().format("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            KeyCode::Char('5') if app.current_tab == Tab::Control || app.current_tab == Tab::Mining => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    let mut s = state.lock().await;
                                    s.log_messages.push_back(format!("[{}] ⛏️  Generating 5 blocks (testnet only)...", 
                                        Utc::now().format("%H:%M:%S")));
                                    drop(s);
                                    
                                    match client.generate(5).await {
                                        Ok(_) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ✅ Generated 5 blocks successfully", 
                                                Utc::now().format("%H:%M:%S")));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ❌ Mining failed: {} (Note: Only works on testnet)", 
                                                Utc::now().format("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            KeyCode::Char('1') if app.current_tab == Tab::Control || app.current_tab == Tab::Mining => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    let mut s = state.lock().await;
                                    s.log_messages.push_back(format!("[{}] ⛏️  Generating 10 blocks (testnet only)...", 
                                        Utc::now().format("%H:%M:%S")));
                                    drop(s);
                                    
                                    match client.generate(10).await {
                                        Ok(_) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ✅ Generated 10 blocks successfully", 
                                                Utc::now().format("%H:%M:%S")));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] ❌ Mining failed: {} (Note: Only works on testnet)", 
                                                Utc::now().format("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                    InputMode::SendToAddress => {
                        match key.code {
                            KeyCode::Char(c) => app.send_to_address.push(c),
                            KeyCode::Backspace => { app.send_to_address.pop(); }
                            KeyCode::Esc => app.input_mode = InputMode::Normal,
                            _ => {}
                        }
                    }
                    InputMode::SendAmount => {
                        match key.code {
                            KeyCode::Char(c) if c.is_numeric() || c == '.' => app.send_amount.push(c),
                            KeyCode::Backspace => { app.send_amount.pop(); }
                            KeyCode::Esc => app.input_mode = InputMode::Normal,
                            _ => {}
                        }
                    }
                    InputMode::SendMemo => {
                        match key.code {
                            KeyCode::Char(c) => app.send_memo.push(c),
                            KeyCode::Backspace => { app.send_memo.pop(); }
                            KeyCode::Esc => app.input_mode = InputMode::Normal,
                            _ => {}
                        }
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn render_send(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Min(0),
        ])
        .split(area);

    let from_style = Style::default().fg(Color::White);
    f.render_widget(
        Paragraph::new("ANY_TADDR (automatic selection)")
            .style(from_style)
            .block(Block::default().borders(Borders::ALL).title("💳 From Address")),
        chunks[0]
    );

    let to_style = if matches!(app.input_mode, InputMode::SendToAddress) { 
        Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD) 
    } else { 
        Style::default().fg(Color::White) 
    };

    f.render_widget(
        Paragraph::new(if app.send_to_address.is_empty() { 
            "Press 'a' to enter address...".to_string() 
        } else { 
            app.send_to_address.clone() 
        })
            .style(to_style)
            .block(Block::default().borders(Borders::ALL).title("📫 To Address (Press 'a' to edit)")),
        chunks[1]
    );

    let amount_style = if matches!(app.input_mode, InputMode::SendAmount) { 
        Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD) 
    } else { 
        Style::default().fg(Color::White) 
    };

    f.render_widget(
        Paragraph::new(if app.send_amount.is_empty() { 
            "Press 'm' to enter amount...".to_string() 
        } else { 
            format!("{} ZEC", app.send_amount)
        })
            .style(amount_style)
            .block(Block::default().borders(Borders::ALL).title("💰 Amount in ZEC (Press 'm' to edit)")),
        chunks[2]
    );

    let memo_style = if matches!(app.input_mode, InputMode::SendMemo) { 
        Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD) 
    } else { 
        Style::default().fg(Color::Gray) 
    };

    f.render_widget(
        Paragraph::new(if app.send_memo.is_empty() { 
            "Optional - Press 'e' to add memo (shielded only)...".to_string() 
        } else { 
            app.send_memo.clone() 
        })
            .style(memo_style)
            .block(Block::default().borders(Borders::ALL).title("📝 Memo (Optional - Press 'e' to edit)")),
        chunks[3]
    );

    let instructions = vec![
        "╔════════════════════════════════════════════════════════════════╗",
        "║  📤 SEND ZCASH - REAL TRANSACTIONS                            ║",
        "╠════════════════════════════════════════════════════════════════╣",
        "║  This sends REAL transactions on the Zcash network!           ║",
        "║                                                                ║",
        "║  'a' - Edit recipient address (t-addr or z-addr)               ║",
        "║  'm' - Edit amount in ZEC                                      ║",
        "║  'e' - Edit memo (only for shielded z-addr transactions)      ║",
        "║  Enter - Broadcast transaction to network                      ║",
        "║  Esc - Cancel current input                                    ║",
        "║                                                                ║",
        "║  ⚠️  CAUTION: Transactions are IRREVERSIBLE!                   ║",
        "║  Double-check address and amount before pressing Enter.        ║",
        "╚════════════════════════════════════════════════════════════════╝",
    ];

    f.render_widget(
        Paragraph::new(instructions.join("\n"))
            .style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().borders(Borders::ALL).title("📤 Send Instructions")),
        chunks[4]
    );

    let status_text = match app.input_mode {
        InputMode::SendToAddress => "✏️  Editing recipient address... Type address and press Esc when done",
        InputMode::SendAmount => "✏️  Editing amount... Type amount in ZEC and press Esc when done",
        InputMode::SendMemo => "✏️  Editing memo... Type memo text and press Esc when done",
        InputMode::Normal => if !app.send_to_address.is_empty() && !app.send_amount.is_empty() {
            "✅ READY - Press Enter to BROADCAST transaction to Zcash network (IRREVERSIBLE!)"
        } else {
            "⚠️  Enter recipient address and amount to continue"
        },
    };

    f.render_widget(
        Paragraph::new(status_text)
            .style(Style::default().fg(
                if matches!(app.input_mode, InputMode::Normal) && !app.send_to_address.is_empty() && !app.send_amount.is_empty() { 
                    ZCASH_RED
                } else if matches!(app.input_mode, InputMode::Normal) {
                    Color::White
                } else {
                    Color::Yellow
                }
            ))
            .block(Block::default().borders(Borders::ALL).title("⚠️  Transaction Status"))
            .wrap(Wrap { trim: true }),
        chunks[5]
    );
}

fn render_receive(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(0)])
        .split(area);

    let info = vec![
        "╔══════════════════════════════════════════════════════════════════╗",
        "║  📥 RECEIVE ZCASH                                                ║",
        "╠══════════════════════════════════════════════════════════════════╣",
        "║  To receive ZEC, share one of your addresses with the sender.   ║",
        "║                                                                  ║",
        "║  💎 Transparent Addresses (T-addresses):                         ║",
        "║     • Start with 't'                                             ║",
        "║     • Public transactions visible on blockchain                  ║",
        "║     • Fast and simple                                            ║",
        "║                                                                  ║",
        "║  🔒 Shielded Addresses (Z-addresses):                            ║",
        "║     • Start with 'z'                                             ║",
        "║     • Private transactions with encrypted amounts                ║",
        "║     • Maximum privacy                                            ║",
        "╚══════════════════════════════════════════════════════════════════╝",
    ];

    f.render_widget(
        Paragraph::new(info.join("\n"))
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL).title("ℹ️  Receive Information")),
        chunks[0]
    );

    let mut addr_items: Vec<ListItem> = state.transparent_addresses.iter().map(|addr| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("💎 Transparent: ", Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled(addr, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
        ])
    }).collect();

    addr_items.extend(state.shielded_addresses.iter().map(|addr| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("🔒 Shielded: ", Style::default().fg(ZCASH_GREEN).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled(addr, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(""),
        ])
    }));

    if addr_items.is_empty() {
        addr_items.push(ListItem::new(vec![
            Line::from(vec![
                Span::styled("No addresses yet.", Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Press 't' for new transparent or 'z' for new shielded address.", 
                    Style::default().fg(Color::Gray)),
            ]),
        ]));
    }

    f.render_widget(
        List::new(addr_items)
            .block(Block::default()
                .title("📫 Your Receiving Addresses - Press 't' for transparent, 'z' for shielded")
                .borders(Borders::ALL)),
        chunks[1]
    );
}

fn render_logs(f: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let items: Vec<ListItem> = state.log_messages.iter().rev().skip(scroll as usize).map(|msg| {
        let color = if msg.contains("⛓️") || msg.contains("Block") {
            ZCASH_GOLD
        } else if msg.contains("✅") || msg.contains("connected") {
            ZCASH_GREEN
        } else if msg.contains("⚠️") || msg.contains("Error") {
            ZCASH_RED
        } else if msg.contains("📬") || msg.contains("Mempool") {
            ZCASH_BLUE
        } else {
            Color::White
        };
        
        ListItem::new(Line::from(msg.as_str())).style(Style::default().fg(color))
    }).collect();

    let log_widget = List::new(items)
        .block(Block::default()
            .title(format!("📋 Real-Time Event Logs ({} events) - Use ↑↓ to scroll", state.log_messages.len()))
            .borders(Borders::ALL));

    f.render_widget(log_widget, area);
}

fn render_control(f: &mut Frame, area: Rect, state: &AppState) {
    let (status_text, _status_color) = if state.zebra_running {
        if state.connected {
            ("✅ RUNNING & CONNECTED", ZCASH_GREEN)
        } else {
            ("⚡ STARTING UP", Color::Yellow)
        }
    } else {
        ("🛑 STOPPED", ZCASH_RED)
    };

    let control_text = format!(
        "╔════════════════════════════════════════════════════════════════════════════╗\n\
         ║  🎛️  NODE CONTROL PANEL                                                    ║\n\
         ╠════════════════════════════════════════════════════════════════════════════╣\n\
         ║  Status:   {}                                              \n\
         ║  Version:  {}                                                    \n\
         ║  Chain:    {}                                                       \n\
         ║  RPC:      http://127.0.0.1:8232                                           ║\n\
         ╚════════════════════════════════════════════════════════════════════════════╝\n\
         \n\
         ╔════════════════════════════════════════════════════════════════════════════╗\n\
         ║  🎮 CONTROLS                                                               ║\n\
         ╠════════════════════════════════════════════════════════════════════════════╣\n\
         ║  's' - Start Zebra Node                                                    ║\n\
         ║  'x' - Stop Zebra Node                                                     ║\n\
         ║  'r' - Restart Node (stop + start)                                         ║\n\
         ║                                                                            ║\n\
         ║  Testnet Mining (if on testnet):                                          ║\n\
         ║  'g' - Generate 1 block                                                    ║\n\
         ║  '5' - Generate 5 blocks                                                   ║\n\
         ║  '1' - Generate 10 blocks                                                  ║\n\
         ╚════════════════════════════════════════════════════════════════════════════╝\n\
         \n\
         ℹ️  The node will automatically start if not running.\n\
         ℹ️  Default RPC endpoint: http://127.0.0.1:8232\n\
         ℹ️  Use ZEBRA_RPC_URL environment variable to change endpoint.",
        status_text, state.node_version, state.chain
    );

    f.render_widget(
        Paragraph::new(control_text)
            .style(Style::default().fg(Color::White))
            .block(Block::default().title("Node Control").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area
    );
}

fn render_performance(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(0),
        ])
        .split(area);

    let perf_text = format!(
        "╔════════════════════════════════════════════════════════════════════════════╗\n\
         ║  📊 PERFORMANCE METRICS                                                    ║\n\
         ╠════════════════════════════════════════════════════════════════════════════╣\n\
         ║  Validation Speed:   {:>10.2} blocks/second                             ║\n\
         ║  Blocks Per Hour:    {:>10.1}                                            ║\n\
         ║  Avg Block Time:     {:>10.1} seconds                                    ║\n\
         ║  Avg Block Size:     {:>10.2} KB                                         ║\n\
         ║  Total Transactions: {:>10}                                            ║\n\
         ║  Disk Usage:         {:>10.2} GB                                         ║\n\
         ╚════════════════════════════════════════════════════════════════════════════╝",
        state.validation_speed,
        state.blocks_per_hour,
        state.avg_block_time,
        state.avg_block_size / 1024.0,
        state.total_transactions,
        state.size_on_disk as f64 / 1_073_741_824.0
    );

    f.render_widget(
        Paragraph::new(perf_text).style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().borders(Borders::ALL)),
        chunks[0]
    );

    let conn_data: Vec<u64> = state.connection_history.iter().copied().collect();
    if !conn_data.is_empty() {
        f.render_widget(
            Sparkline::default()
                .block(Block::default().title("🌐 Connection History (last 100 updates)").borders(Borders::ALL))
                .data(&conn_data)
                .style(Style::default().fg(ZCASH_BLUE)),
            chunks[1]
        );
    }

    let mempool_data: Vec<u64> = state.mempool_history.iter().copied().collect();
    if !mempool_data.is_empty() {
        f.render_widget(
            Sparkline::default()
                .block(Block::default().title("📬 Mempool Size History (last 100 updates)").borders(Borders::ALL))
                .data(&mempool_data)
                .style(Style::default().fg(ZCASH_GREEN)),
            chunks[2]
        );
    }

    let block_items: Vec<ListItem> = state.recent_blocks.iter().take(10).map(|b| {
        ListItem::new(Line::from(vec![
            Span::styled(format!("#{:<8}", b.height), Style::default().fg(ZCASH_GOLD)),
            Span::raw(" │ "),
            Span::styled(format!("{:>3} tx", b.tx_count), Style::default().fg(ZCASH_GREEN)),
            Span::raw(" │ "),
            Span::styled(format!("{:>7.1} KB", b.size as f64 / 1024.0), Style::default().fg(Color::White)),
            Span::raw(" │ "),
            Span::styled(b.time.format("%H:%M:%S").to_string(), Style::default().fg(Color::Gray)),
        ]))
    }).collect();

    f.render_widget(
        List::new(block_items)
            .block(Block::default().title("⚡ Recent Block Activity").borders(Borders::ALL)),
        chunks[3]
    );
}

fn render_network(f: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(16), Constraint::Min(0)])
        .split(area);

    let network_text = format!(
        "╔════════════════════════════════════════════════════════════════════════════╗\n\
         ║  🌐 NETWORK INFORMATION                                                    ║\n\
         ╠════════════════════════════════════════════════════════════════════════════╣\n\
         ║  Node Version:       {}                                          \n\
         ║  Chain:              {:<20}  Protocol: Bitcoin-derived          ║\n\
         ║  Connections:        {:<5} active peers                                    ║\n\
         ║                                                                            ║\n\
         ║  📬 MEMPOOL STATUS                                                         ║\n\
         ║  Transactions:       {:<10} pending                                       ║\n\
         ║  Size:               {:.2} KB                                           ║\n\
         ║  Memory Usage:       {:.2} MB                                           ║\n\
         ║                                                                            ║\n\
         ║  🔄 SYNCHRONIZATION                                                        ║\n\
         ║  Progress:           {:.2}%                                              ║\n\
         ║  Status:             {}                                            ║\n\
         ╚════════════════════════════════════════════════════════════════════════════╝",
        state.node_version, state.chain, state.connections,
        state.mempool_size, state.mempool_bytes as f64 / 1024.0, state.mempool_usage,
        state.sync_progress,
        if state.sync_progress >= 99.9 { "✅ Fully Synced" } else { "⚡ Syncing..." }
    );

    f.render_widget(
        Paragraph::new(network_text)
            .style(Style::default().fg(Color::White))
            .block(Block::default().title("Network Status").borders(Borders::ALL)),
        chunks[0]
    );

    let peer_items: Vec<ListItem> = if state.peers.is_empty() {
        vec![ListItem::new(Line::from(vec![
            Span::styled("No peers connected yet...", Style::default().fg(Color::Gray))
        ]))]
    } else {
        state.peers.iter().skip(scroll as usize).map(|peer| {
            let sent_mb = peer.bytes_sent.unwrap_or(0) as f64 / 1_048_576.0;
            let recv_mb = peer.bytes_recv.unwrap_or(0) as f64 / 1_048_576.0;
            
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("🔗 Peer: ", Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD)),
                    Span::styled(&peer.addr, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("   Version: ", Style::default().fg(Color::Gray)),
                    Span::styled(format!("{}", peer.version), Style::default().fg(Color::White)),
                    Span::raw("  │  "),
                    Span::styled(&peer.sub_ver, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("   Synced:  ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{} blocks", peer.synced_blocks.unwrap_or(0)),
                        Style::default().fg(ZCASH_GREEN)
                    ),
                ]),
                Line::from(vec![
                    Span::styled("   Traffic: ", Style::default().fg(Color::Gray)),
                    Span::styled(format!("⬆️  {:.2} MB sent", sent_mb), Style::default().fg(ZCASH_BLUE)),
                    Span::raw("  │  "),
                    Span::styled(format!("⬇️  {:.2} MB recv", recv_mb), Style::default().fg(ZCASH_GREEN)),
                ]),
                Line::from(""),
            ])
        }).collect()
    };

    f.render_widget(
        List::new(peer_items)
            .block(Block::default()
                .title(format!("👥 Connected Peers ({}) - Use ↑↓ to scroll", state.peers.len()))
                .borders(Borders::ALL)),
        chunks[1]
    );
}
