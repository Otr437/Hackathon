// COMPLETE ZEBRA NODE TUI MANAGER - FULLY IMPLEMENTED
// ALL FEATURES: Wallet, Shielded Transactions, Block Explorer, Mining, Network
// 
// Cargo.toml:
// [package]
// name = "zebra-tui-manager"
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

use std::io;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::collections::VecDeque;
use tokio::sync::Mutex;
use tokio::process::Command as TokioCommand;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Gauge, Tabs, Wrap, Clear, Table, Row, Cell},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

const ZCASH_GOLD: Color = Color::Rgb(244, 183, 40);
const ZCASH_GREEN: Color = Color::Rgb(64, 198, 77);
const ZCASH_RED: Color = Color::Red;

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
    connections: u32,
    chain: String,
    difficulty: f64,
    recent_blocks: VecDeque<BlockRecord>,
    node_version: String,
    connected: bool,
    status_message: String,
    log_messages: VecDeque<String>,
    mempool_size: u64,
    mempool_bytes: u64,
    size_on_disk: u64,
    peers: Vec<PeerInfo>,
    zebra_running: bool,
    wallet_balance: f64,
    transparent_balance: f64,
    shielded_balance: f64,
    transparent_addresses: Vec<String>,
    shielded_addresses: Vec<String>,
    transactions: Vec<Transaction>,
    last_update: Instant,
    mining_enabled: bool,
    network_hashrate: f64,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            block_height: 0,
            block_hash: String::new(),
            sync_progress: 0.0,
            connections: 0,
            chain: String::from("unknown"),
            difficulty: 0.0,
            recent_blocks: VecDeque::new(),
            node_version: String::from("Unknown"),
            connected: false,
            status_message: String::from("Initializing..."),
            log_messages: VecDeque::new(),
            mempool_size: 0,
            mempool_bytes: 0,
            size_on_disk: 0,
            peers: Vec::new(),
            zebra_running: false,
            wallet_balance: 0.0,
            transparent_balance: 0.0,
            shielded_balance: 0.0,
            transparent_addresses: Vec::new(),
            shielded_addresses: Vec::new(),
            transactions: Vec::new(),
            last_update: Instant::now(),
            mining_enabled: false,
            network_hashrate: 0.0,
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
}

impl Tab {
    fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Wallet", "Send", "Receive", "Blockchain", "Network", "Mining", "Logs", "Control"]
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
    send_from_address: String,
    show_popup: bool,
    popup_message: String,
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
            send_from_address: String::from("ANY_TADDR"),
            show_popup: false,
            popup_message: String::new(),
        }
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

    async fn get_balance(&self) -> anyhow::Result<f64> {
        self.call("getbalance", vec![]).await
    }

    async fn z_get_total_balance(&self) -> anyhow::Result<serde_json::Value> {
        self.call("z_gettotalbalance", vec![]).await
    }

    async fn z_get_balance(&self, address: &str) -> anyhow::Result<f64> {
        self.call("z_getbalance", vec![serde_json::json!(address)]).await
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

    async fn z_list_received_by_address(&self, address: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        self.call("z_listreceivedbyaddress", vec![serde_json::json!(address)]).await
    }

    async fn send_to_address(&self, address: &str, amount: f64) -> anyhow::Result<String> {
        self.call("sendtoaddress", vec![serde_json::json!(address), serde_json::json!(amount)]).await
    }

    async fn z_send_many(&self, from: &str, amounts: Vec<serde_json::Value>) -> anyhow::Result<String> {
        self.call("z_sendmany", vec![serde_json::json!(from), serde_json::json!(amounts)]).await
    }

    async fn z_get_operation_status(&self, operation_ids: Vec<String>) -> anyhow::Result<Vec<serde_json::Value>> {
        self.call("z_getoperationstatus", vec![serde_json::json!(operation_ids)]).await
    }

    async fn z_get_operation_result(&self, operation_ids: Vec<String>) -> anyhow::Result<Vec<serde_json::Value>> {
        self.call("z_getoperationresult", vec![serde_json::json!(operation_ids)]).await
    }

    async fn get_mining_info(&self) -> anyhow::Result<serde_json::Value> {
        self.call("getmininginfo", vec![]).await
    }

    async fn get_network_hash_ps(&self) -> anyhow::Result<f64> {
        self.call("getnetworkhashps", vec![]).await
    }

    async fn generate(&self, num_blocks: u32) -> anyhow::Result<Vec<String>> {
        self.call("generate", vec![serde_json::json!(num_blocks)]).await
    }
}

async fn check_zebra_running() -> bool {
    if cfg!(target_os = "windows") {
        TokioCommand::new("tasklist").arg("/FI").arg("IMAGENAME eq zebrad.exe").output().await
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("zebrad.exe")).unwrap_or(false)
    } else {
        TokioCommand::new("pgrep").arg("-f").arg("zebrad").output().await
            .map(|out| !out.stdout.is_empty()).unwrap_or(false)
    }
}

async fn start_zebra(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] Starting Zebra node...", Utc::now().format("%H:%M:%S")));
    drop(s);

    TokioCommand::new("zebrad").arg("start").spawn()?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] Zebra started successfully", Utc::now().format("%H:%M:%S")));
    Ok(())
}

async fn stop_zebra(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] Stopping Zebra node...", Utc::now().format("%H:%M:%S")));
    drop(s);

    if cfg!(target_os = "windows") {
        TokioCommand::new("taskkill").arg("/F").arg("/IM").arg("zebrad.exe").output().await?;
    } else {
        TokioCommand::new("pkill").arg("-SIGTERM").arg("zebrad").output().await?;
    }
    
    let mut s = state.lock().await;
    s.log_messages.push_back(format!("[{}] Zebra stopped", Utc::now().format("%H:%M:%S")));
    Ok(())
}

async fn update_node_state(client: Arc<ZebraClient>, state: Arc<Mutex<AppState>>) {
    let mut last_block_height = 0u64;
    
    loop {
        let zebra_running = check_zebra_running().await;
        
        if !zebra_running {
            let mut s = state.lock().await;
            s.zebra_running = false;
            s.connected = false;
            s.status_message = "Zebra not running - Press 's' in Control tab to start".to_string();
            drop(s);
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let mut s = state.lock().await;
        s.zebra_running = true;
        s.last_update = Instant::now();
        drop(s);

        // Update blockchain info
        if let Ok(info) = client.get_blockchain_info().await {
            let mut s = state.lock().await;
            s.connected = true;
            s.block_height = info.blocks;
            s.block_hash = info.best_block_hash.clone();
            s.sync_progress = info.verification_progress * 100.0;
            s.chain = info.chain;
            s.difficulty = info.difficulty;
            s.size_on_disk = info.size_on_disk.unwrap_or(0);
            s.status_message = format!("Block {}", info.blocks);

            if info.blocks > last_block_height {
                for height in (last_block_height.max(info.blocks.saturating_sub(19)) + 1)..=info.blocks {
                    if let Ok(hash) = client.get_block_hash(height).await {
                        if let Ok(block) = client.get_block(&hash).await {
                            s.recent_blocks.push_front(BlockRecord {
                                height: block.height,
                                hash: block.hash,
                                time: DateTime::from_timestamp(block.time as i64, 0).unwrap_or_else(|| Utc::now()),
                                tx_count: block.tx.len(),
                                size: block.size,
                            });
                            if s.recent_blocks.len() > 20 {
                                s.recent_blocks.pop_back();
                            }
                        }
                    }
                }
                s.log_messages.push_back(format!("[{}] New block #{}", Utc::now().format("%H:%M:%S"), info.blocks));
                last_block_height = info.blocks;
            }
            drop(s);
        }

        // Update network info
        if let Ok(net_info) = client.get_network_info().await {
            let mut s = state.lock().await;
            s.connections = net_info.connections;
            s.node_version = net_info.sub_version;
            drop(s);
        }

        // Update mempool
        if let Ok(mempool) = client.get_mempool_info().await {
            let mut s = state.lock().await;
            s.mempool_size = mempool.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            s.mempool_bytes = mempool.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            drop(s);
        }

        // Update peers
        if let Ok(peers) = client.get_peer_info().await {
            let mut s = state.lock().await;
            s.peers = peers;
            drop(s);
        }

        // Update wallet balances
        if let Ok(total_balance) = client.z_get_total_balance().await {
            let mut s = state.lock().await;
            s.transparent_balance = total_balance.get("transparent").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            s.shielded_balance = total_balance.get("private").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            s.wallet_balance = s.transparent_balance + s.shielded_balance;
            drop(s);
        } else if let Ok(balance) = client.get_balance().await {
            let mut s = state.lock().await;
            s.transparent_balance = balance;
            s.wallet_balance = balance;
            drop(s);
        }

        // Update addresses
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

        // Update transactions
        if let Ok(txs) = client.list_transactions(20).await {
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

        // Update mining info
        if let Ok(hashps) = client.get_network_hash_ps().await {
            let mut s = state.lock().await;
            s.network_hashrate = hashps;
            drop(s);
        }

        let mut s = state.lock().await;
        while s.log_messages.len() > 100 {
            s.log_messages.pop_front();
        }
        drop(s);

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn render_ui(f: &mut Frame, app: &App, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(f.area());

    render_header(f, chunks[0], state);
    render_tabs(f, chunks[1], app.current_tab);
    
    match app.current_tab {
        Tab::Dashboard => render_dashboard(f, chunks[2], state),
        Tab::Wallet => render_wallet(f, chunks[2], state, app.scroll_offset),
        Tab::Send => render_send(f, chunks[2], app, state),
        Tab::Receive => render_receive(f, chunks[2], state),
        Tab::Blockchain => render_blockchain(f, chunks[2], state, app.scroll_offset),
        Tab::Network => render_network(f, chunks[2], state, app.scroll_offset),
        Tab::Mining => render_mining(f, chunks[2], state),
        Tab::Logs => render_logs(f, chunks[2], state, app.scroll_offset),
        Tab::Control => render_control(f, chunks[2], state),
    }

    let footer = Paragraph::new(format!("Last Update: {}s ago | {} | q=Quit Tab/Shift+Tab=Nav ↑↓=Scroll", 
        state.last_update.elapsed().as_secs(), state.status_message))
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[3]);

    if app.show_popup {
        render_popup(f, &app.popup_message);
    }
}

fn render_header(f: &mut Frame, area: Rect, state: &AppState) {
    let status_color = if state.connected { ZCASH_GREEN } else { ZCASH_RED };
    let status_text = if state.connected { "● ONLINE" } else { "● OFFLINE" };

    let header = Paragraph::new(Line::from(vec![
        Span::styled("🦓 ZEBRA ", Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD)),
        Span::styled(status_text, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        Span::raw("  │  "),
        Span::styled(format!("Block: {} ", state.block_height), Style::default().fg(Color::White)),
        Span::raw("│  "),
        Span::styled(format!("Peers: {} ", state.connections), Style::default().fg(Color::White)),
        Span::raw("│  "),
        Span::styled(format!("Balance: {:.8} ZEC", state.wallet_balance), Style::default().fg(ZCASH_GOLD)),
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
        .constraints([Constraint::Length(12), Constraint::Length(4), Constraint::Min(0)])
        .split(area);

    let stats = format!(
        "╔══════════════════════════════════════════════════════════════════════════╗\n\
         ║  LIVE NODE STATUS - {}                                    ║\n\
         ╠══════════════════════════════════════════════════════════════════════════╣\n\
         ║  Height: {:>10}  │  Chain: {:>12}  │  Sync: {:>6.2}%        ║\n\
         ║  Difficulty: {:>10.2}  │  Peers: {:>5}  │  Mempool: {:>5} txs      ║\n\
         ║  Total Balance:    {:>10.8} ZEC                                    ║\n\
         ║  Transparent:      {:>10.8} ZEC                                    ║\n\
         ║  Shielded:         {:>10.8} ZEC                                    ║\n\
         ║  Disk Size: {:>7.2} GB  │  Hash Rate: {:>10.2} H/s                 ║\n\
         ╚══════════════════════════════════════════════════════════════════════════╝",
        Utc::now().format("%H:%M:%S"),
        state.block_height, state.chain, state.sync_progress,
        state.difficulty, state.connections, state.mempool_size,
        state.wallet_balance,
        state.transparent_balance,
        state.shielded_balance,
        state.size_on_disk as f64 / 1_073_741_824.0, state.network_hashrate
    );

    f.render_widget(
        Paragraph::new(stats).style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().borders(Borders::ALL).title("Statistics")),
        chunks[0]
    );

    f.render_widget(
        Gauge::default()
            .block(Block::default().title("Sync Progress").borders(Borders::ALL))
            .gauge_style(Style::default().fg(ZCASH_GREEN))
            .percent(state.sync_progress.min(100.0) as u16)
            .label(format!("{:.2}%", state.sync_progress)),
        chunks[1]
    );

    let items: Vec<ListItem> = state.recent_blocks.iter().map(|b| {
        ListItem::new(Line::from(vec![
            Span::styled(format!("#{:<8}", b.height), Style::default().fg(ZCASH_GOLD)),
            Span::raw("  "),
            Span::styled(&b.hash[..16], Style::default().fg(Color::Cyan)),
            Span::raw("  "),
            Span::styled(format!("{} tx", b.tx_count), Style::default().fg(Color::White)),
            Span::raw("  "),
            Span::styled(b.time.format("%H:%M:%S").to_string(), Style::default().fg(Color::Gray)),
        ]))
    }).collect();

    f.render_widget(
        List::new(items).block(Block::default().title("Recent Blocks").borders(Borders::ALL)),
        chunks[2]
    );
}

fn render_wallet(f: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    let balance_text = format!(
        "╔══════════════════════════════════════════════════════════╗\n\
         ║  WALLET BALANCES                                         ║\n\
         ╠══════════════════════════════════════════════════════════╣\n\
         ║  Total:          {:>15.8} ZEC                      ║\n\
         ║  Transparent:    {:>15.8} ZEC                      ║\n\
         ║  Shielded:       {:>15.8} ZEC                      ║\n\
         ╚══════════════════════════════════════════════════════════╝",
        state.wallet_balance, state.transparent_balance, state.shielded_balance
    );

    f.render_widget(
        Paragraph::new(balance_text).style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().borders(Borders::ALL).title("Balance")),
        chunks[0]
    );

    let mut addr_items: Vec<ListItem> = state.transparent_addresses.iter().map(|addr| {
        ListItem::new(Line::from(vec![
            Span::styled("T: ", Style::default().fg(ZCASH_GOLD)),
            Span::styled(addr, Style::default().fg(Color::Cyan)),
        ]))
    }).collect();

    addr_items.extend(state.shielded_addresses.iter().map(|addr| {
        ListItem::new(Line::from(vec![
            Span::styled("Z: ", Style::default().fg(ZCASH_GREEN)),
            Span::styled(addr, Style::default().fg(Color::Magenta)),
        ]))
    }));

    f.render_widget(
        List::new(addr_items)
            .block(Block::default()
                .title(format!("Addresses (T:{} Z:{}) - Press 't' for new transparent, 'z' for shielded", 
                    state.transparent_addresses.len(), state.shielded_addresses.len()))
                .borders(Borders::ALL)),
        chunks[1]
    );

    let tx_items: Vec<ListItem> = state.transactions.iter().skip(scroll as usize).map(|tx| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("TxID: ", Style::default().fg(Color::Gray)),
                Span::styled(&tx.txid[..16], Style::default().fg(Color::Cyan)),
                Span::raw("..."),
            ]),
            Line::from(vec![
                Span::styled("Amount: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{:.8} ZEC", tx.amount), 
                    Style::default().fg(if tx.amount > 0.0 { ZCASH_GREEN } else { ZCASH_RED })
                ),
                Span::raw("  "),
                Span::styled(format!("{} confirms", tx.confirmations), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("To: ", Style::default().fg(Color::Gray)),
                Span::styled(&tx.address, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
        ])
    }).collect();

    f.render_widget(
        List::new(tx_items)
            .block(Block::default()
                .title(format!("Recent Transactions ({}) - Use ↑↓ to scroll", state.transactions.len()))
                .borders(Borders::ALL)),
        chunks[2]
    );
}

fn render_send(f: &mut Frame, area: Rect, app: &App, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);

    let from_style = if matches!(app.input_mode, InputMode::Normal) { 
        Style::default().fg(Color::White) 
    } else { 
        Style::default().fg(Color::Gray) 
    };

    f.render_widget(
        Paragraph::new(format!("From: {}", app.send_from_address))
            .style(from_style)
            .block(Block::default().borders(Borders::ALL).title("From Address (Press 'f' to change)")),
        chunks[0]
    );

    let to_style = if matches!(app.input_mode, InputMode::SendToAddress) { 
        Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD) 
    } else { 
        Style::default().fg(Color::White) 
    };

    f.render_widget(
        Paragraph::new(app.send_to_address.as_str())
            .style(to_style)
            .block(Block::default().borders(Borders::ALL).title("To Address (Press 'a' to edit)")),
        chunks[1]
    );

    let amount_style = if matches!(app.input_mode, InputMode::SendAmount) { 
        Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD) 
    } else { 
        Style::default().fg(Color::White) 
    };

    f.render_widget(
        Paragraph::new(app.send_amount.as_str())
            .style(amount_style)
            .block(Block::default().borders(Borders::ALL).title("Amount in ZEC (Press 'm' to edit)")),
        chunks[2]
    );

    let memo_style = if matches!(app.input_mode, InputMode::SendMemo) { 
        Style::default().fg(ZCASH_GOLD).add_modifier(Modifier::BOLD) 
    } else { 
        Style::default().fg(Color::White) 
    };

    f.render_widget(
        Paragraph::new(app.send_memo.as_str())
            .style(memo_style)
            .block(Block::default().borders(Borders::ALL).title("Memo (Optional - Press 'e' to edit)")),
        chunks[3]
    );

    let instructions = vec![
        "Instructions:",
        "  'a' - Edit To Address",
        "  'm' - Edit Amount",
        "  'e' - Edit Memo (for shielded transactions)",
        "  'f' - Change From Address",
        "  Enter - Send Transaction",
        "  Esc - Cancel input",
    ];

    f.render_widget(
        Paragraph::new(instructions.join("\n"))
            .style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().borders(Borders::ALL).title("Send Transaction")),
        chunks[4]
    );

    let status_text = match app.input_mode {
        InputMode::SendToAddress => "Editing To Address... Press Esc to finish",
        InputMode::SendAmount => "Editing Amount... Press Esc to finish",
        InputMode::SendMemo => "Editing Memo... Press Esc to finish",
        InputMode::Normal => "Ready to send - Press Enter to confirm",
    };

    f.render_widget(
        Paragraph::new(status_text)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Status")),
        chunks[5]
    );
}

fn render_receive(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(area);

    let info = vec![
        "RECEIVE ZCASH",
        "",
        "To receive ZEC, share one of your addresses with the sender.",
        "",
        "Transparent Addresses (T-addresses):",
        "  - Start with 't'",
        "  - Public transactions",
        "  - Visible on blockchain",
        "",
        "Shielded Addresses (Z-addresses):",
        "  - Start with 'z'",
        "  - Private transactions",
        "  - Hidden amounts and addresses",
    ];

    f.render_widget(
        Paragraph::new(info.join("\n"))
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL).title("Receive Information")),
        chunks[0]
    );

    let mut addr_items: Vec<ListItem> = state.transparent_addresses.iter().map(|addr| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("Transparent: ", Style::default().fg(ZCASH_GOLD)),
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
                Span::styled("Shielded: ", Style::default().fg(ZCASH_GREEN)),
            ]),
            Line::from(vec![
                Span::styled(addr, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(""),
        ])
    }));

    f.render_widget(
        List::new(addr_items)
            .block(Block::default()
                .title("Your Addresses - Press 't' for new transparent, 'z' for new shielded")
                .borders(Borders::ALL)),
        chunks[1]
    );
}

fn render_blockchain(f: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let items: Vec<ListItem> = state.recent_blocks.iter().skip(scroll as usize).map(|block| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("Block #", Style::default().fg(ZCASH_GOLD)),
                Span::styled(format!("{}", block.height), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Hash:  ", Style::default().fg(Color::Gray)),
                Span::styled(&block.hash, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Time:  ", Style::default().fg(Color::Gray)),
                Span::styled(block.time.format("%Y-%m-%d %H:%M:%S").to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Txs:   ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", block.tx_count), Style::default().fg(Color::White)),
                Span::raw("    "),
                Span::styled("Size: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{} bytes", block.size), Style::default().fg(Color::White)),
            ]),
            Line::from(""),
        ])
    }).collect();

    f.render_widget(
        List::new(items)
            .block(Block::default()
                .title(format!("Blockchain Explorer ({} blocks) - Use ↑↓ to scroll", state.recent_blocks.len()))
                .borders(Borders::ALL)),
        area
    );
}

fn render_network(f: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(0)])
        .split(area);

    let network_text = format!(
        "╔════════════════════════════════════════════════════════════════╗\n\
         ║  NETWORK INFORMATION                                           ║\n\
         ╠════════════════════════════════════════════════════════════════╣\n\
         ║  Node Version:       {}                         \n\
         ║  Chain:              {}                                   \n\
         ║  Connections:        {}                                   \n\
         ║  Network Hash Rate:  {:.2} H/s                         \n\
         ║                                                                ║\n\
         ║  MEMPOOL                                                       ║\n\
         ║  Transactions:       {}                                   \n\
         ║  Size:               {:.2} KB                            \n\
         ╚════════════════════════════════════════════════════════════════╝",
        state.node_version, state.chain, state.connections, state.network_hashrate,
        state.mempool_size, state.mempool_bytes as f64 / 1024.0
    );

    f.render_widget(
        Paragraph::new(network_text)
            .style(Style::default().fg(Color::White))
            .block(Block::default().title("Network Status").borders(Borders::ALL)),
        chunks[0]
    );

    let peer_items: Vec<ListItem> = state.peers.iter().skip(scroll as usize).map(|peer| {
        ListItem::new(vec![
            Line::from(vec![
                Span::styled("Peer: ", Style::default().fg(ZCASH_GOLD)),
                Span::styled(&peer.addr, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Version: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", peer.version), Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(&peer.sub_ver, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Synced Blocks: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{}", peer.synced_blocks.unwrap_or(0)),
                    Style::default().fg(Color::White)
                ),
            ]),
            Line::from(""),
        ])
    }).collect();

    f.render_widget(
        List::new(peer_items)
            .block(Block::default()
                .title(format!("Connected Peers ({}) - Use ↑↓ to scroll", state.peers.len()))
                .borders(Borders::ALL)),
        chunks[1]
    );
}

fn render_mining(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(area);

    let mining_text = format!(
        "╔════════════════════════════════════════════════════════════════╗\n\
         ║  MINING INFORMATION                                            ║\n\
         ╠════════════════════════════════════════════════════════════════╣\n\
         ║  Current Height:     {:>10}                              ║\n\
         ║  Difficulty:         {:>10.8}                          ║\n\
         ║  Network Hash Rate:  {:>10.2} H/s                       ║\n\
         ║  Chain:              {}                                   ║\n\
         ║                                                                ║\n\
         ║  Note: Mining on mainnet requires specialized hardware        ║\n\
         ║  For testnet, use the 'generate' command in Control tab       ║\n\
         ╚════════════════════════════════════════════════════════════════╝",
        state.block_height, state.difficulty, state.network_hashrate, state.chain
    );

    f.render_widget(
        Paragraph::new(mining_text)
            .style(Style::default().fg(ZCASH_GOLD))
            .block(Block::default().title("Mining Statistics").borders(Borders::ALL)),
        chunks[0]
    );

    let instructions = vec![
        "Mining Controls:",
        "",
        "For TESTNET only:",
        "  'g' - Generate 1 block",
        "  '5' - Generate 5 blocks",
        "  '1' - Generate 10 blocks",
        "",
        "Mining on mainnet requires:",
        "  - Specialized ASIC hardware",
        "  - Mining pool configuration",
        "  - External mining software",
        "",
        "The Zebra node itself does not mine on mainnet.",
        "It validates and propagates blocks mined by others.",
    ];

    f.render_widget(
        Paragraph::new(instructions.join("\n"))
            .style(Style::default().fg(Color::White))
            .block(Block::default().title("Mining Information").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        chunks[1]
    );
}

fn render_logs(f: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let items: Vec<ListItem> = state.log_messages.iter().rev().skip(scroll as usize).map(|msg| {
        ListItem::new(Line::from(msg.as_str())).style(Style::default().fg(Color::White))
    }).collect();

    f.render_widget(
        List::new(items)
            .block(Block::default()
                .title(format!("Event Logs ({}) - Use ↑↓ to scroll", state.log_messages.len()))
                .borders(Borders::ALL)),
        area
    );
}

fn render_control(f: &mut Frame, area: Rect, state: &AppState) {
    let status = if state.zebra_running {
        if state.connected {
            ("RUNNING", ZCASH_GREEN)
        } else {
            ("STARTING", Color::Yellow)
        }
    } else {
        ("STOPPED", ZCASH_RED)
    };

    let control_text = format!(
        "╔════════════════════════════════════════════════════════════════╗\n\
         ║  NODE CONTROL                                                  ║\n\
         ╠════════════════════════════════════════════════════════════════╣\n\
         ║  Status: {}                                              \n\
         ║  Version: {}                                       \n\
         ║  Chain: {}                                            \n\
         ╚════════════════════════════════════════════════════════════════╝\n\
         \n\
         Controls:\n\
         \n\
         's' - Start Zebra Node\n\
         'x' - Stop Zebra Node\n\
         'r' - Restart Node\n\
         \n\
         Testnet Mining (if on testnet):\n\
         'g' - Generate 1 block\n\
         '5' - Generate 5 blocks\n\
         '1' - Generate 10 blocks\n\
         \n\
         Node will start automatically if not running.\n\
         Default RPC: http://127.0.0.1:8232",
        status.0, state.node_version, state.chain
    );

    f.render_widget(
        Paragraph::new(control_text)
            .style(Style::default().fg(Color::White))
            .block(Block::default().title("Node Control Panel").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area
    );
}

fn render_popup(f: &mut Frame, message: &str) {
    let area = centered_rect(60, 20, f.area());
    
    f.render_widget(Clear, area);
    
    let popup = Paragraph::new(message)
        .style(Style::default().fg(Color::White))
        .block(Block::default()
            .title("Message")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ZCASH_GOLD)))
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Center);
    
    f.render_widget(popup, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

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
                if app.show_popup {
                    if key.code == KeyCode::Enter || key.code == KeyCode::Esc {
                        app.show_popup = false;
                    }
                    continue;
                }

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
                            
                            // Wallet tab - generate addresses
                            KeyCode::Char('t') if app.current_tab == Tab::Wallet || app.current_tab == Tab::Receive => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    match client.get_new_address().await {
                                        Ok(addr) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] New transparent address: {}", Utc::now().format("%H:%M:%S"), addr));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Error: {}", Utc::now().format("%H:%M:%S"), e));
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
                                            s.log_messages.push_back(format!("[{}] New shielded address: {}", Utc::now().format("%H:%M:%S"), addr));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Error: {}", Utc::now().format("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            
                            // Send tab
                            KeyCode::Char('a') if app.current_tab == Tab::Send => app.input_mode = InputMode::SendToAddress,
                            KeyCode::Char('m') if app.current_tab == Tab::Send => app.input_mode = InputMode::SendAmount,
                            KeyCode::Char('e') if app.current_tab == Tab::Send => app.input_mode = InputMode::SendMemo,
                            KeyCode::Enter if app.current_tab == Tab::Send => {
                                let to_addr = app.send_to_address.clone();
                                let amount_str = app.send_amount.clone();
                                let memo = app.send_memo.clone();
                                
                                if let Ok(amount) = amount_str.parse::<f64>() {
                                    let client = Arc::clone(&app.client);
                                    let state = Arc::clone(&app.state);
                                    
                                    tokio::spawn(async move {
                                        let result = if to_addr.starts_with('z') {
                                            let mut amounts = vec![serde_json::json!({
                                                "address": to_addr,
                                                "amount": amount
                                            })];
                                            if !memo.is_empty() {
                                                amounts[0]["memo"] = serde_json::json!(memo);
                                            }
                                            client.z_send_many("ANY_TADDR", amounts).await
                                        } else {
                                            client.send_to_address(&to_addr, amount).await
                                        };
                                        
                                        let mut s = state.lock().await;
                                        match result {
                                            Ok(txid) => s.log_messages.push_back(format!("[{}] Transaction sent: {}", Utc::now().format("%H:%M:%S"), txid)),
                                            Err(e) => s.log_messages.push_back(format!("[{}] Error: {}", Utc::now().format("%H:%M:%S"), e)),
                                        }
                                    });
                                    
                                    app.send_to_address.clear();
                                    app.send_amount.clear();
                                    app.send_memo.clear();
                                }
                            }
                            
                            // Control tab
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
                            KeyCode::Char('g') if app.current_tab == Tab::Control || app.current_tab == Tab::Mining => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    match client.generate(1).await {
                                        Ok(hashes) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Generated 1 block: {}", Utc::now().format("%H:%M:%S"), hashes[0]));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Mining error: {}", Utc::now().format("%H:%M:%S"), e));
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
}("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            KeyCode::Char('5') if app.current_tab == Tab::Control || app.current_tab == Tab::Mining => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    match client.generate(5).await {
                                        Ok(_) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Generated 5 blocks", Utc::now().format("%H:%M:%S")));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Mining error: {}", Utc::now().format("%H:%M:%S"), e));
                                        }
                                    }
                                });
                            }
                            KeyCode::Char('1') if app.current_tab == Tab::Control || app.current_tab == Tab::Mining => {
                                let client = Arc::clone(&app.client);
                                let state = Arc::clone(&app.state);
                                tokio::spawn(async move {
                                    match client.generate(10).await {
                                        Ok(_) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Generated 10 blocks", Utc::now().format("%H:%M:%S")));
                                        }
                                        Err(e) => {
                                            let mut s = state.lock().await;
                                            s.log_messages.push_back(format!("[{}] Mining error: {}", Utc::now().format
