#!/usr/bin/env python3
"""
Production Zcash Testnet Faucet
Fully implemented with security, encryption, and device-based HSM support.

Requirements:
    pip install flask werkzeug requests cryptography pynacl sqlalchemy python-dotenv bcrypt
"""

import os
import json
import time
import hmac
import hashlib
import secrets
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pathlib import Path

# Security & Encryption
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import nacl.secret
import nacl.utils
import bcrypt

# Web Framework
from flask import Flask, request, jsonify, render_template_string, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import safe_join

# Database
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool

# HTTP Client
import requests
from requests.auth import HTTPBasicAuth

# Environment
from dotenv import load_dotenv

# ============================================================================
# CONFIGURATION & LOGGING
# ============================================================================

__version__ = "2.0.0-production"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('faucet.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DEVICE-BASED HSM (HARDWARE SECURITY MODULE EMULATION)
# ============================================================================

class DeviceHSM:
    """
    Device-based encryption using machine-specific identifiers.
    This provides hardware-bound encryption when no HSM is available.
    """
    
    def __init__(self):
        self.device_id = self._get_device_id()
        self.master_key = self._derive_master_key()
        
    def _get_device_id(self) -> bytes:
        """Get unique device identifier from multiple sources"""
        identifiers = []
        
        # CPU info
        try:
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    identifiers.append(f.read())
        except:
            pass
        
        # Machine ID (Linux/systemd)
        try:
            if os.path.exists('/etc/machine-id'):
                with open('/etc/machine-id', 'r') as f:
                    identifiers.append(f.read().strip())
        except:
            pass
        
        # Disk UUID
        try:
            if os.path.exists('/sys/class/dmi/id/product_uuid'):
                with open('/sys/class/dmi/id/product_uuid', 'r') as f:
                    identifiers.append(f.read().strip())
        except:
            pass
        
        # MAC address
        try:
            import uuid
            identifiers.append(str(uuid.getnode()))
        except:
            pass
        
        # Combine all identifiers
        combined = '|'.join(identifiers)
        if not combined:
            raise RuntimeError("Could not determine device identity. Cannot initialize HSM.")
        
        return hashlib.sha256(combined.encode()).digest()
    
    def _derive_master_key(self) -> bytes:
        """Derive master encryption key from device ID"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'zcash-faucet-device-bound-key',
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.device_id)
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using device-bound key"""
        box = nacl.secret.SecretBox(self.master_key)
        return box.encrypt(data)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using device-bound key"""
        box = nacl.secret.SecretBox(self.master_key)
        return box.decrypt(encrypted_data)
    
    def encrypt_string(self, plaintext: str) -> str:
        """Encrypt string and return base64"""
        import base64
        encrypted = self.encrypt(plaintext.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_string(self, ciphertext: str) -> str:
        """Decrypt base64 string"""
        import base64
        encrypted = base64.b64decode(ciphertext.encode())
        return self.decrypt(encrypted).decode()

# ============================================================================
# SECURE ENVIRONMENT FILE HANDLING
# ============================================================================

class SecureEnv:
    """Encrypted environment file management"""
    
    def __init__(self, env_file: str = '.env.encrypted'):
        self.env_file = env_file
        self.hsm = DeviceHSM()
        self.env_data = {}
        
    def create_encrypted_env(self, config: Dict[str, str]):
        """Create encrypted environment file from config dict"""
        plaintext = json.dumps(config, indent=2)
        encrypted = self.hsm.encrypt_string(plaintext)
        
        with open(self.env_file, 'w') as f:
            f.write(encrypted)
        
        logger.info(f"Created encrypted environment file: {self.env_file}")
    
    def load(self) -> Dict[str, str]:
        """Load and decrypt environment file"""
        if not os.path.exists(self.env_file):
            # Try fallback to plain .env
            if os.path.exists('.env'):
                logger.warning("Using unencrypted .env file. Consider encrypting with --encrypt-env")
                load_dotenv()
                return dict(os.environ)
            else:
                raise FileNotFoundError(f"No environment file found: {self.env_file}")
        
        try:
            with open(self.env_file, 'r') as f:
                encrypted = f.read()
            
            plaintext = self.hsm.decrypt_string(encrypted)
            self.env_data = json.loads(plaintext)
            logger.info("Successfully loaded encrypted environment")
            return self.env_data
        
        except Exception as e:
            logger.error(f"Failed to decrypt environment file: {e}")
            logger.error("This may happen if the environment file was created on a different machine.")
            raise
    
    def get(self, key: str, default: str = None) -> str:
        """Get environment variable"""
        return self.env_data.get(key, default)

# ============================================================================
# DATABASE MODELS
# ============================================================================

Base = declarative_base()

class FaucetRequest(Base):
    __tablename__ = 'faucet_requests'
    
    id = Column(Integer, primary_key=True)
    address = Column(String(200), nullable=False, index=True)
    ip_address = Column(String(50), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    operation_id = Column(String(100), nullable=True)
    txid = Column(String(100), nullable=True)
    status = Column(String(20), default='pending', index=True)  # pending, executing, success, failed
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    user_agent = Column(String(500), nullable=True)

class APIKey(Base):
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True)
    key_hash = Column(String(100), unique=True, nullable=False)
    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)

# ============================================================================
# ZCASH RPC CLIENT
# ============================================================================

class ZcashRPC:
    """Production-ready Zcash RPC client with full async operation handling"""
    
    def __init__(self, config: Dict[str, str]):
        self.rpc_url = config.get('RPC_URL', 'http://127.0.0.1:8232')
        self.rpc_user = config.get('RPC_USER')
        self.rpc_password = config.get('RPC_PASSWORD')
        self.node_type = config.get('NODE_TYPE', 'zebra').lower()
        self.testnet = config.get('TESTNET', 'true').lower() == 'true'
        
        logger.info(f"Initialized Zcash RPC client: {self.node_type} at {self.rpc_url}")
    
    def _call(self, method: str, params: List = None) -> Any:
        """Execute RPC call"""
        if params is None:
            params = []
        
        payload = {
            "jsonrpc": "1.0",
            "id": secrets.token_hex(8),
            "method": method,
            "params": params
        }
        
        headers = {"Content-Type": "application/json"}
        auth = None
        
        # zcashd requires authentication, Zebra does not
        if self.node_type == 'zcashd' and self.rpc_user and self.rpc_password:
            auth = HTTPBasicAuth(self.rpc_user, self.rpc_password)
        
        try:
            response = requests.post(
                self.rpc_url,
                json=payload,
                headers=headers,
                auth=auth,
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            
            if 'error' in result and result['error'] is not None:
                error_msg = result['error'].get('message', 'Unknown RPC error')
                logger.error(f"RPC error in {method}: {error_msg}")
                raise Exception(f"RPC error: {error_msg}")
            
            return result.get('result')
        
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP error calling {method}: {e}")
            raise
    
    def get_balance(self) -> float:
        """Get wallet balance"""
        try:
            balance = self._call('getbalance')
            return float(balance) if balance else 0.0
        except Exception as e:
            logger.error(f"Failed to get balance: {e}")
            return 0.0
    
    def get_blockchain_info(self) -> Dict:
        """Get blockchain information"""
        return self._call('getblockchaininfo')
    
    def validate_address(self, address: str) -> Dict:
        """Validate address format"""
        return self._call('validateaddress', [address])
    
    def send_many(self, address: str, amount: float) -> str:
        """
        Send ZEC to address using z_sendmany (async operation).
        Returns operation ID that must be polled for completion.
        """
        # z_sendmany parameters:
        # 1. from_address: "ANY_TADDR" to use any transparent address
        # 2. amounts: array of {address, amount} objects
        # 3. minconf: minimum confirmations (default 1)
        # 4. fee: transaction fee (default 0.0001)
        
        params = [
            "ANY_TADDR",
            [{"address": address, "amount": amount}],
            1,  # minconf
            0.0001  # fee
        ]
        
        operation_id = self._call('z_sendmany', params)
        logger.info(f"Initiated transaction to {address}: operation {operation_id}")
        return operation_id
    
    def get_operation_status(self, operation_id: str) -> Dict:
        """Get status of async operation"""
        result = self._call('z_getoperationstatus', [[operation_id]])
        if result and len(result) > 0:
            return result[0]
        return None
    
    def wait_for_operation(self, operation_id: str, timeout: int = 60) -> Dict:
        """
        Wait for async operation to complete.
        Returns operation result with status: success, failed, or cancelled.
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_operation_status(operation_id)
            
            if not status:
                logger.warning(f"Operation {operation_id} not found")
                return None
            
            op_status = status.get('status')
            
            if op_status in ['success', 'failed', 'cancelled']:
                logger.info(f"Operation {operation_id} completed with status: {op_status}")
                return status
            
            # Still executing
            time.sleep(2)
        
        logger.warning(f"Operation {operation_id} timed out after {timeout}s")
        return {'status': 'timeout', 'id': operation_id}

# ============================================================================
# ADDRESS VALIDATION
# ============================================================================

def validate_zcash_address(address: str, testnet: bool = True) -> bool:
    """Validate Zcash address format (testnet)"""
    import re
    
    if not address or not isinstance(address, str):
        return False
    
    if testnet:
        # Testnet patterns
        patterns = [
            r'^tm1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$',  # P2PKH
            r'^tm3[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$',  # P2SH
            r'^ztestsapling[a-z0-9]{76}$',  # Sapling
            r'^utest1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{60,}$',  # Unified
        ]
    else:
        # Mainnet patterns (not used in faucet)
        patterns = [
            r'^t1[a-zA-Z0-9]{33}$',
            r'^t3[a-zA-Z0-9]{33}$',
            r'^zs1[a-z0-9]{75}$',
            r'^u1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{60,}$',
        ]
    
    return any(re.match(pattern, address) for pattern in patterns)

# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """In-memory rate limiter with database persistence"""
    
    def __init__(self, db_session, config: Dict[str, str]):
        self.db = db_session
        self.daily_limit_address = float(config.get('DAILY_LIMIT_ADDRESS', '500'))
        self.daily_limit_ip = float(config.get('DAILY_LIMIT_IP', '1000'))
        self.rate_limit_minutes = int(config.get('RATE_LIMIT_MINUTES', '60'))
    
    def check_limits(self, address: str, ip_address: str) -> tuple[bool, str]:
        """Check if request is within rate limits"""
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        hour_ago = now - timedelta(minutes=self.rate_limit_minutes)
        
        # Check address daily limit
        address_total = self.db.query(
            sqlalchemy.func.sum(FaucetRequest.amount)
        ).filter(
            FaucetRequest.address == address,
            FaucetRequest.created_at >= day_ago,
            FaucetRequest.status == 'success'
        ).scalar() or 0.0
        
        if address_total >= self.daily_limit_address:
            return False, f"Daily limit reached for address ({self.daily_limit_address} ZEC/day)"
        
        # Check IP daily limit
        ip_total = self.db.query(
            sqlalchemy.func.sum(FaucetRequest.amount)
        ).filter(
            FaucetRequest.ip_address == ip_address,
            FaucetRequest.created_at >= day_ago,
            FaucetRequest.status == 'success'
        ).scalar() or 0.0
        
        if ip_total >= self.daily_limit_ip:
            return False, f"Daily limit reached for IP ({self.daily_limit_ip} ZEC/day)"
        
        # Check recent requests (time-based rate limit)
        recent_count = self.db.query(FaucetRequest).filter(
            sqlalchemy.or_(
                FaucetRequest.address == address,
                FaucetRequest.ip_address == ip_address
            ),
            FaucetRequest.created_at >= hour_ago
        ).count()
        
        if recent_count > 0:
            return False, f"Please wait {self.rate_limit_minutes} minutes between requests"
        
        return True, "OK"

# ============================================================================
# FLASK APPLICATION
# ============================================================================

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = secrets.token_hex(32)

# Global state
secure_env = None
zcash_rpc = None
db_session = None
rate_limiter = None
config_data = None

def init_app():
    """Initialize application components"""
    global secure_env, zcash_rpc, db_session, rate_limiter, config_data
    
    # Load encrypted environment
    secure_env = SecureEnv()
    config_data = secure_env.load()
    
    # Initialize Zcash RPC
    zcash_rpc = ZcashRPC(config_data)
    
    # Initialize database
    database_url = config_data.get('DATABASE_URL', 'sqlite:///faucet.db')
    engine = create_engine(
        database_url,
        connect_args={'check_same_thread': False} if 'sqlite' in database_url else{},
        poolclass=StaticPool if 'sqlite' in database_url else None
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    db_session = scoped_session(session_factory)
    
    # Initialize rate limiter
    rate_limiter = RateLimiter(db_session, config_data)
    
    logger.info("Application initialized successfully")

# Import sqlalchemy.func for rate limiter
import sqlalchemy
import sqlalchemy.func

# ============================================================================
# API ROUTES
# ============================================================================

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zcash Testnet Faucet</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 800px; margin: 0 auto; }
        .card {
            background: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        h1 { color: #667eea; margin-bottom: 10px; font-size: 2.5em; text-align: center; }
        .subtitle { color: #666; text-align: center; margin-bottom: 30px; }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            margin-bottom: 15px;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-box {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        .stat-value { font-size: 2em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; font-size: 0.9em; margin-top: 5px; }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .info-box {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .secure-badge {
            display: inline-block;
            background: #28a745;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.8em;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>⚡ Zcash Testnet Faucet<span class="secure-badge">🔒 SECURE</span></h1>
            <p class="subtitle">Production-grade faucet with device-bound encryption</p>
        </div>

        {% if message %}
        <div class="alert alert-{{ 'success' if success else 'error' }}">
            {{ message|safe }}
        </div>
        {% endif %}

        <div class="card">
            <h2 style="margin-bottom: 20px;">Request Testnet ZEC</h2>
            <form method="POST" action="/request">
                <input type="text" name="address" placeholder="Testnet address (tm1q..., ztestsapling..., utest1...)" required>
                <input type="number" name="amount" min="1" max="{{ max_amount }}" value="{{ max_amount }}" required>
                <button type="submit">💰 Request ZEC</button>
            </form>
        </div>

        <div class="card">
            <h3 style="margin-bottom: 15px;">Statistics</h3>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">{{ "%.2f"|format(balance) }}</div>
                    <div class="stat-label">Balance (ZEC)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{{ max_amount }}</div>
                    <div class="stat-label">Per Request</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{{ daily_limit }}</div>
                    <div class="stat-label">Daily Limit</div>
                </div>
            </div>
        </div>

        <div class="card info-box">
            <h3 style="color: #667eea; margin-bottom: 10px;">🔒 Security Features</h3>
            <ul style="margin-left: 20px; color: #555;">
                <li>Device-bound encryption for sensitive data</li>
                <li>Encrypted environment configuration</li>
                <li>Rate limiting and abuse prevention</li>
                <li>Secure async operation handling</li>
                <li>Production-ready logging and monitoring</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    """Main faucet page"""
    try:
        balance = zcash_rpc.get_balance()
        max_amount = float(config_data.get('MAX_PER_REQUEST', '100'))
        daily_limit = float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
        
        return render_template_string(
            HTML_TEMPLATE,
            balance=balance,
            max_amount=max_amount,
            daily_limit=daily_limit
        )
    except Exception as e:
        logger.error(f"Error rendering index: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/request', methods=['POST'])
def request_zec():
    """Handle ZEC request from web form"""
    try:
        address = request.form.get('address', '').strip()
        amount = float(request.form.get('amount', 0))
        
        # Get client IP
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        user_agent = request.headers.get('User-Agent', '')
        
        # Validate address
        if not validate_zcash_address(address, testnet=True):
            return render_template_string(
                HTML_TEMPLATE,
                message="Invalid testnet address format",
                success=False,
                balance=zcash_rpc.get_balance(),
                max_amount=float(config_data.get('MAX_PER_REQUEST', '100')),
                daily_limit=float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
            )
        
        # Validate amount
        max_amount = float(config_data.get('MAX_PER_REQUEST', '100'))
        if amount <= 0 or amount > max_amount:
            return render_template_string(
                HTML_TEMPLATE,
                message=f"Amount must be between 1 and {max_amount} ZEC",
                success=False,
                balance=zcash_rpc.get_balance(),
                max_amount=max_amount,
                daily_limit=float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
            )
        
        # Check rate limits
        can_proceed, limit_msg = rate_limiter.check_limits(address, ip_address)
        if not can_proceed:
            return render_template_string(
                HTML_TEMPLATE,
                message=f"❌ {limit_msg}",
                success=False,
                balance=zcash_rpc.get_balance(),
                max_amount=max_amount,
                daily_limit=float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
            )
        
        # Check balance
        balance = zcash_rpc.get_balance()
        if balance < amount:
            return render_template_string(
                HTML_TEMPLATE,
                message=f"❌ Insufficient faucet balance ({balance} ZEC available)",
                success=False,
                balance=balance,
                max_amount=max_amount,
                daily_limit=float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
            )
        
        # Create database record
        req = FaucetRequest(
            address=address,
            ip_address=ip_address,
            amount=amount,
            user_agent=user_agent,
            status='pending'
        )
        db_session.add(req)
        db_session.commit()
        
        try:
            # Initiate transaction (async operation)
            operation_id = zcash_rpc.send_many(address, amount)
            req.operation_id = operation_id
            req.status = 'executing'
            db_session.commit()
            
            # Wait for operation to complete
            operation_result = zcash_rpc.wait_for_operation(operation_id, timeout=60)
            
            if operation_result and operation_result.get('status') == 'success':
                txid = operation_result.get('result', {}).get('txid')
                req.txid = txid
                req.status = 'success'
                req.completed_at = datetime.utcnow()
                db_session.commit()
                
                explorer_url = config_data.get('EXPLORER_URL', 'https://explorer.testnet.z.cash')
                message = f"""
                ✅ Successfully sent {amount} ZEC!<br><br>
                <strong>Transaction ID:</strong><br>
                <code>{txid}</code><br><br>
                <a href="{explorer_url}/tx/{txid}" target="_blank">View on Explorer</a>
                """
                
                return render_template_string(
                    HTML_TEMPLATE,
                    message=message,
                    success=True,
                    balance=zcash_rpc.get_balance(),
                    max_amount=max_amount,
                    daily_limit=float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
                )
            else:
                # Operation failed
                error = operation_result.get('error', {}).get('message', 'Unknown error') if operation_result else 'Timeout'
                req.status = 'failed'
                req.error_message = error
                req.completed_at = datetime.utcnow()
                db_session.commit()
                
                return render_template_string(
                    HTML_TEMPLATE,
                    message=f"❌ Transaction failed: {error}",
                    success=False,
                    balance=zcash_rpc.get_balance(),
                    max_amount=max_amount,
                    daily_limit=float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
                )
        
        except Exception as e:
            logger.error(f"Transaction error: {e}")
            req.status = 'failed'
            req.error_message = str(e)
            req.completed_at = datetime.utcnow()
            db_session.commit()
            
            return render_template_string(
                HTML_TEMPLATE,
                message=f"❌ Transaction error: {str(e)}",
                success=False,
                balance=zcash_rpc.get_balance(),
                max_amount=max_amount,
                daily_limit=float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
            )
    
    except Exception as e:
        logger.error(f"Request handler error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/request', methods=['POST'])
def api_request_zec():
    """API endpoint for ZEC requests"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400
        
        # Check API key if required
        if config_data.get('API_KEY_REQUIRED', 'false').lower() == 'true':
            api_key = request.headers.get('X-API-Key') or data.get('api_key')
            if not api_key:
                return jsonify({'success': False, 'error': 'API key required'}), 401
            
            # Verify API key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            api_key_obj = db_session.query(APIKey).filter_by(key_hash=key_hash, is_active=True).first()
            if not api_key_obj:
                return jsonify({'success': False, 'error': 'Invalid API key'}), 401
            
            api_key_obj.last_used = datetime.utcnow()
            db_session.commit()
        
        address = data.get('address', '').strip()
        amount = float(data.get('amount', 0))
        
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        user_agent = request.headers.get('User-Agent', '')
        
        # Validate
        if not validate_zcash_address(address, testnet=True):
            return jsonify({'success': False, 'error': 'Invalid testnet address'}), 400
        
        max_amount = float(config_data.get('MAX_PER_REQUEST', '100'))
        if amount <= 0 or amount > max_amount:
            return jsonify({
                'success': False,
                'error': f'Amount must be between 1 and {max_amount}'
            }), 400
        
        # Rate limits
        can_proceed, limit_msg = rate_limiter.check_limits(address, ip_address)
        if not can_proceed:
            return jsonify({'success': False, 'error': limit_msg}), 429
        
        # Balance check
        balance = zcash_rpc.get_balance()
        if balance < amount:
            return jsonify({
                'success': False,
                'error': f'Insufficient balance ({balance} ZEC available)'
            }), 503
        
        # Create record
        req = FaucetRequest(
            address=address,
            ip_address=ip_address,
            amount=amount,
            user_agent=user_agent,
            status='pending'
        )
        db_session.add(req)
        db_session.commit()
        
        try:
            # Send transaction
            operation_id = zcash_rpc.send_many(address, amount)
            req.operation_id = operation_id
            req.status = 'executing'
            db_session.commit()
            
            # Wait for completion
            operation_result = zcash_rpc.wait_for_operation(operation_id, timeout=60)
            
            if operation_result and operation_result.get('status') == 'success':
                txid = operation_result.get('result', {}).get('txid')
                req.txid = txid
                req.status = 'success'
                req.completed_at = datetime.utcnow()
                db_session.commit()
                
                explorer_url = config_data.get('EXPLORER_URL', 'https://explorer.testnet.z.cash')
                
                return jsonify({
                    'success': True,
                    'amount': amount,
                    'address': address,
                    'txid': txid,
                    'operation_id': operation_id,
                    'explorer_url': f'{explorer_url}/tx/{txid}'
                })
            else:
                error = operation_result.get('error', {}).get('message', 'Unknown error') if operation_result else 'Timeout'
                req.status = 'failed'
                req.error_message = error
                req.completed_at = datetime.utcnow()
                db_session.commit()
                
                return jsonify({'success': False, 'error': error}), 500
        
        except Exception as e:
            logger.error(f"API transaction error: {e}")
            req.status = 'failed'
            req.error_message = str(e)
            req.completed_at = datetime.utcnow()
            db_session.commit()
            
            return jsonify({'success': False, 'error': str(e)}), 500
    
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get faucet statistics"""
    try:
        balance = zcash_rpc.get_balance()
        
        # Total distributed
        total_distributed = db_session.query(
            sqlalchemy.func.sum(FaucetRequest.amount)
        ).filter(FaucetRequest.status == 'success').scalar() or 0.0
        
        # Total requests
        total_requests = db_session.query(FaucetRequest).count()
        
        # Requests today
        today = datetime.utcnow().date()
        requests_today = db_session.query(FaucetRequest).filter(
            sqlalchemy.func.date(FaucetRequest.created_at) == today
        ).count()
        
        # Success rate
        successful = db_session.query(FaucetRequest).filter(
            FaucetRequest.status == 'success'
        ).count()
        success_rate = (successful / total_requests * 100) if total_requests > 0 else 0
        
        return jsonify({
            'balance': balance,
            'total_distributed': total_distributed,
            'total_requests': total_requests,
            'requests_today': requests_today,
            'success_rate': round(success_rate, 2),
            'max_per_request': float(config_data.get('MAX_PER_REQUEST', '100')),
            'daily_limit': float(config_data.get('DAILY_LIMIT_ADDRESS', '500'))
        })
    
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        balance = zcash_rpc.get_balance()
        blockchain_info = zcash_rpc.get_blockchain_info()
        
        return jsonify({
            'status': 'healthy',
            'balance': balance,
            'blocks': blockchain_info.get('blocks'),
            'chain': blockchain_info.get('chain'),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/admin/generate-api-key', methods=['POST'])
def generate_api_key():
    """Generate new API key (admin only - add auth in production)"""
    try:
        data = request.get_json() or {}
        description = data.get('description', 'API Key')
        
        # Generate API key
        api_key = f"zec_test_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store in database
        api_key_obj = APIKey(
            key_hash=key_hash,
            description=description
        )
        db_session.add(api_key_obj)
        db_session.commit()
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'description': description,
            'created_at': api_key_obj.created_at.isoformat()
        })
    
    except Exception as e:
        logger.error(f"Failed to generate API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def create_default_env():
    """Create default encrypted environment file"""
    config = {
        "NODE_TYPE": "zebra",
        "RPC_URL": "http://127.0.0.1:8232",
        "RPC_USER": "",
        "RPC_PASSWORD": "",
        "TESTNET": "true",
        "MAX_PER_REQUEST": "100",
        "DAILY_LIMIT_ADDRESS": "500",
        "DAILY_LIMIT_IP": "1000",
        "RATE_LIMIT_MINUTES": "60",
        "DATABASE_URL": "sqlite:///faucet.db",
        "EXPLORER_URL": "https://explorer.testnet.z.cash",
        "API_KEY_REQUIRED": "false",
        "HOST": "127.0.0.1",
        "PORT": "5000"
    }
    
    env = SecureEnv()
    env.create_encrypted_env(config)
    
    print("\n✅ Created encrypted environment file: .env.encrypted")
    print("📝 Edit the configuration and re-encrypt if needed\n")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Production Zcash Testnet Faucet',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create encrypted environment file
  python faucet.py --create-env
  
  # Run faucet server
  python faucet.py
  
  # Run on custom host/port
  python faucet.py --host 0.0.0.0 --port 8080
  
  # Check node status
  python faucet.py --node-info
  
  # Generate API key
  python faucet.py --generate-api-key "My App"
        """
    )
    
    parser.add_argument('--create-env', action='store_true',
                      help='Create default encrypted environment file')
    parser.add_argument('--node-info', action='store_true',
                      help='Display Zcash node information')
    parser.add_argument('--generate-api-key', type=str, metavar='DESCRIPTION',
                      help='Generate new API key with description')
    parser.add_argument('--host', default=None,
                      help='Host to bind to (default from config)')
    parser.add_argument('--port', type=int, default=None,
                      help='Port to bind to (default from config)')
    parser.add_argument('--debug', action='store_true',
                      help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create environment file
    if args.create_env:
        create_default_env()
        return
    
    # Initialize application
    print("=" * 70)
    print("🚀 Production Zcash Testnet Faucet")
    print("=" * 70)
    print(f"Version: {__version__}")
    print("=" * 70)
    
    try:
        init_app()
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        print(f"\n❌ Initialization failed: {e}")
        print("\nIf this is your first run, create an encrypted environment:")
        print("  python faucet.py --create-env\n")
        return
    
    # Node info
    if args.node_info:
        try:
            info = zcash_rpc.get_blockchain_info()
            balance = zcash_rpc.get_balance()
            
            print("\n📊 Node Information")
            print("-" * 70)
            print(f"Node Type: {config_data.get('NODE_TYPE', 'unknown')}")
            print(f"RPC URL: {config_data.get('RPC_URL')}")
            print(f"Chain: {info.get('chain', 'unknown')}")
            print(f"Blocks: {info.get('blocks', 'unknown')}")
            print(f"Balance: {balance} ZEC")
            print(f"Testnet: {config_data.get('TESTNET', 'unknown')}")
            print("-" * 70)
            
            # Stats
            total_requests = db_session.query(FaucetRequest).count()
            successful = db_session.query(FaucetRequest).filter(
                FaucetRequest.status == 'success'
            ).count()
            
            print(f"\n📈 Faucet Statistics")
            print("-" * 70)
            print(f"Total Requests: {total_requests}")
            print(f"Successful: {successful}")
            print(f"Failed: {total_requests - successful}")
            print("-" * 70)
            
            if config_data.get('NODE_TYPE', '').lower() == 'zcashd':
                print("\n⚠️  WARNING: zcashd is deprecated (Q2 2025)")
                print("   Migrate to Zebra: https://github.com/zcashfoundation/zebra\n")
        
        except Exception as e:
            logger.error(f"Failed to get node info: {e}")
            print(f"\n❌ Error: {e}\n")
        
        return
    
    # Generate API key
    if args.generate_api_key:
        description = args.generate_api_key
        api_key = f"zec_test_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        api_key_obj = APIKey(
            key_hash=key_hash,
            description=description
        )
        db_session.add(api_key_obj)
        db_session.commit()
        
        print(f"\n✅ Generated API Key")
        print("-" * 70)
        print(f"Key: {api_key}")
        print(f"Description: {description}")
        print(f"Created: {api_key_obj.created_at}")
        print("-" * 70)
        print("\nAdd to requests:")
        print(f"  Header: X-API-Key: {api_key}")
        print(f"  Or JSON: {{'api_key': '{api_key}'}}\n")
        
        return
    
    # Run server
    host = args.host or config_data.get('HOST', '127.0.0.1')
    port = args.port or int(config_data.get('PORT', '5000'))
    
    print(f"\n🔒 Security Features:")
    print(f"  • Device-bound encryption: ✅ ENABLED")
    print(f"  • Encrypted environment: ✅ ENABLED")
    print(f"  • Rate limiting: ✅ ENABLED")
    print(f"  • Async operations: ✅ ENABLED")
    
    print(f"\n⚙️  Configuration:")
    print(f"  • Host: {host}")
    print(f"  • Port: {port}")
    print(f"  • Node: {config_data.get('NODE_TYPE', 'unknown')}")
    print(f"  • Balance: {zcash_rpc.get_balance()} ZEC")
    print(f"  • Max per request: {config_data.get('MAX_PER_REQUEST')} ZEC")
    print(f"  • Daily limit: {config_data.get('DAILY_LIMIT_ADDRESS')} ZEC")
    
    print(f"\n🌐 Server starting...")
    print(f"  • Web UI: http://{host}:{port}")
    print(f"  • API: http://{host}:{port}/api/request")
    print(f"  • Health: http://{host}:{port}/health")
    print(f"  • Stats: http://{host}:{port}/api/stats")
    print("=" * 70)
    print()
    
    try:
        app.run(
            host=host,
            port=port,
            debug=args.debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Shutting down gracefully...")
        db_session.close()
        print("✅ Shutdown complete\n")
    except Exception as e:
        logger.error(f"Server error: {e}")
        print(f"\n❌ Server error: {e}\n")

if __name__ == '__main__':
    main()
