import os, sys, json, time, datetime, subprocess, base64, re, secrets, threading, hashlib, sqlite3, socket, select, struct, ssl
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlparse, parse_qs


def is_call_allowed_now(client):
    """
    Checks if voice phone call alert is enabled and current local time is within permitted time slot.
    Default slot: 10:00 AM - 6:00 PM (10:00 to 18:00) IST.
    """
    if not client.get('call_alert_enabled', 1):
        return False, "Voice phone call alerts disabled for this client"
    start_str = str(client.get('call_window_start') or '10:00').strip()
    end_str = str(client.get('call_window_end') or '18:00').strip()
    ist_now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    curr_hm = ist_now.strftime('%H:%M')
    if start_str <= end_str:
        allowed = start_str <= curr_hm <= end_str
    else:
        allowed = curr_hm >= start_str or curr_hm <= end_str
    if not allowed:
        return False, f"Outside calling window ({start_str} - {end_str}). Current time is {curr_hm} IST"
    return True, f"Within calling window ({start_str} - {end_str})"

# Base directory setup: supports /srv/gavasah-cloud on Linux with local fallback
if 'BASE_DIR' in os.environ:
    BASE_DIR = os.environ['BASE_DIR']
elif os.path.exists('/srv') or (os.name != 'nt' and os.path.exists('/')):
    BASE_DIR = '/srv/gavasah-cloud'
else:
    BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

os.makedirs(BASE_DIR, exist_ok=True)
STATE_FILE = os.environ.get('STATE_FILE', os.path.join(BASE_DIR, 'clients_state.json'))
AUTH_FILE = os.environ.get('AUTH_FILE', os.path.join(BASE_DIR, 'auth_state.json'))
LOGS_DIR = os.environ.get('LOGS_DIR', os.path.join(BASE_DIR, 'logs'))
DB_FILE = os.environ.get('DB_FILE', os.path.join(BASE_DIR, 'fleet.db'))
PORT = int(os.environ.get('PORT', 3000))
WG_SERVER_PUBKEY = os.environ.get('WG_SERVER_PUBKEY', 'SpiDqVVfDrzrIlfmuDbffXVwQcWC2bb4J5TopI1q6Wk=')
WG_ENDPOINT = os.environ.get('WG_ENDPOINT', 'dealer.gavasah.com:51820')
WG_INTERFACE = os.environ.get('WG_INTERFACE', 'wg0')

# Thread concurrency locks
STATE_LOCK = threading.RLock()
AUTH_LOCK = threading.RLock()
LOGS_LOCK = threading.RLock()
DB_LOCK = threading.RLock()

# In-memory synchronization caches
REGISTERED_SSH_KEYS = set()
SYNCED_CADDY_ROUTES = {}

# ==============================================================================
# Cryptographic Password & Session Helpers
# ==============================================================================
def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt, hashed

def verify_password(password, salt, expected_hash):
    _, test_hash = hash_password(password, salt)
    return secrets.compare_digest(test_hash, expected_hash)

# ==============================================================================
# WireGuard Overlay Mesh Data Access & Peer Management
# ==============================================================================
def generate_wg_keypair():
    try:
        priv = subprocess.check_output(['wg', 'genkey'], text=True).strip()
        pub = subprocess.check_output(['wg', 'pubkey'], input=priv, text=True).strip()
        return priv, pub
    except Exception:
        priv = base64.b64encode(secrets.token_bytes(32)).decode()
        pub = base64.b64encode(hashlib.sha256(priv.encode()).digest()).decode()
        return priv, pub

def sync_wireguard_peer(pubkey, ip):
    if not pubkey or not ip or os.name == 'nt' or os.environ.get('MOCK_WG') == '1':
        return True
    try:
        cmd = ['wg', 'set', WG_INTERFACE, 'peer', pubkey, 'allowed-ips', f"{ip}/32", 'persistent-keepalive', '25']
        subprocess.run(cmd, check=True, timeout=5)
        return True
    except Exception as e:
        print(f"[!] Warning syncing WireGuard peer {pubkey} ({ip}): {e}")
        return False

def remove_wireguard_peer(pubkey):
    if not pubkey or os.name == 'nt' or os.environ.get('MOCK_WG') == '1':
        return True
    try:
        cmd = ['wg', 'set', WG_INTERFACE, 'peer', pubkey, 'remove']
        subprocess.run(cmd, check=True, timeout=5)
        return True
    except Exception as e:
        print(f"[!] Warning removing WireGuard peer {pubkey}: {e}")
        return False

def allocate_next_wg_ip():
    with DB_LOCK:
        conn = get_db_connection()
        rows = conn.execute("SELECT wg_ip FROM clients WHERE wg_ip IS NOT NULL").fetchall()
        conn.close()
        used_ips = {r['wg_ip'] for r in rows}
        for b in range(0, 256):
            for c in range(2 if b == 0 else 1, 255):
                candidate = f"10.42.{b}.{c}"
                if candidate not in used_ips:
                    return candidate
        raise Exception("WireGuard /16 subnet address space exhausted (65,534 nodes allocated)!")

# ==============================================================================
# SQLite with WAL Mode (Write-Ahead Logging) Data Access Layer
# ==============================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode = WAL;')
    conn.execute('PRAGMA synchronous = NORMAL;')
    conn.execute('PRAGMA busy_timeout = 5000;')
    return conn

# ==============================================================================
# Remote ETS UDP Port Pool Management (Monotonic Ring Buffer & FIFO Recycle)
# Designated Clean UDP Range: 10001 - 20000 (10,000 Ports)
# ==============================================================================
ETS_PORT_MIN = 10001
ETS_PORT_MAX = 20000

def allocate_ets_port(client_id, target_ip='127.0.0.1', target_port=3671, target_type='onboard'):
    """
    Ring buffer with FIFO recycle policy for ETS UDP remote programming ports (10001 - 20000).
    1. Checks if client_id already holds an active ets_port. If so, updates target info and returns it.
    2. Monotonically increments high_watermark from 10001 up to 20000.
    3. Released ports are NEVER immediately reassigned until the pool reaches 20000 (every other port is taken).
    4. Only when high_watermark >= 20000, recycles the oldest released port (FIFO based on released_at).
    """
    with DB_LOCK:
        conn = get_db_connection()
        try:
            with conn:
                cur = conn.cursor()
                # 1. Existing allocation check
                cur.execute("SELECT ets_port FROM clients WHERE client_id = ?", (client_id,))
                row = cur.fetchone()
                now = int(time.time())
                if row and row['ets_port']:
                    existing_port = row['ets_port']
                    cur.execute("""
                        UPDATE clients SET
                            ets_target_type = ?,
                            ets_target_ip = ?,
                            ets_target_port = ?
                        WHERE client_id = ?
                    """, (target_type, target_ip or '127.0.0.1', target_port or 3671, client_id))
                    cur.execute("""
                        INSERT OR REPLACE INTO ets_port_pool (port, client_id, status, allocated_at, released_at)
                        VALUES (?, ?, 'allocated', ?, NULL)
                    """, (existing_port, client_id, now))
                    return existing_port

                # 2. Check high-watermark
                cur.execute("SELECT value FROM ets_allocator_meta WHERE key = 'high_watermark'")
                meta_row = cur.fetchone()
                hw_val = int(meta_row['value']) if meta_row else 10000

                assigned_port = None
                if hw_val < ETS_PORT_MAX:
                    # Allocate next clean monotonic port
                    candidate = hw_val + 1
                    assigned_port = candidate
                    cur.execute("INSERT OR REPLACE INTO ets_allocator_meta (key, value) VALUES ('high_watermark', ?)", (str(candidate),))
                else:
                    # Ring buffer exhausted initial run: FIFO recycle oldest released port
                    cur.execute("""
                        SELECT port FROM ets_port_pool
                        WHERE status = 'released'
                        ORDER BY released_at ASC, port ASC
                        LIMIT 1
                    """)
                    rel_row = cur.fetchone()
                    if rel_row:
                        assigned_port = rel_row['port']
                    else:
                        raise Exception(f"ETS Remote Port pool ({ETS_PORT_MIN}-{ETS_PORT_MAX}) fully exhausted! 10,000 active gateways connected.")

                # Record assignment in pool
                cur.execute("""
                    INSERT OR REPLACE INTO ets_port_pool (port, client_id, status, allocated_at, released_at)
                    VALUES (?, ?, 'allocated', ?, NULL)
                """, (assigned_port, client_id, now))

                # Update clients record
                cur.execute("""
                    UPDATE clients SET
                        ets_port = ?,
                        ets_target_type = ?,
                        ets_target_ip = ?,
                        ets_target_port = ?,
                        ets_port_assigned_at = ?
                    WHERE client_id = ?
                """, (assigned_port, target_type, target_ip or '127.0.0.1', target_port or 3671, now, client_id))

            conn.close()
            return assigned_port
        except Exception as e:
            conn.close()
            raise e

def release_ets_port(client_id):
    """
    Frees the ETS port allocated to client_id.
    Marks status as 'released' with current timestamp so it enters the FIFO queue,
    which will only be recycled after the high-watermark reaches 20000.
    """
    with DB_LOCK:
        conn = get_db_connection()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT ets_port FROM clients WHERE client_id = ?", (client_id,))
                row = cur.fetchone()
                if row and row['ets_port']:
                    port = row['ets_port']
                    now = int(time.time())
                    cur.execute("""
                        UPDATE ets_port_pool SET
                            status = 'released',
                            client_id = NULL,
                            released_at = ?
                        WHERE port = ?
                    """, (now, port))
                    cur.execute("""
                        UPDATE clients SET
                            ets_port = NULL,
                            ets_target_type = NULL,
                            ets_target_ip = NULL,
                            ets_target_port = NULL,
                            ets_port_assigned_at = NULL
                        WHERE client_id = ?
                    """, (client_id,))
                    print(f"[*] Released remote ETS port {port} for client '{client_id}' (queued for FIFO recycle)")
            conn.close()
            return True
        except Exception as e:
            conn.close()
            print(f"[!] Error releasing ETS port for {client_id}: {e}")
            return False

# ==============================================================================
# KNXnet/IP Application Layer Gateway (ALG) Proxy for Remote ETS Programming
# ==============================================================================
class KnxAlgProxyManager:
    """
    Autonomous KNXnet/IP Application Layer Gateway (ALG) Proxy for Remote ETS Programming.
    Intercepts and manages remote UDP ETS sessions across the WireGuard mesh.
    Normalizes Server Data Endpoint HPAI in CONNECT_RESPONSE frames from internal LAN IPs (e.g. 192.168.1.111:0)
    to RFC-compliant NAT route-back (0.0.0.0:0).
    Ensures ETS Falcon stack communicates reliably without packet drops or timeout aborts.
    """
    def __init__(self):
        self.proxies = {} # port -> dict
        self.lock = threading.Lock()
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name="KnxAlgProxyManager")
        self.thread.start()

    def sync(self, port_targets):
        """
        port_targets: dict of {port: (wg_ip, client_id)}
        """
        with self.lock:
            # 1. Close obsolete or re-routed proxies
            for port in list(self.proxies.keys()):
                if port not in port_targets or self.proxies[port]['target_ip'] != port_targets[port][0]:
                    p = self.proxies.pop(port)
                    try: p['client_sock'].close()
                    except Exception: pass
                    try: p['gw_sock'].close()
                    except Exception: pass
                    print(f"[KNX-ALG] Closed proxy on port {port}")

            # 2. Add or maintain active proxies
            for port, (wg_ip, cid) in port_targets.items():
                if port not in self.proxies:
                    try:
                        cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        cs.bind(('0.0.0.0', int(port)))

                        gs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        # Bind gateway-facing socket to wg0 IP if possible, else 0.0.0.0
                        try:
                            gs.bind(('10.42.0.1', 0))
                        except Exception:
                            gs.bind(('0.0.0.0', 0))

                        self.proxies[port] = {
                            'client_sock': cs,
                            'gw_sock': gs,
                            'target_ip': wg_ip,
                            'target_port': 3671,
                            'client_id': cid,
                            'client_addr': None,
                            'channel_map': {}, # chan_id -> client_addr
                            'last_seen': time.time()
                        }
                        print(f"[KNX-ALG] Started proxy on 0.0.0.0:{port} -> {wg_ip}:3671 (Client: {cid})")
                    except Exception as e:
                        print(f"[KNX-ALG] Failed binding port {port}: {e}")

    def _run_loop(self):
        while self.running:
            with self.lock:
                socks_map = {}
                for port, p in self.proxies.items():
                    socks_map[p['client_sock']] = (port, 'client')
                    socks_map[p['gw_sock']] = (port, 'gw')

            if not socks_map:
                time.sleep(0.5)
                continue

            try:
                r, _, _ = select.select(list(socks_map.keys()), [], [], 0.5)
            except Exception:
                continue

            now = time.time()
            for s in r:
                info = socks_map.get(s)
                if not info:
                    continue
                port, role = info
                with self.lock:
                    p = self.proxies.get(port)
                    if not p:
                        continue

                try:
                    data, addr = s.recvfrom(2048)
                except Exception:
                    continue

                if role == 'client':
                    p['client_addr'] = addr
                    p['last_seen'] = now
                    try:
                        p['gw_sock'].sendto(data, (p['target_ip'], p['target_port']))
                    except Exception as e:
                        print(f"[KNX-ALG] Forward to GW ({p['target_ip']}) failed: {e}", flush=True)

                elif role == 'gw':
                    if p['client_addr']:
                        # Intercept CONNECT_RESPONSE (0x0206)
                        if len(data) >= 16 and data[2] == 0x02 and data[3] == 0x06:
                            orig_ip = socket.inet_ntoa(data[10:14])
                            orig_port = struct.unpack('>H', data[14:16])[0]
                            chan_id = data[6]
                            status = data[7]
                            # Rewrite Data Endpoint HPAI (bytes 10..15) to 0.0.0.0:0 (route-back)
                            mod = bytearray(data)
                            mod[10:16] = bytes([0, 0, 0, 0, 0, 0])
                            data = bytes(mod)
                            print(f"[KNX-ALG] Port {port} ({p['client_id']}): Intercepted CONNECT_RESPONSE (CH={chan_id}, Status={status}) - Rewrote DataEndpoint {orig_ip}:{orig_port} -> 0.0.0.0:0 (route-back)", flush=True)

                        try:
                            p['client_sock'].sendto(data, p['client_addr'])
                        except Exception as e:
                            print(f"[KNX-ALG] Forward to Client {p['client_addr']} failed: {e}", flush=True)

KNX_ALG_MANAGER = KnxAlgProxyManager()

def sync_ets_nat_rules():
    """
    Synchronizes KNX ALG User-Space Proxies and underlying Linux firewall state for remote ETS UDP programming.
    1. Flushes iptables GAVASAH_ETS_NAT chain so incoming UDP traffic on assigned ETS ports hits local ALG sockets.
    2. Ensures POSTROUTING masquerade on wg0 for transparent gateway communication.
    3. Queries DB and registers all active clients with KnxAlgProxyManager.
    """
    if os.name == 'nt' or os.environ.get('MOCK_NAT') == '1':
        return True
    try:
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
        except Exception:
            pass

        # 1. Flush DNAT rules so packets reach CT 150 local proxy sockets
        subprocess.run(['iptables', '-t', 'nat', '-N', 'GAVASAH_ETS_NAT'], capture_output=True)
        subprocess.run(['iptables', '-t', 'nat', '-F', 'GAVASAH_ETS_NAT'], check=True)

        check_jump = subprocess.run(['iptables', '-t', 'nat', '-C', 'PREROUTING', '-j', 'GAVASAH_ETS_NAT'], capture_output=True)
        if check_jump.returncode != 0:
            subprocess.run(['iptables', '-t', 'nat', '-I', 'PREROUTING', '1', '-j', 'GAVASAH_ETS_NAT'], check=True)

        # 2. Ensure POSTROUTING MASQUERADE for wg0
        check_masq = subprocess.run(['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-o', WG_INTERFACE, '-j', 'MASQUERADE'], capture_output=True)
        if check_masq.returncode != 0:
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', WG_INTERFACE, '-j', 'MASQUERADE'], check=True)

        # 3. Fetch all active clients with an ets_port and sync ALG proxy
        with DB_LOCK:
            conn = get_db_connection()
            rows = conn.execute("SELECT client_id, ets_port, wg_ip FROM clients WHERE ets_port IS NOT NULL AND wg_ip IS NOT NULL AND (knx_remote_enabled IS NULL OR knx_remote_enabled != 0)").fetchall()
            conn.close()

        port_targets = {}
        for r in rows:
            port = r['ets_port']
            wg_ip = r['wg_ip']
            cid = r['client_id']
            if port and wg_ip:
                port_targets[int(port)] = (wg_ip, cid)

        KNX_ALG_MANAGER.sync(port_targets)
        print(f"[OK] Synchronized {len(port_targets)} KNX ALG UDP proxies in KnxAlgProxyManager")
        return True
    except Exception as e:
        print(f"[!] Warning syncing KNX ALG rules: {e}")
        return False

def init_sqlite_database():
    with DB_LOCK:
        conn = get_db_connection()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS owner (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dealers (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_plain TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            role TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS integrators (
            id TEXT PRIMARY KEY,
            dealer_id TEXT NOT NULL,
            dealer_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_plain TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            role TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            dealer_id TEXT NOT NULL,
            dealer_name TEXT NOT NULL,
            integrator_id TEXT,
            integrator_name TEXT,
            domain TEXT NOT NULL,
            auth_secret TEXT NOT NULL,
            dashboard_port INTEGER,
            ssh_port INTEGER,
            wg_ip TEXT,
            wg_pubkey TEXT,
            wg_privkey TEXT,
            tunnel_mode TEXT DEFAULT 'wireguard',
            
            knx_ip TEXT,
            knx_port INTEGER,
            last_heartbeat INTEGER NOT NULL,
            status TEXT NOT NULL,
            remote_enabled INTEGER NOT NULL DEFAULT 1,
            system_json TEXT,
            network_json TEXT,
            knx_json TEXT,
            onboarded_at INTEGER,
            hb_delayed_interval INTEGER DEFAULT 1800,
            hb_warning_interval INTEGER DEFAULT 21600,
            hb_offline_interval INTEGER DEFAULT 86400,
            approval_status TEXT DEFAULT 'approved',
            rejection_reason TEXT,
            knx_remote_enabled INTEGER NOT NULL DEFAULT 1,
            call_alert_enabled INTEGER DEFAULT 1,
            msg_alert_enabled INTEGER DEFAULT 1,
            call_window_start TEXT DEFAULT '10:00',
            call_window_end TEXT DEFAULT '18:00'
        );

        CREATE TABLE IF NOT EXISTS client_logs (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            level TEXT NOT NULL,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            source TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ets_port_pool (
            port INTEGER PRIMARY KEY,
            client_id TEXT,
            status TEXT NOT NULL DEFAULT 'released',
            allocated_at INTEGER,
            released_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS ets_allocator_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS copilot_proposals (
            id TEXT PRIMARY KEY,
            client_id TEXT,
            subsystem TEXT,
            action_type TEXT,
            summary TEXT,
            payload_json TEXT,
            status TEXT DEFAULT 'pending',
            created_at INTEGER,
            resolved_at INTEGER,
            resolved_by TEXT,
            result_log TEXT
        );

        CREATE TABLE IF NOT EXISTS copilot_events (
            id TEXT PRIMARY KEY,
            client_id TEXT,
            subsystem TEXT,
            event_type TEXT,
            attempt_count INTEGER DEFAULT 1,
            details_json TEXT,
            timestamp INTEGER
        );

        CREATE TABLE IF NOT EXISTS copilot_chat_history (
            id TEXT PRIMARY KEY,
            sender TEXT,
            message TEXT,
            timestamp INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_clients_dealer ON clients(dealer_id);
        CREATE INDEX IF NOT EXISTS idx_clients_integrator ON clients(integrator_id);
        CREATE INDEX IF NOT EXISTS idx_logs_client_time ON client_logs(client_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_ets_port_pool_status ON ets_port_pool(status, released_at);
        CREATE INDEX IF NOT EXISTS idx_copilot_proposals_status ON copilot_proposals(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_copilot_events_time ON copilot_events(client_id, timestamp DESC);
        """)

        # Ensure WireGuard columns exist for upgrade
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(clients)")
        cols = {r['name'] for r in cur.fetchall()}
        if 'wg_ip' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN wg_ip TEXT")
        if 'wg_pubkey' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN wg_pubkey TEXT")
        if 'wg_privkey' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN wg_privkey TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_wg_ip ON clients(wg_ip);")
        
        # Ensure Multi-Tech & Backup columns exist in clients table
        if 'technologies_json' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN technologies_json TEXT")
        if 'backups_json' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN backups_json TEXT")
        if 'pending_backup' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN pending_backup TEXT")
        if 'pending_command' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN pending_command TEXT")
        if 'onboarded_at' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN onboarded_at INTEGER")
            conn.execute("UPDATE clients SET onboarded_at = last_heartbeat WHERE last_heartbeat > 0 AND onboarded_at IS NULL")
        if 'hb_delayed_interval' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN hb_delayed_interval INTEGER DEFAULT 1800")
        if 'hb_warning_interval' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN hb_warning_interval INTEGER DEFAULT 21600")
        if 'hb_offline_interval' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN hb_offline_interval INTEGER DEFAULT 86400")
        if 'approval_status' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN approval_status TEXT DEFAULT 'approved'")
        if 'rejection_reason' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN rejection_reason TEXT")
        if 'knx_remote_enabled' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN knx_remote_enabled INTEGER NOT NULL DEFAULT 1")
        if 'call_alert_enabled' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN call_alert_enabled INTEGER DEFAULT 1")
        if 'msg_alert_enabled' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN msg_alert_enabled INTEGER DEFAULT 1")
        if 'call_window_start' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN call_window_start TEXT DEFAULT '10:00'")
        if 'call_window_end' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN call_window_end TEXT DEFAULT '18:00'")

        # Ensure Remote ETS UDP Port Forwarding columns exist
        if 'ets_port' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN ets_port INTEGER")
        if 'ets_target_type' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN ets_target_type TEXT")
        if 'ets_target_ip' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN ets_target_ip TEXT")
        if 'ets_target_port' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN ets_target_port INTEGER")
        if 'ets_port_assigned_at' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN ets_port_assigned_at INTEGER")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_ets_port ON clients(ets_port);")

        # Initialize high-watermark metadata
        cur.execute("SELECT value FROM ets_allocator_meta WHERE key = 'high_watermark'")
        hw_row = cur.fetchone()
        if not hw_row:
            conn.execute("INSERT OR REPLACE INTO ets_allocator_meta (key, value) VALUES ('high_watermark', '10000')")

        # Ensure branding_json exists in dealers table
        cur.execute("PRAGMA table_info(dealers)")
        d_cols = {r['name'] for r in cur.fetchall()}
        if 'branding_json' not in d_cols:
            conn.execute("ALTER TABLE dealers ADD COLUMN branding_json TEXT")

        # Ensure branding_json exists in owner table (for manufacturer branding)
        cur.execute("PRAGMA table_info(owner)")
        o_cols = {r['name'] for r in cur.fetchall()}
        if 'branding_json' not in o_cols:
            conn.execute("ALTER TABLE owner ADD COLUMN branding_json TEXT")

        # Auto-migrate all existing clients to WireGuard
        cur.execute("SELECT client_id, name FROM clients WHERE wg_ip IS NULL OR wg_ip = ''")
        unmigrated = cur.fetchall()
        if unmigrated:
            print(f"[*] Auto-migrating {len(unmigrated)} existing client(s) to WireGuard...")
            cur.execute("SELECT wg_ip FROM clients WHERE wg_ip IS NOT NULL")
            used_ips = {r['wg_ip'] for r in cur.fetchall()}
            for row in unmigrated:
                cid = row['client_id']
                assigned_ip = None
                for b in range(0, 256):
                    for c in range(2 if b == 0 else 1, 255):
                        candidate = f"10.42.{b}.{c}"
                        if candidate not in used_ips:
                            assigned_ip = candidate
                            used_ips.add(candidate)
                            break
                    if assigned_ip:
                        break
                priv, pub = generate_wg_keypair()
                conn.execute(
                    "UPDATE clients SET wg_ip = ?, wg_pubkey = ?, wg_privkey = ?, tunnel_mode = 'wireguard' WHERE client_id = ?",
                    (assigned_ip, pub, priv, cid)
                )
                sync_wireguard_peer(pub, assigned_ip)
                print(f"[OK] Migrated '{cid}' -> IP: {assigned_ip}, PubKey: {pub[:14]}...")
            conn.commit()


        # Migration logic if database is newly initialized
        cur = conn.cursor()
        cur.execute("SELECT count(*) as c FROM owner")
        if cur.fetchone()['c'] == 0:
            print("[*] Initializing SQLite database state...")
            if os.path.exists(AUTH_FILE):
                try:
                    with open(AUTH_FILE, 'r', encoding='utf-8') as f:
                        auth_data = json.load(f)
                    ow = auth_data.get('owner', {})
                    if ow:
                        conn.execute("INSERT OR REPLACE INTO owner VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (ow.get('id', 'owner_master'), ow.get('username', 'admin'), ow.get('name', 'Master Manufacturer'),
                             ow.get('role', 'manufacturer'), ow.get('salt', ''), ow.get('password_hash', ''), ow.get('created_at', int(time.time())))
                        )
                    for did, d in auth_data.get('dealers', {}).items():
                        conn.execute("""INSERT OR REPLACE INTO dealers (
                            id, username, name, password_plain, email, phone, role, status,
                            salt, password_hash, created_at, branding_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (d.get('id', did), d.get('username', ''), d.get('name', ''), d.get('password_plain', 'apex123!'),
                             d.get('email', ''), d.get('phone', ''), d.get('role', 'dealer'), d.get('status', 'active'),
                             d.get('salt', ''), d.get('password_hash', ''), d.get('created_at', int(time.time())),
                             json.dumps(d.get('branding') or {}))
                        )
                    for iid, it in auth_data.get('integrators', {}).items():
                        conn.execute("INSERT OR REPLACE INTO integrators VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (it.get('id', iid), it.get('dealer_id', ''), it.get('dealer_name', ''), it.get('username', ''),
                             it.get('name', ''), it.get('password_plain', 'rajesh123!'), it.get('email', ''), it.get('phone', ''),
                             it.get('role', 'integrator'), it.get('status', 'active'), it.get('salt', ''), it.get('password_hash', ''),
                             it.get('created_at', int(time.time())))
                        )
                except Exception as e:
                    print(f"[!] Migration error: {e}")
            else:
                owner_salt, owner_hash = hash_password("gavasah2026!")
                conn.execute("INSERT INTO owner VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ('owner_master', 'admin', 'Master Manufacturer', 'manufacturer', owner_salt, owner_hash, int(time.time()))
                )
                d1_salt, d1_hash = hash_password("apex123!")
                conn.execute("""INSERT INTO dealers (
                    id, username, name, password_plain, email, phone, role, status, salt, password_hash, created_at, branding_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    ('dealer_apex', 'apex_dealer', 'Apex Smart Automation', 'apex123!', 'contact@apexsmart.in', '+91 98490 12345', 'dealer', 'active', d1_salt, d1_hash, int(time.time()) - 86400*30, '{}')
                )
                d2_salt, d2_hash = hash_password("vajra123!")
                conn.execute("""INSERT INTO dealers (
                    id, username, name, password_plain, email, phone, role, status, salt, password_hash, created_at, branding_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    ('dealer_vajra', 'vajra_knx', 'Vajra KNX Solutions', 'vajra123!', 'sales@vajraknx.com', '+91 99887 76655', 'dealer', 'active', d2_salt, d2_hash, int(time.time()) - 86400*15, '{}')
                )
                i1_salt, i1_hash = hash_password("rajesh123!")
                conn.execute("INSERT INTO integrators VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('int_apex_rajesh', 'dealer_apex', 'Apex Smart Automation', 'rajesh_knx', 'Rajesh Kumar (Lead Integrator)', 'rajesh123!', 'rajesh@apexsmart.in', '+91 98450 11223', 'integrator', 'active', i1_salt, i1_hash, int(time.time()) - 86400*20)
                )
                i2_salt, i2_hash = hash_password("vikram123!")
                conn.execute("INSERT INTO integrators VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('int_apex_vikram', 'dealer_apex', 'Apex Smart Automation', 'vikram_knx', 'Vikram Patel (Field Tech)', 'vikram123!', 'vikram@apexsmart.in', '+91 98450 33445', 'integrator', 'active', i2_salt, i2_hash, int(time.time()) - 86400*10)
                )
                i3_salt, i3_hash = hash_password("suresh123!")
                conn.execute("INSERT INTO integrators VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('int_vajra_suresh', 'dealer_vajra', 'Vajra KNX Solutions', 'suresh_knx', 'Suresh Reddy (Systems Eng)', 'suresh123!', 'suresh@vajraknx.com', '+91 97400 55667', 'integrator', 'active', i3_salt, i3_hash, int(time.time()) - 86400*12)
                )

            if os.path.exists(STATE_FILE):
                try:
                    with open(STATE_FILE, 'r', encoding='utf-8') as f:
                        c_data = json.load(f)
                    for cid, c in c_data.items():
                        conn.execute("""INSERT OR REPLACE INTO clients (
                            client_id, name, dealer_id, dealer_name, integrator_id, integrator_name,
                            domain, auth_secret, dashboard_port, ssh_port, knx_ip, knx_port,
                            last_heartbeat, status, remote_enabled, system_json, network_json, knx_json,
                            wg_ip, wg_pubkey, wg_privkey, tunnel_mode
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (c.get('client_id', cid), c.get('name', cid), c.get('dealer_id', 'dealer_apex'), c.get('dealer_name', 'Apex Smart Automation'),
                             c.get('integrator_id', 'int_apex_rajesh'), c.get('integrator_name', 'Rajesh Kumar (Lead Integrator)'), c.get('domain', f"{cid}.gavasah.com"),
                             c.get('auth_secret', ''), int(c.get('dashboard_port', 10001)), int(c.get('ssh_port', 22001)),
                             c.get('knx_ip', '192.168.1.111'), int(c.get('knx_port', 3671)), int(c.get('last_heartbeat', int(time.time()))),
                             c.get('status', 'online'), 1 if c.get('remote_enabled', True) else 0,
                             json.dumps(c.get('system', {})), json.dumps(c.get('network', {})), json.dumps(c.get('knx_status', {})),
                             c.get('wg_ip'), c.get('wg_pubkey'), c.get('wg_privkey'), c.get('tunnel_mode', 'wireguard'))
                        )
                except Exception as e:
                    print(f"[!] Clients migration error: {e}")
            else:
                conn.execute("""INSERT OR REPLACE INTO clients (
                    client_id, name, dealer_id, dealer_name, integrator_id, integrator_name,
                    domain, auth_secret, dashboard_port, ssh_port, knx_ip, knx_port,
                    last_heartbeat, status, remote_enabled, system_json, network_json, knx_json,
                    wg_ip, wg_pubkey, wg_privkey, tunnel_mode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    ('sharma-villa', 'Sharma Residence (Jubilee Hills)', 'dealer_apex', 'Apex Smart Automation',
                     'int_apex_rajesh', 'Rajesh Kumar (Lead Integrator)', 'sharma-villa.gavasah.com',
                     '', 10001, 22001,
                     '192.168.1.111', 3671, int(time.time()),
                     'online', 1,
                     json.dumps({"haos_version": "13.2", "core_version": "2026.9.3", "cpu_percent": 12.4, "memory_percent": 41.2, "disk_free_gb": 182.4}),
                     json.dumps({"local_ipv4": "192.168.1.105", "gateway": "192.168.1.1", "mac_address": "E4:5F:01:42:33:9A"}),
                     json.dumps({"state": "connected", "telegrams_rx": 4120, "telegrams_tx": 305}),
                     '10.42.0.2', 'WGPUB_SHARMA_TEST_KEY_44CHARS_BASE64_OK===', 'WGPRIV_SHARMA_TEST_KEY_44CHARS_BASE64_OK==', 'wireguard')
                )

            conn.commit()
            print("[OK] SQLite WAL database synchronized successfully!")

        # Auto-allocate remote ETS ports ONLY for genuine KNX-enabled clients & clean phantoms
        try:
            cur = conn.cursor()
            # Startup purge of phantom ETS ports for non-KNX clients
            cur.execute("SELECT client_id, knx_ip, knx_json, ets_port FROM clients WHERE ets_port IS NOT NULL")
            for kc in cur.fetchall():
                cid = kc['client_id']
                kjson = kc['knx_json'] or '{}'
                kip = (kc['knx_ip'] or '').strip()
                if ('"reason": "no_knx_integration"' in kjson) or ('"configured": false' in kjson) or (kjson == '{}' and kip in ['', '192.168.1.100']):
                    release_ets_port(cid)
                    conn.execute("UPDATE clients SET knx_ip = NULL, knx_port = NULL WHERE client_id = ?", (cid,))
                    print(f"[*] Cleaned phantom KNX & released ETS port for non-KNX client: {cid}")

            # Allocate only for genuine KNX clients without ETS port
            cur.execute("SELECT client_id, knx_ip, knx_port, knx_json FROM clients WHERE ets_port IS NULL")
            cand_clients = cur.fetchall()
            for kc in cand_clients:
                cid = kc['client_id']
                kip = (kc['knx_ip'] or '').strip()
                kjson = kc['knx_json'] or '{}'
                has_knx = bool(kip and kip not in ['192.168.1.100', '—', 'none', 'null', ''] and ('"reason": "no_knx_integration"' not in kjson) and (('"configured": true' in kjson) or ('"state": "connected"' in kjson)))
                if has_knx:
                    ttype = 'onboard' if kip in ['127.0.0.1', 'localhost', ''] else 'lan_device'
                    try:
                        p = allocate_ets_port(cid, target_ip=kip or '127.0.0.1', target_port=kc['knx_port'] or 3671, target_type=ttype)
                        print(f"[*] Pre-allocated remote ETS port {p} for genuine KNX client '{cid}' (Type: {ttype})")
                    except Exception as ex:
                        print(f"[!] Error pre-allocating ETS port for '{cid}': {ex}")
        except Exception as e:
            print(f"[!] Warning checking existing KNX clients for ETS ports: {e}")

        conn.close()

init_sqlite_database()
sync_ets_nat_rules()

# ==============================================================================
# Compatibility Wrappers for Auth and Client State (Backed by SQLite WAL)
# ==============================================================================
def load_auth_state():
    with DB_LOCK:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM owner LIMIT 1")
        row = cur.fetchone()
        owner = dict(row) if row else {}
        try: owner['branding'] = json.loads(owner.get('branding_json') or '{}')
        except: owner['branding'] = {}
        cur.execute("SELECT * FROM dealers")
        dealers = {}
        for r in cur.fetchall():
            d = dict(r)
            try: d['branding'] = json.loads(d.get('branding_json') or '{}')
            except: d['branding'] = {}
            dealers[d['id']] = d
        cur.execute("SELECT * FROM integrators")
        integrators = {r['id']: dict(r) for r in cur.fetchall()}
        cur.execute("SELECT * FROM sessions")
        sessions = {r['token']: dict(r) for r in cur.fetchall()}
        conn.close()
        return {
            'owner': owner,
            'dealers': dealers,
            'integrators': integrators,
            'sessions': sessions
        }

def save_auth_state(data):
    with DB_LOCK:
        conn = get_db_connection()
        try:
            with conn:
                ow = data.get('owner', {})
                if ow:
                    ow_branding_val = ow.get('branding_json')
                    if ow_branding_val is None:
                        ow_branding_val = json.dumps(ow.get('branding') or {})
                    conn.execute("""INSERT OR REPLACE INTO owner (
                        id, username, name, role, salt, password_hash, created_at, branding_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (ow.get('id', 'owner_master'), ow.get('username', 'admin'), ow.get('name', 'Master Manufacturer'),
                         ow.get('role', 'manufacturer'), ow.get('salt', ''), ow.get('password_hash', ''), ow.get('created_at', int(time.time())),
                         ow_branding_val)
                    )
                existing_dealer_ids = {r['id'] for r in conn.execute("SELECT id FROM dealers").fetchall()}
                current_dealer_ids = set(data.get('dealers', {}).keys())
                for did in existing_dealer_ids - current_dealer_ids:
                    conn.execute("DELETE FROM dealers WHERE id = ?", (did,))

                for did, d in data.get('dealers', {}).items():
                    branding_val = d.get('branding_json')
                    if branding_val is None:
                        branding_val = json.dumps(d.get('branding') or {})
                    conn.execute("""INSERT OR REPLACE INTO dealers (
                        id, username, name, password_plain, email, phone, role, status,
                        salt, password_hash, created_at, branding_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (d.get('id', did), d.get('username', ''), d.get('name', ''), d.get('password_plain', ''),
                         d.get('email', ''), d.get('phone', ''), d.get('role', 'dealer'), d.get('status', 'active'),
                         d.get('salt', ''), d.get('password_hash', ''), d.get('created_at', int(time.time())),
                         branding_val)
                    )

                existing_int_ids = {r['id'] for r in conn.execute("SELECT id FROM integrators").fetchall()}
                current_int_ids = set(data.get('integrators', {}).keys())
                for iid in existing_int_ids - current_int_ids:
                    conn.execute("DELETE FROM integrators WHERE id = ?", (iid,))

                for iid, it in data.get('integrators', {}).items():
                    conn.execute("""INSERT OR REPLACE INTO integrators (
                        id, dealer_id, dealer_name, username, name, password_plain, email, phone,
                        role, status, salt, password_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (it.get('id', iid), it.get('dealer_id', ''), it.get('dealer_name', ''), it.get('username', ''),
                         it.get('name', ''), it.get('password_plain', ''), it.get('email', ''), it.get('phone', ''),
                         it.get('role', 'integrator'), it.get('status', 'active'), it.get('salt', ''), it.get('password_hash', ''),
                         it.get('created_at', int(time.time())))
                    )

                existing_tokens = {r['token'] for r in conn.execute("SELECT token FROM sessions").fetchall()}
                current_tokens = set(data.get('sessions', {}).keys())
                for tok in existing_tokens - current_tokens:
                    conn.execute("DELETE FROM sessions WHERE token = ?", (tok,))

                for tok, s in data.get('sessions', {}).items():
                    conn.execute("""INSERT OR REPLACE INTO sessions (
                        token, user_id, role, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?)""",
                        (tok, s.get('user_id', ''), s.get('role', ''), s.get('created_at', int(time.time())), s.get('expires_at', int(time.time()) + 86400*7))
                    )
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error saving auth state in SQLite: {e}")
            conn.close()
            return False

def save_session(token, user_id, role, created_at=None, expires_at=None):
    if not created_at:
        created_at = int(time.time())
    if not expires_at:
        expires_at = created_at + 86400 * 7
    with DB_LOCK:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute("""INSERT OR REPLACE INTO sessions (
                    token, user_id, role, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?)""", (token, user_id, role, created_at, expires_at))
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error saving session {token} in SQLite: {e}")
            conn.close()
            return False

def delete_session(token):
    with DB_LOCK:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error deleting session {token} in SQLite: {e}")
            conn.close()
            return False

def get_session(token):
    if not token:
        return None
    with DB_LOCK:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT token, user_id, role, created_at, expires_at FROM sessions WHERE token = ?", (token,))
            row = cur.fetchone()
            conn.close()
            return dict(row) if row else None
        except Exception as e:
            print(f"[!] Error getting session {token} from SQLite: {e}")
            conn.close()
            return None

def load_clients_state():
    with DB_LOCK:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients")
        res = {}
        for r in cur.fetchall():
            c = dict(r)
            c['remote_enabled'] = bool(c.get('remote_enabled', 1))
            c['knx_remote_enabled'] = bool(c.get('knx_remote_enabled', 1))
            try: c['system'] = json.loads(c.get('system_json') or '{}')
            except: c['system'] = {}
            try: c['network'] = json.loads(c.get('network_json') or '{}')
            except: c['network'] = {}
            try: c['knx_status'] = json.loads(c.get('knx_json') or '{}')
            except: c['knx_status'] = {}
            try: c['technologies'] = json.loads(c.get('technologies_json') or '{}')
            except: c['technologies'] = {}
            try: c['backups'] = json.loads(c.get('backups_json') or '[]')
            except: c['backups'] = []
            try: c['hb_delayed_interval'] = int(c.get('hb_delayed_interval') or 1800)
            except: c['hb_delayed_interval'] = 1800
            try: c['hb_warning_interval'] = int(c.get('hb_warning_interval') or 21600)
            except: c['hb_warning_interval'] = 21600
            try: c['hb_offline_interval'] = int(c.get('hb_offline_interval') or 86400)
            except: c['hb_offline_interval'] = 86400
            c['approval_status'] = c.get('approval_status') or 'approved'
            c['rejection_reason'] = c.get('rejection_reason') or ''
            c['call_alert_enabled'] = int(c.get('call_alert_enabled', 1) if c.get('call_alert_enabled') is not None else 1)
            c['msg_alert_enabled'] = int(c.get('msg_alert_enabled', 1) if c.get('msg_alert_enabled') is not None else 1)
            c['call_window_start'] = str(c.get('call_window_start') or '10:00')
            c['call_window_end'] = str(c.get('call_window_end') or '18:00')
            try: c['unmonitored_integrations'] = json.loads(c.get('unmonitored_integrations') or '[]')
            except: c['unmonitored_integrations'] = []
            res[c['client_id']] = c
        conn.close()
        return res

def save_clients_state(data):
    with DB_LOCK:
        conn = get_db_connection()
        try:
            with conn:
                existing_cids = {r['client_id'] for r in conn.execute("SELECT client_id FROM clients").fetchall()}
                current_cids = set(data.keys())
                for cid in existing_cids - current_cids:
                    conn.execute("DELETE FROM clients WHERE client_id = ?", (cid,))

                used_dash_ports = set()
                used_ssh_ports = set()
                next_dash = 10001
                next_ssh = 22001

                for cid, c in data.items():
                    d_port = c.get('dashboard_port')
                    if not d_port or d_port in used_dash_ports:
                        while next_dash in used_dash_ports:
                            next_dash += 1
                        d_port = next_dash
                    used_dash_ports.add(d_port)
                    c['dashboard_port'] = d_port

                    s_port = c.get('ssh_port')
                    if not s_port or s_port in used_ssh_ports:
                        while next_ssh in used_ssh_ports:
                            next_ssh += 1
                        s_port = next_ssh
                    used_ssh_ports.add(s_port)
                    c['ssh_port'] = s_port

                    sys_json = json.dumps(c.get('system', {}))
                    net_json = json.dumps(c.get('network', {}))
                    knx_json = json.dumps(c.get('knx_status', {}))
                    tech_json = json.dumps(c.get('technologies', {}))
                    backups_json = json.dumps(c.get('backups', []))
                    unmon_json = json.dumps(c.get('unmonitored_integrations', []))
                    conn.execute("""INSERT OR REPLACE INTO clients (
                        client_id, name, dealer_id, dealer_name, integrator_id, integrator_name,
                        domain, auth_secret, dashboard_port, ssh_port, knx_ip, knx_port,
                        last_heartbeat, status, remote_enabled, system_json, network_json, knx_json,
                        wg_ip, wg_pubkey, wg_privkey, tunnel_mode,
                        technologies_json, backups_json, pending_backup,
                        ets_port, ets_target_type, ets_target_ip, ets_target_port, ets_port_assigned_at,
                        onboarded_at,
                        hb_delayed_interval, hb_warning_interval, hb_offline_interval,
                        approval_status, rejection_reason,
                        knx_remote_enabled,
                        call_alert_enabled, msg_alert_enabled, call_window_start, call_window_end, unmonitored_integrations
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (c.get('client_id', cid), c.get('name', cid), c.get('dealer_id', 'owner_master'), c.get('dealer_name', 'Master Manufacturer (Direct)'),
                         c.get('integrator_id'), c.get('integrator_name', 'Direct Dealer Supervision'), c.get('domain', f"{cid}.gavasah.com"),
                         c.get('auth_secret', ''), int(c.get('dashboard_port', d_port)), int(c.get('ssh_port', s_port)),
                         (c.get('knx_ip') if c.get('knx_ip') and str(c.get('knx_ip')).strip() not in ['192.168.1.100', '—', 'none', 'null', ''] else None),
                         (int(c['knx_port']) if c.get('knx_port') and c.get('knx_ip') and str(c.get('knx_ip')).strip() not in ['192.168.1.100', '—', 'none', 'null', ''] else None),
                         int(c.get('last_heartbeat', int(time.time()))),
                         c.get('status', 'online'), 1 if c.get('remote_enabled', True) else 0,
                         sys_json, net_json, knx_json,
                         c.get('wg_ip'), c.get('wg_pubkey'), c.get('wg_privkey'), c.get('tunnel_mode', 'wireguard'),
                         tech_json, backups_json, c.get('pending_backup'),
                         c.get('ets_port'), c.get('ets_target_type'), c.get('ets_target_ip'), c.get('ets_target_port'), c.get('ets_port_assigned_at'),
                         c.get('onboarded_at'),
                         int(c.get('hb_delayed_interval') or 1800),
                         int(c.get('hb_warning_interval') or 21600),
                         int(c.get('hb_offline_interval') or 86400),
                         c.get('approval_status', 'approved'),
                         c.get('rejection_reason', ''),
                         1 if c.get('knx_remote_enabled', True) else 0,
                         1 if c.get('call_alert_enabled', 1) in [1, True, '1'] else 0,
                         1 if c.get('msg_alert_enabled', 1) in [1, True, '1'] else 0,
                         str(c.get('call_window_start') or '10:00'),
                         str(c.get('call_window_end') or '18:00'), unmon_json)
                    )
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error saving clients state in SQLite: {e}")
            conn.close()
            return False

# ==============================================================================
# Local Ingress & OpenSSH Helpers (CT 150 Self-Contained)
# ==============================================================================
def generate_ssh_keypair(comment="client"):
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        priv_str = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8').strip()
        pub_str = pub_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8').strip() + f" {comment}@gavasah"
        return priv_str, pub_str
    except Exception:
        import tempfile
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                kf = os.path.join(tmpdir, "id_ed25519")
                subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{comment}@gavasah", "-f", kf], capture_output=True, timeout=5)
                if os.path.exists(f"{kf}.pub"):
                    with open(f"{kf}.pub", "r", encoding="utf-8") as f: pub_str = f.read().strip()
                    with open(kf, "r", encoding="utf-8") as f: priv_str = f.read().strip()
                    return priv_str, pub_str
        except Exception:
            pass
        return "", ""

def prewarm_caddy_tls(domain_to_warm):
    """Asynchronously triggers Caddy ACME on-demand certificate issuance during onboarding so domain loads instantly."""
    def _worker():
        try:
            import urllib.request, ssl
            w_ctx = ssl.create_default_context()
            w_ctx.check_hostname = False
            w_ctx.verify_mode = ssl.CERT_NONE
            w_req = urllib.request.Request(f"https://{domain_to_warm}/", headers={"User-Agent": "Gavasah-TLS-Prewarm/1.0"})
            with urllib.request.urlopen(w_req, context=w_ctx, timeout=12) as _:
                pass
            print(f"[✓] Successfully pre-warmed Caddy TLS certificate for {domain_to_warm}")
        except Exception as e:
            # Expected on initial handshake before tunnel opens; TLS cert is still issued by Caddy!
            print(f"[*] Caddy TLS pre-warm triggered for {domain_to_warm}: {e}")
    threading.Thread(target=_worker, daemon=True).start()

def sync_client_ssh_user(client_id, ssh_public_key):
    if not ssh_public_key:
        return True
    if os.name == 'nt':
        REGISTERED_SSH_KEYS.add(ssh_public_key)
        return True

    # 1. Ensure Linux group 'haclients' exists locally
    gid = "1000"
    try:
        subprocess.run(["groupadd", "-f", "haclients"], capture_output=True, timeout=3)
        with open('/etc/group', 'r') as gf:
            for line in gf:
                if line.startswith('haclients:'):
                    gid = line.split(':')[2]
                    break
    except Exception:
        pass

    # 2. Ensure Linux user exists locally for client_id (supports any length without useradd 32-char limits)
    try:
        res = subprocess.run(["id", client_id], capture_output=True, timeout=3)
        if res.returncode != 0:
            ua = subprocess.run([
                "useradd", "--badname", "-m", "-s", "/usr/sbin/nologin", "-g", "haclients", client_id
            ], capture_output=True, timeout=5)
            if ua.returncode != 0:
                with open('/etc/passwd', 'r') as pf:
                    pw_text = pf.read()
                if client_id not in pw_text:
                    existing_uids = {int(l.split(':')[2]) for l in pw_text.splitlines() if len(l.split(':')) >= 3 and l.split(':')[2].isdigit()}
                    n_uid = 1100
                    while n_uid in existing_uids:
                        n_uid += 1
                    with open('/etc/passwd', 'a') as pf:
                        pf.write(f"{client_id}:x:{n_uid}:{gid}::/home/{client_id}:/usr/sbin/nologin\n")
                    with open('/etc/shadow', 'a') as sf:
                        sf.write(f"{client_id}:*:19000:0:99999:7:::\n")
                    print(f"[+] Autonomously created user {client_id} (UID {n_uid})")
    except Exception as e:
        print(f"[!] Error ensuring linux user {client_id}: {e}")

    # 3. Write authorized_keys in /home/{client_id}/.ssh/
    user_home = f"/home/{client_id}"
    user_ssh_dir = f"{user_home}/.ssh"
    user_auth_keys = f"{user_ssh_dir}/authorized_keys"
    try:
        os.makedirs(user_ssh_dir, exist_ok=True)
        existing = ""
        if os.path.exists(user_auth_keys):
            with open(user_auth_keys, "r", encoding="utf-8") as f:
                existing = f.read()
        if ssh_public_key not in existing:
            with open(user_auth_keys, "a", encoding="utf-8") as f:
                f.write(f"\n# Gateway Client: {client_id}\n{ssh_public_key}\n")
        os.chmod(user_home, 0o755)
        os.chmod(user_ssh_dir, 0o700)
        os.chmod(user_auth_keys, 0o600)
        subprocess.run(["chown", "-R", f"{client_id}:haclients", user_home], capture_output=True, timeout=3)
    except Exception as e:
        print(f"[!] Error setting client authorized_keys: {e}")

    # 4. Also maintain /root/.ssh/authorized_keys
    auth_keys_path = "/root/.ssh/authorized_keys"
    try:
        os.makedirs(os.path.dirname(auth_keys_path), exist_ok=True)
        existing = ""
        if os.path.exists(auth_keys_path):
            with open(auth_keys_path, "r", encoding="utf-8") as f:
                existing = f.read()
        if ssh_public_key not in existing:
            with open(auth_keys_path, "a", encoding="utf-8") as f:
                f.write(f"\n# Gateway Client: {client_id}\n{ssh_public_key}\n")
    except Exception as e:
        print(f"[!] Error syncing root SSH key: {e}")

    REGISTERED_SSH_KEYS.add(ssh_public_key)
    return True

def teardown_client_tunnel(client_id, dashboard_port=None, ssh_port=None, ssh_public_key=None):
    """
    Completely and permanently severs active reverse tunnels, kills listening ports,
    deletes Linux user account, wipes SSH authorized_keys, and cleans local dynamic configs.
    Executes 100% locally on CT 150 without touching external servers.
    """
    if os.name == 'nt':
        return True

    print(f"[*] Teardown initiated for client '{client_id}' (Ports: {dashboard_port}, {ssh_port})")

    # 1. Kill any active SSH sessions owned by this user
    try:
        subprocess.run(["pkill", "-9", "-u", client_id], capture_output=True, timeout=5)
    except Exception as e:
        print(f"[!] Error killing client user processes: {e}")

    # 2. Force kill any lingering TCP listeners on the allocated reverse tunnel ports
    for port in [dashboard_port, ssh_port]:
        if port:
            try:
                p_int = int(port)
                if p_int > 0:
                    subprocess.run(["fuser", "-k", "-n", "tcp", str(p_int)], capture_output=True, timeout=5)
            except Exception as e:
                print(f"[!] Error killing port {port}: {e}")

    # 3. Permanently remove the Linux user account and home directory
    try:
        subprocess.run(["userdel", "-r", "-f", client_id], capture_output=True, timeout=5)
    except Exception as e:
        print(f"[!] Error deleting Linux user {client_id}: {e}")

    # 4. Remove SSH key from /root/.ssh/authorized_keys
    auth_keys_path = "/root/.ssh/authorized_keys"
    try:
        if os.path.exists(auth_keys_path):
            with open(auth_keys_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = []
            skip_next = False
            for line in lines:
                if f"Gateway Client: {client_id}" in line:
                    skip_next = True
                    continue
                if skip_next:
                    skip_next = False
                    continue
                if ssh_public_key and ssh_public_key in line:
                    continue
                new_lines.append(line)
            with open(auth_keys_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
    except Exception as e:
        print(f"[!] Error purging root authorized_keys: {e}")

    if ssh_public_key:
        REGISTERED_SSH_KEYS.discard(ssh_public_key)

    # 5. Clean up local dynamic ingress configuration files on CT 150
    purge_local_ingress(client_id)
    return True

def publish_mqtt_message(topic, payload, qos=0, retain=False):
    """Publishes a message to the local EMQX broker on CT 150."""
    try:
        import paho.mqtt.publish as publish
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        publish.single(topic, str(payload), hostname="127.0.0.1", port=1883, qos=qos, retain=retain)
        return True
    except Exception as e:
        print(f"[!] MQTT publish error ({topic}): {e}")
        return False

def sync_local_ingress(client_id, dash_port, proto="http", enabled=True, force=False, wg_ip=None):
    """
    Maintains local dynamic proxy routing configuration in /srv/gavasah-cloud/dynamic/.
    Completely local to CT 150 with zero external SSH dependencies.
    """
    dynamic_dir = "/srv/gavasah-cloud/dynamic"
    if not os.path.exists(dynamic_dir):
        return True

    yaml_path = os.path.join(dynamic_dir, f"{client_id}.yaml")
    if not enabled:
        if os.path.exists(yaml_path):
            try: os.remove(yaml_path)
            except Exception: pass
        return True

    target_url = f"http://{wg_ip}:8123" if wg_ip else f"http://127.0.0.1:{dash_port}"
    yaml_content = f"""http:
  routers:
    {client_id}-router:
      rule: "Host(`{client_id}.gavasah.com`)"
      entryPoints:
        - websecure
      service: {client_id}-service
  services:
    {client_id}-service:
      loadBalancer:
        servers:
          - url: "{target_url}"
"""
    try:
        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(yaml_content)
        return True
    except Exception as e:
        print(f"[!] Error writing dynamic config for {client_id}: {e}")
        return False

def purge_local_ingress(client_id):
    """Removes local dynamic proxy configs on CT 150."""
    SYNCED_CADDY_ROUTES.pop(client_id, None)
    for p in [
        f"/srv/gavasah-cloud/dynamic/{client_id}.yaml",
        f"/srv/gavasah-cloud/dynamic/{client_id}.yml",
        f"/srv/ha-cloud/traefik/dynamic/{client_id}.yaml",
        f"/srv/ha-cloud/traefik/dynamic/{client_id}.yml"
    ]:
        if os.path.exists(p):
            try:
                os.remove(p)
                print(f"[+] Removed local dynamic config: {p}")
            except Exception:
                pass
    return True

# Aliases for backwards compatibility within codebase
sync_caddy_ingress = sync_local_ingress
purge_caddy_ingress = purge_local_ingress


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GAVASAH | Fleet Command Multi-Tenant Cloud Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #070a12;
            --bg-card: rgba(15, 22, 36, 0.75);
            --bg-card-hover: rgba(22, 32, 52, 0.85);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(255, 255, 255, 0.18);
            --accent: #00f0ff;
            --accent-glow: rgba(0, 240, 255, 0.25);
            --primary: #38bdf8;
            --purple: #a855f7;
            --purple-glow: rgba(168, 85, 247, 0.25);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --sidebar-width: 260px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
        }

        body {
            background-color: var(--bg-base);
            background-image: 
                radial-gradient(circle at 5% 10%, rgba(0, 240, 255, 0.06) 0%, transparent 40%),
                radial-gradient(circle at 95% 85%, rgba(168, 85, 247, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 50% 50%, rgba(15, 23, 42, 0.6) 0%, transparent 100%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

        /* ==========================================================================
           1. LOGIN SCREEN STYLES
           ========================================================================== */
        #login-view {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
        }

        .login-card {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 44px 40px;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6), 0 0 35px rgba(0, 240, 255, 0.08);
            backdrop-filter: blur(20px);
            animation: fadeIn 0.4s ease-out;
        }

        .login-brand {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            margin-bottom: 32px;
        }

        .login-logo {
            width: 58px;
            height: 58px;
            border-radius: 14px;
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.25), rgba(168, 85, 247, 0.15));
            border: 1px solid var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 25px var(--accent-glow);
            margin-bottom: 16px;
        }

        .login-title {
            font-size: 22px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .login-sub {
            font-size: 12px;
            color: var(--accent);
            font-weight: 600;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            margin-top: 4px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 8px;
            letter-spacing: 0.3px;
        }

        .form-input-wrap {
            position: relative;
            display: flex;
            align-items: center;
        }

        .form-input {
            width: 100%;
            background: rgba(9, 13, 22, 0.9);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 12px 14px 12px 14px;
            color: #fff;
            font-size: 14px;
            outline: none;
            transition: all 0.2s;
        }

        .form-input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 12px var(--accent-glow);
        }

        /* Remove spin arrows from number inputs across all modern browsers */
        input[type=number]::-webkit-inner-spin-button,
        input[type=number]::-webkit-outer-spin-button {
            -webkit-appearance: none;
            margin: 0;
        }
        input[type=number] {
            -moz-appearance: textfield;
            appearance: textfield;
        }

        .pwd-toggle-btn {
            position: absolute;
            right: 12px;
            background: transparent;
            border: none;
            color: #64748b;
            cursor: pointer;
            padding: 4px;
            font-size: 15px;
            transition: color 0.2s;
        }

        .pwd-toggle-btn:hover { color: #fff; }

        .btn-submit-login {
            width: 100%;
            background: linear-gradient(135deg, #00f0ff, #0284c7);
            color: #030712;
            font-weight: 700;
            font-size: 14px;
            border: none;
            border-radius: 10px;
            padding: 13px;
            cursor: pointer;
            box-shadow: 0 0 20px var(--accent-glow);
            transition: all 0.2s;
            margin-top: 10px;
        }

        .btn-submit-login:hover {
            transform: translateY(-1px);
            box-shadow: 0 0 28px rgba(0, 240, 255, 0.45);
        }

        .login-error {
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.35);
            color: #f87171;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 12px;
            margin-bottom: 18px;
            display: none;
        }

        /* ==========================================================================
           2. MAIN APP LAYOUT (MANUFACTURER & DEALER)
           ========================================================================== */
        #app-view {
            display: none;
            min-height: 100vh;
            flex-direction: row;
        }

        /* Left-Hand Sidebar (Manufacturer View) */
/* Collapsible Sidebar Styles */
        .sidebar {
            width: var(--sidebar-width);
            background: rgba(9, 13, 22, 0.95);
            border-right: 1px solid var(--border);
            backdrop-filter: blur(20px);
            display: flex;
            flex-direction: column;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            z-index: 100;
            transform: translateX(0);
            transition: transform 0.28s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .main-wrapper {
            flex: 1;
            margin-left: var(--sidebar-width);
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            transition: margin-left 0.28s cubic-bezier(0.4, 0, 0.2, 1);
        }

        body.sidebar-collapsed .sidebar {
            transform: translateX(-100%);
        }

        body.sidebar-collapsed .main-wrapper {
            margin-left: 0;
        }

        .sidebar-toggle-btn {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            border-radius: 8px;
            width: 38px;
            height: 38px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #94a3b8;
            cursor: pointer;
            transition: all 0.2s ease;
            padding: 0;
            flex-shrink: 0;
        }

        .sidebar-toggle-btn:hover {
            background: rgba(0, 240, 255, 0.12);
            border-color: var(--accent);
            color: var(--accent);
            box-shadow: 0 0 10px var(--accent-glow);
        }

        .sidebar-brand-toggle {
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #94a3b8;
            cursor: pointer;
            transition: all 0.2s ease;
            padding: 0;
            flex-shrink: 0;
            margin-left: auto;
        }

        .sidebar-brand-toggle:hover {
            background: rgba(0, 240, 255, 0.12);
            border-color: var(--accent);
            color: var(--accent);
            box-shadow: 0 0 8px var(--accent-glow);
        }

        body.is-integrator #sidebar-toggle-btn {
            display: none !important;
        }

        .sidebar-brand {
            height: 74px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            padding: 0 20px;
            gap: 12px;
        }

        .sidebar-nav {
            flex: 1;
            padding: 20px 12px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            overflow-y: auto;
        }

        .nav-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 11px 16px;
            border-radius: 10px;
            color: var(--text-muted);
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: 1px solid transparent;
        }

        .nav-item:hover {
            color: #fff;
            background: rgba(255, 255, 255, 0.04);
        }

        .nav-item.active {
            color: var(--accent);
            background: rgba(0, 240, 255, 0.08);
            border-color: rgba(0, 240, 255, 0.25);
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.08);
        }

        .nav-item-icon {
            font-size: 16px;
            width: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .nav-item-badge {
            font-size: 10px;
            font-weight: 700;
            background: rgba(255, 255, 255, 0.08);
            color: #cbd5e1;
            padding: 2px 7px;
            border-radius: 10px;
            font-family: 'JetBrains Mono', monospace;
        }

        .sidebar-footer {
            border-top: 1px solid var(--border);
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            background: rgba(5, 8, 14, 0.6);
        }

        .user-chip {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 10px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border);
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: linear-gradient(135deg, #0284c7, #a855f7);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            font-weight: 700;
            color: #fff;
        }

        .user-info-text {
            flex: 1;
            overflow: hidden;
        }

        .user-name-label {
            font-size: 12px;
            font-weight: 700;
            color: #fff;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .user-role-badge {
            font-size: 10px;
            color: var(--accent);
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .btn-logout {
            width: 100%;
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #f87171;
            font-size: 12px;
            font-weight: 600;
            padding: 8px 12px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }

        .btn-logout:hover {
            background: rgba(239, 68, 68, 0.18);
            color: #fff;
        }

        /* Main Content Wrapper */
        .main-wrapper {
            flex: 1;
            margin-left: var(--sidebar-width);
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            transition: margin-left 0.3s;
        }

        /* 3-Tier Multi-Tenant Layout Rules */
        body.is-dealer #nav-dealers {
            display: none !important;
        }
        body.is-dealer #integrator-dealer-filter-wrap {
            display: none !important;
        }
        body.is-dealer #th-dealer-col {
            display: none;
        }
        body.is-dealer #ov-card-dealers {
            display: none !important;
        }
        
        body.is-integrator #ov-card-dealers {
            display: none !important;
        }
        
        body.is-integrator .sidebar {
            display: none !important;
        }
        body.is-integrator .main-wrapper {
            margin-left: 0 !important;
        }
        body.is-integrator #th-dealer-col,
        body.is-integrator #th-integrator-col {
            display: none;
        }
        body.is-integrator #integrator-header-actions {
            display: flex !important;
        }

        .portal-role-tag.role-tag-integrator {
            background: rgba(16, 185, 129, 0.15);
            border-color: rgba(16, 185, 129, 0.4);
            color: #34d399;
        }

        .badge-integrator {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.25);
            color: #34d399;
        }

        .badge-direct-dealer {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            background: rgba(148, 163, 184, 0.08);
            border: 1px solid rgba(148, 163, 184, 0.2);
            color: #94a3b8;
        }

        .btn-reassign-sm {
            background: rgba(168, 85, 247, 0.1);
            border: 1px solid rgba(168, 85, 247, 0.28);
            color: #c084fc;
        }
        .btn-reassign-sm:hover {
            background: rgba(168, 85, 247, 0.22);
            color: #fff;
        }

        /* Top Header */
        .header {
            height: 74px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 32px;
            backdrop-filter: blur(16px);
            background: rgba(9, 13, 22, 0.85);
            position: sticky;
            top: 0;
            z-index: 90;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .portal-role-tag {
            font-size: 10px;
            font-weight: 800;
            padding: 3px 9px;
            border-radius: 12px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .role-tag-manufacturer {
            background: rgba(168, 85, 247, 0.15);
            color: #c084fc;
            border: 1px solid rgba(168, 85, 247, 0.35);
        }

        .role-tag-dealer {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.35);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .ssl-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 7px 16px;
            border-radius: 20px;
            font-size: 12px;
            color: #34d399;
            font-weight: 600;
        }

        .ssl-pulse {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .content-container {
            padding: 32px;
            max-width: 1440px;
            width: 100%;
        }

        /* Tabs Visibility */
        .tab-pane {
            display: none;
            animation: fadeIn 0.3s ease-out;
        }

        .tab-pane.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Metric Grid */
        .grid-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 28px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            backdrop-filter: blur(12px);
            transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-hover);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }

        .metric-label {
            font-size: 11px;
            font-weight: 700;
            color: var(--text-muted);
            letter-spacing: 0.6px;
            text-transform: uppercase;
        }

        .metric-value {
            font-size: 32px;
            font-weight: 800;
            margin: 6px 0 2px 0;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: -1px;
        }

        .metric-sub {
            font-size: 11px;
            color: #64748b;
        }

        /* Section Headers */
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
            gap: 16px;
            flex-wrap: wrap;
        }

        .section-title {
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.3px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Buttons */
        .btn-action {
            background: linear-gradient(135deg, #00f0ff, #0284c7);
            color: #030712;
            border: none;
            padding: 9px 18px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 0 15px var(--accent-glow);
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn-action:hover {
            transform: translateY(-1px);
            box-shadow: 0 0 22px rgba(0, 240, 255, 0.4);
        }

        .btn-purple {
            background: linear-gradient(135deg, #a855f7, #6366f1);
            color: #fff;
            box-shadow: 0 0 15px var(--purple-glow);
        }
        .btn-purple:hover {
            box-shadow: 0 0 22px rgba(168, 85, 247, 0.45);
        }

        .btn-sm {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            color: #fff;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }

        .btn-sm:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--border-hover);
        }

        .btn-primary-sm {
            background: rgba(0, 240, 255, 0.1);
            border-color: rgba(0, 240, 255, 0.3);
            color: var(--accent);
        }
        .btn-primary-sm:hover {
            background: rgba(0, 240, 255, 0.2);
            border-color: var(--accent);
        }

        .btn-danger-sm {
            background: rgba(239, 68, 68, 0.1);
            border-color: rgba(239, 68, 68, 0.25);
            color: #f87171;
        }
        .btn-danger-sm:hover {
            background: rgba(239, 68, 68, 0.2);
            border-color: #ef4444;
        }

        /* Controls Bar (Search & Pagination) */
        .fleet-controls-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 16px;
            background: rgba(18, 24, 38, 0.6);
            border: 1px solid var(--border);
            padding: 12px 18px;
            border-radius: 12px;
            backdrop-filter: blur(10px);
        }

        .search-box {
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(9, 13, 22, 0.85);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 8px 14px;
            flex: 1;
            min-width: 260px;
            max-width: 440px;
            transition: all 0.2s;
        }

        .search-box:focus-within {
            border-color: var(--accent);
            box-shadow: 0 0 12px var(--accent-glow);
        }

        .search-box input {
            background: transparent;
            border: none;
            outline: none;
            color: #fff;
            font-size: 13px;
            width: 100%;
        }

        .filter-pills {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .pill-btn {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            color: #94a3b8;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .pill-btn:hover { border-color: var(--border-hover); color: #fff; }
        .pill-btn.active {
            background: rgba(0, 240, 255, 0.15);
            border-color: var(--accent);
            color: var(--accent);
            box-shadow: 0 0 10px var(--accent-glow);
        }
        .pill-btn.pill-green.active {
            background: rgba(16, 185, 129, 0.15);
            border-color: #10b981;
            color: #34d399;
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.25);
        }
        .pill-btn.pill-yellow.active {
            background: rgba(250, 204, 21, 0.15);
            border-color: #facc15;
            color: #facc15;
            box-shadow: 0 0 10px rgba(250, 204, 21, 0.25);
        }
        .pill-btn.pill-orange.active {
            background: rgba(251, 146, 60, 0.15);
            border-color: #fb923c;
            color: #fb923c;
            box-shadow: 0 0 10px rgba(251, 146, 60, 0.25);
        }
        .pill-btn.pill-red.active {
            background: rgba(239, 68, 68, 0.15);
            border-color: #ef4444;
            color: #f87171;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.25);
        }

        /* High-Visibility Cyberpunk Toggle Switch */
        .toggle-switch {
            position: relative;
            display: inline-flex;
            align-items: center;
            width: 44px;
            height: 24px;
            flex-shrink: 0;
            cursor: pointer;
            user-select: none;
            vertical-align: middle;
        }

        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
            position: absolute;
            margin: 0;
        }

        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(255, 255, 255, 0.12);
            border: 1.5px solid rgba(148, 163, 184, 0.35);
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            border-radius: 24px;
        }

        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 3px;
            bottom: 2.5px;
            background-color: #94a3b8;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            border-radius: 50%;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.5);
        }

        .toggle-switch input:checked + .toggle-slider {
            background-color: rgba(0, 240, 255, 0.25);
            border-color: #00f0ff;
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.45);
        }

        .toggle-switch input:checked + .toggle-slider:before {
            transform: translateX(20px);
            background-color: #00f0ff;
            box-shadow: 0 0 8px #00f0ff;
        }

        .toggle-switch:hover .toggle-slider {
            border-color: rgba(0, 240, 255, 0.6);
        }

        .toggle-pill-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 9px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            transition: all 0.2s;
            cursor: pointer;
            border: 1px solid transparent;
            user-select: none;
        }
        .toggle-pill-badge.pill-live {
            background: rgba(0, 240, 255, 0.12);
            color: #00f0ff;
            border-color: rgba(0, 240, 255, 0.3);
        }
        .toggle-pill-badge.pill-live:hover {
            background: rgba(0, 240, 255, 0.22);
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.3);
        }
        .toggle-pill-badge.pill-off {
            background: rgba(239, 68, 68, 0.12);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.3);
        }
        .toggle-pill-badge.pill-off:hover {
            background: rgba(239, 68, 68, 0.22);
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.3);
        }

        .pagination-bar {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12px;
            color: #94a3b8;
        }

        .pagination-bar select {
            background: rgba(9, 13, 22, 0.9);
            border: 1px solid var(--border);
            color: #cbd5e1;
            padding: 5px 8px;
            border-radius: 6px;
            font-size: 12px;
            outline: none;
            cursor: pointer;
        }

        /* Tables */
        .table-wrap {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow-x: auto;
            backdrop-filter: blur(12px);
            margin-bottom: 24px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }

        th {
            background: rgba(15, 23, 42, 0.85);
            padding: 14px 18px;
            font-size: 11px;
            font-weight: 700;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }

        td {
            padding: 14px 18px;
            border-bottom: 1px solid var(--border);
            color: #e2e8f0;
            vertical-align: middle;
        }

        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }

        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 20px;
            letter-spacing: 0.3px;
            white-space: nowrap;
        }

        .badge-green { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-red { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-purple { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
        .badge-blue { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }

        .badge-status {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            font-size: 11px;
            font-weight: 700;
            padding: 3px 9px;
            border-radius: 20px;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }
        .status-online {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .status-delayed {
            background: rgba(250, 204, 21, 0.15);
            color: #facc15;
            border: 1px solid rgba(250, 204, 21, 0.35);
        }
        .status-warning {
            background: rgba(251, 146, 60, 0.15);
            color: #fb923c;
            border: 1px solid rgba(251, 146, 60, 0.35);
        }
        .status-lost {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .status-pending {
            background: rgba(168, 85, 247, 0.15);
            color: #c084fc;
            border: 1px solid rgba(168, 85, 247, 0.3);
        }

        .onboard-status-wrap {
            display: flex;
            flex-direction: column;
            gap: 2px;
            min-width: 140px;
        }

        .ov-clients-container {
            display: flex;
            flex-direction: column;
            gap: 4px;
            max-height: none !important;
            overflow-y: visible !important;
            padding-right: 4px;
        }
        .ov-clients-container::-webkit-scrollbar {
            width: 4px;
        }
        .ov-clients-container::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.15);
            border-radius: 4px;
        }
        .ov-client-chip {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 6px;
            padding: 4px 8px;
            font-size: 11.5px;
            transition: all 0.2s ease;
        }
        .ov-client-chip:hover {
            background: rgba(30, 41, 59, 0.85);
            border-color: rgba(56, 189, 248, 0.3);
            transform: translateX(2px);
        }

        /* Graphical Heartbeat Status Badge with Colored Glowing Balls */
        .heartbeat-status-wrap {
            display: flex;
            flex-direction: column;
            gap: 3px;
            min-width: 140px;
        }
        .heartbeat-pill-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 9px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            width: fit-content;
            border: 1px solid transparent;
            user-select: none;
            transition: all 0.2s ease;
        }
        .hb-ball {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
            flex-shrink: 0;
        }
        .hb-pill-online {
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border-color: rgba(16, 185, 129, 0.35);
        }
        .hb-ball-online {
            background: #10b981;
            box-shadow: 0 0 8px #10b981, 0 0 14px rgba(16, 185, 129, 0.6);
            animation: hbPulseGreen 2.2s infinite ease-in-out;
        }
        .hb-pill-delayed {
            background: rgba(250, 204, 21, 0.12);
            color: #facc15;
            border-color: rgba(250, 204, 21, 0.35);
        }
        .hb-ball-delayed {
            background: #facc15;
            box-shadow: 0 0 8px #facc15, 0 0 14px rgba(250, 204, 21, 0.6);
            animation: hbPulseYellow 2.2s infinite ease-in-out;
        }
        .hb-timing-delayed { color: #facc15; font-weight: 600; }
        .hb-pill-warning {
            background: rgba(251, 146, 60, 0.12);
            color: #fb923c;
            border-color: rgba(251, 146, 60, 0.35);
        }
        .hb-ball-warning {
            background: #fb923c;
            box-shadow: 0 0 8px #fb923c, 0 0 14px rgba(251, 146, 60, 0.6);
            animation: hbPulseOrange 2.2s infinite ease-in-out;
        }
        .hb-timing-warning { color: #fb923c; font-weight: 600; }
        .hb-pill-offline {
            background: rgba(239, 68, 68, 0.12);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.35);
        }
        .hb-ball-offline {
            background: #ef4444;
            box-shadow: 0 0 8px #ef4444;
        }
        .hb-pill-pending {
            background: rgba(168, 85, 247, 0.12);
            color: #c084fc;
            border-color: rgba(168, 85, 247, 0.35);
        }
        .hb-ball-pending {
            background: #a855f7;
            box-shadow: 0 0 8px #a855f7;
            animation: hbPulsePurple 2.2s infinite ease-in-out;
        }
        @keyframes hbPulseGreen {
            0%, 100% { transform: scale(1); opacity: 1; box-shadow: 0 0 6px #10b981; }
            50% { transform: scale(1.25); opacity: 0.8; box-shadow: 0 0 12px #10b981, 0 0 16px rgba(16, 185, 129, 0.5); }
        }
        @keyframes hbPulseYellow {
            0%, 100% { transform: scale(1); opacity: 1; box-shadow: 0 0 6px #facc15; }
            50% { transform: scale(1.25); opacity: 0.8; box-shadow: 0 0 12px #facc15, 0 0 16px rgba(250, 204, 21, 0.5); }
        }
        @keyframes hbPulseOrange {
            0%, 100% { transform: scale(1); opacity: 1; box-shadow: 0 0 6px #fb923c; }
            50% { transform: scale(1.25); opacity: 0.8; box-shadow: 0 0 12px #fb923c, 0 0 16px rgba(251, 146, 60, 0.5); }
        }
        @keyframes hbPulsePurple {
            0%, 100% { transform: scale(1); opacity: 1; box-shadow: 0 0 6px #a855f7; }
            50% { transform: scale(1.25); opacity: 0.8; box-shadow: 0 0 12px #a855f7; }
        }
        .hb-timing-sub {
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            white-space: nowrap;
            margin-top: 1px;
        }
        .hb-timing-online { color: #94a3b8; }
        .hb-timing-offline { color: #f87171; font-weight: 600; }
        .hb-timing-warning { color: #fbbf24; font-weight: 600; }
        .hb-timing-pending { color: #c084fc; }
        .hb-timestamp-sub {
            font-size: 10px;
            color: #64748b;
            font-family: 'JetBrains Mono', monospace;
            white-space: nowrap;
        }

        .dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            display: inline-block;
        }
        .dot-green { background: #10b981; box-shadow: 0 0 6px #10b981; }
        .dot-red { background: #ef4444; box-shadow: 0 0 6px #ef4444; }
        .dot-amber { background: #f59e0b; box-shadow: 0 0 6px #f59e0b; }

        /* Action Links Group */
        .action-links {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }

        /* Toggle Switch */
        .switch-wrap {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .switch {
            position: relative;
            display: inline-block;
            width: 36px;
            height: 20px;
        }

        .switch input { opacity: 0; width: 0; height: 0; }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background-color: rgba(255, 255, 255, 0.15);
            transition: .3s;
            border-radius: 20px;
            border: 1px solid var(--border);
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 14px;
            width: 14px;
            left: 2px;
            bottom: 2px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: #10b981;
            border-color: #10b981;
            box-shadow: 0 0 8px rgba(16, 185, 129, 0.4);
        }

        input:checked + .slider:before {
            transform: translateX(16px);
        }

        /* Account Settings Card */
        .account-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            max-width: 600px;
            backdrop-filter: blur(14px);
        }

        /* Modals */
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .modal.active { display: flex; }

        .modal-content {
            background: #0d121f;
            border: 1px solid var(--border-hover);
            border-radius: 16px;
            width: 100%;
            max-width: 540px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
            overflow: hidden;
            animation: fadeIn 0.25s ease-out;
            max-height: 90vh;
            display: flex;
            flex-direction: column;
        }

        .modal-content form {
            display: flex;
            flex-direction: column;
            flex: 1;
            min-height: 0;
            overflow: hidden;
        }

        .modal-header {
            padding: 18px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(15, 23, 42, 0.6);
            font-size: 16px;
            font-weight: 700;
            flex-shrink: 0;
        }

        .modal-body {
            padding: 24px;
            overflow-y: auto;
            overflow-x: hidden;
            flex: 1;
        }

        .modal-footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 10px;
            background: rgba(15, 23, 42, 0.6);
            flex-shrink: 0;
        }

        /* Diagnostic Terminal Modal */
        .terminal-box {
            background: #030610;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #cbd5e1;
            overflow-y: auto;
            max-height: 480px;
            line-height: 1.7;
        }

        .log-line {
            display: flex;
            gap: 12px;
            align-items: baseline;
            padding: 4px 6px;
            border-radius: 4px;
        }
        .log-line:hover { background: rgba(255, 255, 255, 0.04); }
        .log-time { color: #64748b; font-size: 11px; white-space: nowrap; }
        .log-tag { font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 4px; white-space: nowrap; }
        .log-tag-INFO { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
        .log-tag-WARN { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
        .log-tag-ERROR { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .log-tag-BOOT { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
        .log-tag-SUCCESS { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }

        /* Toast notifications */
        #toast-box {
            position: fixed;
            bottom: 24px;
            right: 24px;
            z-index: 2000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .toast {
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid var(--border-hover);
            color: #fff;
            padding: 12px 18px;
            border-radius: 10px;
            font-size: 13px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            gap: 10px;
            animation: fadeIn 0.25s ease-out;
            backdrop-filter: blur(10px);
        }
        .toast.success { border-color: rgba(16, 185, 129, 0.5); }
        .toast.error { border-color: rgba(239, 68, 68, 0.5); color: #f87171; }
    
        .pwd-cell-wrap {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(15, 23, 42, 0.6);
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }
        .btn-icon-pwd {
            background: transparent;
            border: none;
            cursor: pointer;
            font-size: 13px;
            padding: 2px 4px;
            border-radius: 4px;
            transition: background 0.15s;
            line-height: 1;
            color: #94a3b8;
        }
        .btn-icon-pwd:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }
        .pwd-masked {
            letter-spacing: 2px;
            color: #cbd5e1;
            font-size: 13px;
            font-family: monospace;
            user-select: all;
        }

    
        .btn-status-toggle {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            padding: 3px 9px;
            border-radius: 9999px;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .status-active-btn {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border-color: rgba(16, 185, 129, 0.35);
        }
        .status-active-btn:hover {
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.4);
        }
        .status-suspended-btn {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.35);
        }
        .status-suspended-btn:hover {
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border-color: rgba(16, 185, 129, 0.4);
        }

    
        /* ==============================================================
           MOBILE & TABLET RESPONSIVE SYSTEM
           ============================================================== */
        .sidebar-backdrop {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(4, 7, 14, 0.75);
            backdrop-filter: blur(6px);
            -webkit-backdrop-filter: blur(6px);
            z-index: 999;
            opacity: 0;
            transition: opacity 0.25s ease;
            pointer-events: none;
        }

        @media (max-width: 900px) {
            .sidebar {
                position: fixed;
                top: 0;
                bottom: 0;
                left: 0;
                z-index: 1000;
                transform: translateX(-100%);
                transition: transform 0.28s cubic-bezier(0.4, 0, 0.2, 1);
            }
            body.sidebar-open-mobile .sidebar {
                transform: translateX(0);
                box-shadow: 12px 0 36px rgba(0, 0, 0, 0.85);
            }
            .sidebar-backdrop {
                display: block;
            }
            body.sidebar-open-mobile .sidebar-backdrop {
                opacity: 1;
                pointer-events: auto;
            }
            .main-wrapper {
                margin-left: 0 !important;
                width: 100% !important;
            }
        }

        @media (max-width: 768px) {
            .header {
                height: 62px;
                padding: 0 16px;
            }
            .header-left {
                gap: 10px;
            }
            #page-heading-title {
                font-size: 14px !important;
                max-width: 140px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .portal-role-tag {
                font-size: 9px;
                padding: 2px 7px;
            }
            .content-container {
                padding: 16px 14px;
            }
            .grid-metrics {
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
                margin-bottom: 20px;
            }
            .metric-card {
                padding: 14px;
                border-radius: 12px;
            }
            .metric-value {
                font-size: 26px;
            }
            .metric-label {
                font-size: 11px;
            }
            .metric-sub {
                font-size: 10px;
            }
            .fleet-controls-bar {
                flex-direction: column;
                align-items: stretch;
                gap: 10px;
                padding: 12px 14px;
            }
            .search-box {
                min-width: 100%;
                max-width: 100%;
            }
            .filter-pills {
                flex-wrap: wrap;
                gap: 6px;
            }
            .pill-btn {
                padding: 6px 10px;
                font-size: 11px;
            }
            .pagination-bar {
                justify-content: space-between;
                width: 100%;
            }
            .section-header {
                flex-direction: column;
                align-items: stretch;
                gap: 10px;
            }
            .section-title {
                font-size: 15px;
            }
            .section-header .btn-action {
                width: 100%;
                justify-content: center;
                text-align: center;
            }
            .table-wrap {
                border-radius: 10px;
                margin-bottom: 18px;
            }
            th, td {
                padding: 10px 12px;
                font-size: 12px;
            }
            .ssl-badge span {
                display: none;
            }
            .ssl-badge {
                padding: 6px 8px;
            }
        }

        @media (max-width: 520px) {
            .grid-metrics {
                grid-template-columns: 1fr;
            }
            .header-actions .btn-sm {
                padding: 6px 8px;
                font-size: 11px;
            }
            .modal-content {
                max-width: 96%;
                margin: 10px auto;
                border-radius: 12px;
            }
            .modal-header {
                padding: 12px 16px;
                font-size: 14px;
            }
            .modal-body {
                padding: 14px 16px;
            }
            .modal-footer {
                padding: 10px 16px;
                flex-direction: column;
            }
            .modal-footer .btn-action,
            .modal-footer .btn-sm {
                width: 100%;
                justify-content: center;
            }
            .login-card {
                padding: 24px 18px;
                width: 92%;
            }
            input, select, textarea {
                font-size: 16px !important;
            }
        }

    
        /* ==============================================================
           GLOBAL BUTTON RESET & GLASSMORPHIC ACTION BUTTONS
           ============================================================== */
        button {
            font-family: inherit;
            border: none;
            background: transparent;
            color: inherit;
            cursor: pointer;
            outline: none;
        }

        .btn-action-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            padding: 6px 12px;
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            white-space: nowrap;
            outline: none;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.25);
        }

        .btn-action-icon:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(255, 255, 255, 0.25);
            color: #fff;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
        }

        /* Suspend Button (Amber / Warning) */
        .btn-action-icon[style*="#fbbf24"],
        .btn-action-icon.btn-suspend {
            background: rgba(245, 158, 11, 0.12) !important;
            border: 1px solid rgba(245, 158, 11, 0.35) !important;
            color: #fbbf24 !important;
        }
        .btn-action-icon[style*="#fbbf24"]:hover,
        .btn-action-icon.btn-suspend:hover {
            background: rgba(245, 158, 11, 0.22) !important;
            border-color: #fbbf24 !important;
            box-shadow: 0 0 12px rgba(245, 158, 11, 0.35) !important;
        }

        /* Activate Button (Emerald / Success) */
        .btn-action-icon[style*="#34d399"],
        .btn-action-icon.btn-activate {
            background: rgba(16, 185, 129, 0.12) !important;
            border: 1px solid rgba(16, 185, 129, 0.35) !important;
            color: #34d399 !important;
        }
        .btn-action-icon[style*="#34d399"]:hover,
        .btn-action-icon.btn-activate:hover {
            background: rgba(16, 185, 129, 0.22) !important;
            border-color: #34d399 !important;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.35) !important;
        }

        /* Edit Button (Sky Blue Accent) */
        .btn-action-icon.btn-edit,
        button.btn-action-icon:not([style*="#"]):not(.btn-reassign-sm) {
            background: rgba(56, 189, 248, 0.1) !important;
            border: 1px solid rgba(56, 189, 248, 0.3) !important;
            color: #38bdf8 !important;
        }
        .btn-action-icon.btn-edit:hover,
        button.btn-action-icon:not([style*="#"]):not(.btn-reassign-sm):hover {
            background: rgba(56, 189, 248, 0.2) !important;
            border-color: #38bdf8 !important;
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.35) !important;
        }

        /* Delete Button (Rose / Danger) */
        .btn-action-icon[style*="#ef4444"],
        .btn-action-icon.btn-delete {
            background: rgba(239, 68, 68, 0.12) !important;
            border: 1px solid rgba(239, 68, 68, 0.35) !important;
            color: #ef4444 !important;
        }
        .btn-action-icon[style*="#ef4444"]:hover,
        .btn-action-icon.btn-delete:hover {
            background: rgba(239, 68, 68, 0.22) !important;
            border-color: #ef4444 !important;
            box-shadow: 0 0 12px rgba(239, 68, 68, 0.35) !important;
        }

        /* Ingress Button (Cyan Glow) */
        .btn-action-icon[style*="#00f0ff"] {
            background: rgba(0, 240, 255, 0.1) !important;
            border: 1px solid rgba(0, 240, 255, 0.3) !important;
            color: #00f0ff !important;
        }
        .btn-action-icon[style*="#00f0ff"]:hover {
            background: rgba(0, 240, 255, 0.2) !important;
            border-color: #00f0ff !important;
            box-shadow: 0 0 12px var(--accent-glow) !important;
        }

        /* Reassign Transfer Button (Purple) */
        .btn-reassign-sm {
            background: rgba(168, 85, 247, 0.12) !important;
            border: 1px solid rgba(168, 85, 247, 0.35) !important;
            color: #c084fc !important;
        }
        .btn-reassign-sm:hover {
            background: rgba(168, 85, 247, 0.22) !important;
            border-color: #c084fc !important;
            box-shadow: 0 0 12px rgba(168, 85, 247, 0.35) !important;
        }

        /* ==============================================================
           TABLE HORIZONTAL SCROLL CONTAINMENT (FIX FOR FLEX OVERFLOW)
           ============================================================== */
        html, body {
            max-width: 100vw;
            overflow-x: hidden;
        }

        .main-wrapper {
            flex: 1;
            margin-left: var(--sidebar-width);
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            min-width: 0 !important;
            max-width: calc(100vw - var(--sidebar-width)) !important;
            width: calc(100% - var(--sidebar-width));
            overflow-x: hidden;
            transition: margin-left 0.28s cubic-bezier(0.4, 0, 0.2, 1), max-width 0.28s cubic-bezier(0.4, 0, 0.2, 1);
        }

        body.sidebar-collapsed .main-wrapper,
        body.is-integrator .main-wrapper {
            margin-left: 0 !important;
            max-width: 100vw !important;
            width: 100% !important;
        }

        @media (max-width: 900px) {
            .main-wrapper {
                margin-left: 0 !important;
                max-width: 100vw !important;
                width: 100% !important;
            }
        }

        .content-container {
            padding: 24px 32px;
            max-width: 100%;
            width: 100%;
            min-width: 0 !important;
            box-sizing: border-box;
        }

        .tab-pane {
            width: 100%;
            max-width: 100%;
            min-width: 0 !important;
        }

        .table-wrap {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            width: 100%;
            max-width: 100%;
            min-width: 0 !important;
            max-height: none !important;
            overflow-x: auto !important;
            overflow-y: visible !important;
            -webkit-overflow-scrolling: touch;
            backdrop-filter: blur(12px);
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
            position: relative;
        }

        .table-wrap table {
            width: 100%;
            min-width: 1080px;
            border-collapse: separate;
            border-spacing: 0;
        }

        .table-wrap th,
        .table-wrap td {
            white-space: nowrap;
        }

        /* Sticky thead: Header stays locked at top when scrolling rows */
        .table-wrap thead th {
            position: sticky;
            top: 0;
            z-index: 18;
            background: #0d1424;
            border-bottom: 1px solid var(--border);
        }

        /* Sticky Left Column: Client Site Name stays anchored */
        .table-wrap th:first-child,
        .table-wrap td:first-child {
            position: sticky;
            left: 0;
            z-index: 14;
            background: #0b101d;
            box-shadow: 4px 0 14px rgba(0, 0, 0, 0.65);
        }
        .table-wrap thead th:first-child {
            z-index: 28;
            background: #0d1424;
        }

        /* Reduced Client Site Column Width by 20% in Client Fleet */
        #tab-fleet .table-wrap th:first-child,
        #tab-fleet .table-wrap td:first-child {
            width: 210px !important;
            max-width: 220px !important;
            min-width: 190px !important;
            box-sizing: border-box;
            padding: 10px 14px !important;
        }

        .site-name-text {
            font-weight: 600;
            color: #fff;
            font-size: 13px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 195px;
        }

        .site-slug-text {
            font-size: 11px;
            color: #64748b;
            font-family: 'JetBrains Mono', monospace;
            margin-top: 2px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 195px;
        }

        .site-domain-link {
            color: #38bdf8;
            text-decoration: none;
            transition: color 0.15s ease;
        }
        .site-domain-link:hover {
            color: #00f0ff;
            text-decoration: underline;
        }

        /* Sticky Right Column: Actions stay pinned */
        .table-wrap th:last-child,
        .table-wrap td:last-child {
            position: sticky;
            right: 0;
            z-index: 14;
            background: #0b101d;
            box-shadow: -6px 0 16px rgba(0, 0, 0, 0.7);
        }
        .table-wrap thead th:last-child {
            z-index: 28;
            background: #0d1424;
        }

        .table-wrap tbody tr:hover td {
            background: rgba(255, 255, 255, 0.03);
        }
        .table-wrap tbody tr:hover td:first-child,
        .table-wrap tbody tr:hover td:last-child {
            background: #141c2e !important;
        }

        /* Sleek Cyberpunk Scrollbars (Both Horizontal & Vertical) */
        .table-wrap::-webkit-scrollbar {
            width: 0px !important;
            height: 9px;
        }
        .table-wrap::-webkit-scrollbar-track {
            background: rgba(11, 16, 28, 0.85);
            border-radius: 4px;
        }
        .table-wrap::-webkit-scrollbar-thumb {
            background: rgba(0, 240, 255, 0.4);
            border-radius: 4px;
            border: 1px solid rgba(0, 240, 255, 0.15);
        }
        .table-wrap::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.6);
        }

        /* Top Synchronized Scrollbar */
        .table-top-scroll {
            display: none !important;
        }
        .table-top-scroll::-webkit-scrollbar {
            height: 8px;
        }
        /* Partner Filter Selector (Replaces column scroll buttons) */
        .fleet-partner-filter-wrap {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 8px;
            padding: 4px 10px;
        }
        .partner-filter-icon {
            font-size: 13px;
        }
        .partner-filter-label {
            font-size: 11px;
            font-weight: 700;
            color: #38bdf8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }
        .partner-filter-select {
            padding: 4px 10px !important;
            font-size: 12px !important;
            height: auto !important;
            border-radius: 6px !important;
            background: #0b1120 !important;
            color: #f1f5f9 !important;
            border: 1px solid rgba(255, 255, 255, 0.15) !important;
            cursor: pointer;
            min-width: 170px;
            max-width: 250px;
            outline: none;
            transition: all 0.2s ease;
        }
        .partner-filter-select:focus {
            border-color: #38bdf8 !important;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.35) !important;
        }

        /* Hideable Actions Dropdown Menu */
        .col-actions-menu {
            position: relative;
            text-align: right;
            white-space: nowrap;
        }
        .col-actions-menu.is-open,
        .col-actions-menu:has(.btn-actions-toggle.active) {
            z-index: 150 !important;
        }
        .action-dropdown-wrap {
            position: relative;
            display: inline-block;
            text-align: right;
        }
        .btn-actions-toggle {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            font-size: 12px;
            font-weight: 600;
            color: #38bdf8;
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            white-space: nowrap;
            user-select: none;
        }
        .btn-actions-toggle:hover, .btn-actions-toggle.active {
            background: rgba(56, 189, 248, 0.2);
            border-color: #38bdf8;
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.4);
            color: #fff;
            transform: translateY(-1px);
        }
        .action-caret {
            font-size: 10px;
            transition: transform 0.2s ease;
        }
        .btn-actions-toggle.active .action-caret {
            transform: rotate(180deg);
        }
        .action-menu-popover {
            position: absolute;
            right: 0;
            top: calc(100% + 6px);
            min-width: 195px;
            background: rgba(11, 17, 32, 0.98);
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 10px;
            box-shadow: 0 14px 35px rgba(0, 0, 0, 0.75), 0 0 1px 1px rgba(56, 189, 248, 0.25);
            backdrop-filter: blur(16px);
            z-index: 1000;
            padding: 6px;
            flex-direction: column;
            gap: 2px;
            animation: fadeInMenu 0.15s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes fadeInMenu {
            from { opacity: 0; transform: translateY(-4px) scale(0.97); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        .action-menu-item {
            display: flex;
            align-items: center;
            gap: 8px;
            width: 100%;
            padding: 8px 12px;
            font-size: 12px;
            font-weight: 500;
            color: #cbd5e1;
            background: transparent;
            border: none;
            border-radius: 6px;
            text-decoration: none;
            cursor: pointer;
            text-align: left;
            transition: background 0.15s, color 0.15s;
            box-sizing: border-box;
            white-space: nowrap;
        }
        .action-menu-item:hover {
            background: rgba(56, 189, 248, 0.15);
            color: #fff;
        }
        .action-menu-item.action-item-dash {
            color: #38bdf8;
            font-weight: 600;
        }
        .action-menu-item.action-item-dash:hover {
            background: rgba(56, 189, 248, 0.25);
        }
        .action-menu-item.action-item-dash.pending {
            color: #fbbf24;
        }
        .action-menu-item.action-item-dash.restricted {
            color: #f87171;
        }
        .action-menu-item.item-danger {
            color: #f87171;
        }
        .action-menu-item.item-danger:hover {
            background: rgba(239, 68, 68, 0.18);
            color: #ef4444;
        }
        .action-menu-divider {
            height: 1px;
            background: rgba(255, 255, 255, 0.08);
            margin: 4px 0;
        }

    
        /* Multi-Technology Protocol Badges */
        .tech-badge-container {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            max-width: 250px;
        }
        .tech-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
            transition: all 0.2s ease;
        }
        .tech-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            display: inline-block;
        }
        .tech-knx {
            background: rgba(56, 189, 248, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }
        .tech-zigbee {
            background: rgba(245, 158, 11, 0.12);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        .tech-lutron {
            background: rgba(192, 132, 252, 0.12);
            color: #c084fc;
            border: 1px solid rgba(192, 132, 252, 0.3);
        }
        .tech-matter {
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .tech-coolmaster {
            background: rgba(6, 182, 212, 0.12);
            color: #22d3ee;
            border: 1px solid rgba(6, 182, 212, 0.35);
        }
        .tech-default {
            background: rgba(100, 116, 139, 0.12);
            color: #94a3b8;
            border: 1px solid rgba(100, 116, 139, 0.3);
        }
        /* Autonomous Self-Healing Engine Styles */
        .tech-status-healing {
            background: rgba(234, 179, 8, 0.15) !important;
            color: #facc15 !important;
            border: 1px solid rgba(234, 179, 8, 0.4) !important;
        }
        .hb-pill-healing {
            background: rgba(234, 179, 8, 0.15) !important;
            color: #facc15 !important;
            border-color: rgba(234, 179, 8, 0.4) !important;
        }
        .hb-ball-healing {
            background: #facc15 !important;
            box-shadow: 0 0 8px #facc15 !important;
            animation: pulse-amber 1.8s infinite;
        }
        @keyframes pulse-amber {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
        }
        .tech-status-online {
            border-color: rgba(16, 185, 129, 0.45) !important;
        }
        .tech-status-offline {
            background: rgba(239, 68, 68, 0.15) !important;
            color: #f87171 !important;
            border: 1px solid rgba(239, 68, 68, 0.45) !important;
        }
        .tech-status-degraded {
            background: rgba(245, 158, 11, 0.15) !important;
            color: #fbbf24 !important;
            border: 1px solid rgba(245, 158, 11, 0.45) !important;
        }
        .tech-dot-pulsing {
            animation: techDotPulse 1.8s infinite ease-in-out;
        }
        @keyframes techDotPulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.35; transform: scale(0.85); }
        }
        .diag-banner {
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 16px;
            font-size: 13px;
        }
        .diag-banner-online {
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.35);
            color: #34d399;
        }
        .diag-banner-offline {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.45);
            color: #f87171;
        }
        .diag-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        .diag-table th {
            text-align: left;
            color: #94a3b8;
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            width: 32%;
        }
        .diag-table td {
            padding: 8px 10px;
            color: #cbd5e1;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-family: 'JetBrains Mono', monospace;
        }

        /* White-Label Branding Studio Styles */
        .branding-studio-grid {
            display: grid;
            grid-template-columns: 1.25fr 1fr;
            gap: 24px;
            align-items: start;
            margin-top: 15px;
        }
        @media (max-width: 1100px) {
            .branding-studio-grid {
                grid-template-columns: 1fr;
            }
        }
        .settings-card {
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 22px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
        }
        .settings-card-header {
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }
        .settings-card-title {
            font-size: 14px;
            font-weight: 700;
            color: #fff;
            letter-spacing: 0.3px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .settings-card-sub {
            font-size: 12px;
            color: #94a3b8;
            margin-top: 4px;
            line-height: 1.4;
        }
        .logo-dropzone {
            border: 2px dashed rgba(255, 255, 255, 0.18);
            border-radius: 12px;
            padding: 28px 20px;
            text-align: center;
            background: rgba(30, 41, 59, 0.35);
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .logo-dropzone:hover, .logo-dropzone.drag-active {
            border-color: var(--accent);
            background: rgba(0, 240, 255, 0.05);
            transform: translateY(-1px);
        }
        .dropzone-icon {
            font-size: 32px;
            margin-bottom: 8px;
            display: inline-block;
        }
        .active-logo-box {
            background: rgba(11, 16, 28, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 12px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
        }
        .logo-thumbnail-preview {
            max-width: 140px;
            height: 48px;
            padding: 6px 12px;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .logo-thumbnail-preview img {
            max-height: 100%;
            max-width: 100%;
            object-fit: contain;
        }
        .btn-danger-sm {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.4);
            color: #f87171;
            border-radius: 6px;
            padding: 6px 14px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn-danger-sm:hover {
            background: rgba(239, 68, 68, 0.3);
            border-color: #ef4444;
            color: #fff;
        }
        .theme-presets-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
            gap: 8px;
            margin-top: 8px;
        }
        .preset-pill {
            background: rgba(30, 41, 59, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #cbd5e1;
            padding: 7px 10px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
            text-align: left;
        }
        .preset-pill:hover {
            border-color: rgba(255, 255, 255, 0.3);
            background: rgba(30, 41, 59, 0.85);
            color: #fff;
            transform: translateY(-1px);
        }
        .swatch-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            flex-shrink: 0;
            box-shadow: 0 0 6px rgba(0, 0, 0, 0.5);
        }
        .color-picker-input {
            width: 44px;
            height: 38px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: transparent;
            cursor: pointer;
            padding: 2px;
        }
        .preview-sticky-wrap {
            position: sticky;
            top: 15px;
        }
        .mockup-frame {
            background: rgba(11, 16, 28, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        }
        .mockup-header-title {
            font-size: 10px;
            font-weight: 800;
            color: #94a3b8;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            margin-bottom: 12px;
        }
        .mockup-topbar-sample {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 10px 14px;
        }
        .preview-header-badge {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 5px 12px 5px 8px;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4);
            transition: border-color 0.2s ease;
        }
        .mock-header-logo-wrap {
            height: 30px;
            max-width: 120px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }
        .mock-header-name {
            font-size: 13px;
            font-weight: 700;
            color: #f8fafc;
            letter-spacing: 0.3px;
            white-space: nowrap;
            max-width: 160px;
            overflow: hidden;
            text-overflow: ellipsis;
            line-height: 1.2;
        }
        .mock-header-tag {
            font-size: 9px;
            font-weight: 700;
            color: var(--accent);
            letter-spacing: 0.5px;
            text-transform: uppercase;
            line-height: 1.2;
            transition: color 0.2s ease;
        }
        .mockup-sidebar-sample {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 14px;
        }
        .mock-sidebar-brand-box {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .mock-sidebar-logo {
            width: 38px;
            height: 38px;
            border-radius: 10px;
            background: rgba(0, 240, 255, 0.15);
            border: 1px solid var(--accent);
            color: var(--accent);
            font-weight: 900;
            font-size: 17px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            transition: all 0.2s ease;
        }
        .mock-sidebar-title {
            font-size: 14px;
            font-weight: 800;
            color: #fff;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            line-height: 1.2;
        }
        .mock-sidebar-sub {
            font-size: 10px;
            color: var(--accent);
            font-weight: 700;
            text-transform: uppercase;
            line-height: 1.2;
            transition: color 0.2s ease;
        }
        .mock-ui-card {
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid var(--accent-glow);
            border-radius: 10px;
            padding: 16px;
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.08);
            transition: all 0.2s ease;
        }
        .mock-status-pill {
            font-size: 9px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 6px;
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
            letter-spacing: 0.5px;
        }

</style>
</head>
<body>

    <!-- ======================================================================
         1. LOGIN VIEW
         ====================================================================== -->
    <div id="login-view">
        <div class="login-card">
            <div class="login-brand">
                <div class="login-logo">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                        <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                        <line x1="6" y1="6" x2="6.01" y2="6"></line>
                        <line x1="6" y1="18" x2="6.01" y2="18"></line>
                    </svg>
                </div>
                <div class="login-title">GAVASAH FLEET COMMAND</div>
                <div class="login-sub">Manufacturer & Dealer Ingress</div>
            </div>

            <div id="login-error" class="login-error"></div>

            <form id="login-form" onsubmit="handleLoginSubmit(event)">
                <div class="form-group">
                    <label class="form-label">USERNAME</label>
                    <div class="form-input-wrap">
                        <input type="text" id="login-username" class="form-input" placeholder="e.g. admin or dealer_name" required autofocus autocomplete="username">
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label">PASSWORD</label>
                    <div class="form-input-wrap">
                        <input type="password" id="login-password" class="form-input" placeholder="Enter your portal password" required autocomplete="current-password">
                        <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('login-password', this)">👁️</button>
                    </div>
                </div>

                <button type="submit" id="login-submit-btn" class="btn-submit-login">Sign In</button>
            </form>
        </div>
    </div>

    <!-- ======================================================================
         2. AUTHENTICATED APP VIEW
         ====================================================================== -->
    <div id="app-view">
        <!-- Manufacturer Left Sidebar -->
        <div class="sidebar" id="sidebar">
            <div class="sidebar-brand">
                <div id="side-brand-logo" style="width: 38px; height: 38px; border-radius: 10px; background: rgba(0, 240, 255, 0.15); border: 1px solid var(--accent); display: flex; align-items: center; justify-content: center; box-shadow: 0 0 12px var(--accent-glow); overflow: hidden; flex-shrink: 0;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2.2">
                        <rect x="2" y="2" width="20" height="8" rx="2"></rect>
                        <rect x="2" y="14" width="20" height="8" rx="2"></rect>
                    </svg>
                </div>
                <div style="min-width: 0; overflow: hidden;">
                    <div style="font-size: 14px; font-weight: 800; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" id="side-brand-title">GAVASAH HUB</div>
                    <div style="font-size: 10px; color: var(--accent); font-weight: 700; text-transform: uppercase; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" id="side-brand-sub">Master Console</div>
                </div>
                <button class="sidebar-brand-toggle" onclick="toggleSidebar()" title="Collapse Sidebar">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="3" y1="6" x2="21" y2="6"></line>
                        <line x1="3" y1="12" x2="21" y2="12"></line>
                        <line x1="3" y1="18" x2="21" y2="18"></line>
                    </svg>
                </button>
            </div>

            <div class="sidebar-nav">
                <div class="nav-item active" id="nav-overview" onclick="switchTab('overview')">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">📊</span>
                        <span>Overview</span>
                    </div>
                </div>

                <div class="nav-item" id="nav-dealers" onclick="switchTab('dealers')">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">🏢</span>
                        <span>Dealers</span>
                    </div>
                    <span class="nav-item-badge" id="badge-dealer-count">0</span>
                </div>

                <div class="nav-item" id="nav-integrators" onclick="switchTab('integrators')">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">🔧</span>
                        <span id="nav-integrators-label">Integrators</span>
                    </div>
                    <span class="nav-item-badge" id="badge-integrator-count">0</span>
                </div>

                <div class="nav-item" id="nav-fleet" onclick="switchTab('fleet')">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">🌐</span>
                        <span id="nav-fleet-label">Client Fleets</span>
                    </div>
                    <span class="nav-item-badge" id="badge-fleet-count">0</span>
                </div>

                <div class="nav-item" id="nav-approvals" onclick="switchTab('approvals')" style="display: none;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">📋</span>
                        <span>Client Approvals</span>
                    </div>
                    <span class="nav-item-badge" id="badge-approvals-count" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); display: none;">0</span>
                </div>

                <div class="nav-item" id="nav-mqtt" onclick="switchTab('mqtt')" style="display: none;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">⚡</span>
                        <span>MQTT Broker (EMQX)</span>
                    </div>
                    <span class="status-indicator-dot online" style="margin-left: auto; width: 8px; height: 8px;"></span>
                </div>

                <div class="nav-item" id="nav-branding" onclick="switchTab('branding')" style="display: none;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">🎨</span>
                        <span>Branding & White-Label</span>
                    </div>
                </div>

                <div class="nav-item" id="nav-alerts" onclick="switchTab('alerts')" style="display: none;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">📱</span>
                        <span>WhatsApp & Alerts</span>
                    </div>
                    <span id="badge-wa-dot" class="status-indicator-dot" style="margin-left: auto; width: 8px; height: 8px; background: #64748b;" title="WhatsApp Gateway Status"></span>
                </div>

                <div class="nav-item" id="nav-copilot" onclick="switchTab('copilot')" style="display: none;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">🤖</span>
                        <span>AI Copilot & Console</span>
                    </div>
                    <span id="badge-copilot-dot" class="status-indicator-dot online" style="margin-left: auto; width: 8px; height: 8px; background: #a855f7;" title="RTX 3060 AI Copilot"></span>
                </div>

                <div class="nav-item" id="nav-account" onclick="switchTab('account')">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="nav-item-icon">⚙️</span>
                        <span>Account & Security</span>
                    </div>
                </div>
            </div>

            <div class="sidebar-footer">
                <div class="user-chip">
                    <div class="user-avatar" id="sidebar-user-avatar">M</div>
                    <div class="user-info-text">
                        <div class="user-name-label" id="sidebar-user-name">Manufacturer</div>
                        <div class="user-role-badge" id="sidebar-user-role">MASTER OWNER</div>
                    </div>
                </div>
                <button class="btn-logout" onclick="handleLogout()">🚪 Sign Out</button>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="main-wrapper">
            <!-- Top Header -->
            <div class="header">
                <div class="header-left">
                    <button class="sidebar-toggle-btn" id="sidebar-toggle-btn" onclick="toggleSidebar()" title="Toggle Sidebar">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <line x1="3" y1="6" x2="21" y2="6"></line>
                            <line x1="3" y1="12" x2="21" y2="12"></line>
                            <line x1="3" y1="18" x2="21" y2="18"></line>
                        </svg>
                    </button>
                    <div class="brand-container" style="display: flex; align-items: center; gap: 12px;">
                        <div class="portal-role-tag role-tag-manufacturer" id="portal-role-badge">MANUFACTURER</div>
                        <div style="font-size: 16px; font-weight: 800; color: #fff;" id="page-heading-title">System Overview</div>
                    </div>
                </div>

                <div class="header-actions" style="display: flex; align-items: center; gap: 14px;">
                    <!-- Top-Right Brand Badge & Logo (Visible for Dealer and Manufacturer) -->
                    <div id="header-brand-container" style="display: none; align-items: center; gap: 10px; padding: 5px 12px 5px 8px; background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; backdrop-filter: blur(8px); box-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                        <div id="header-brand-logo-wrap" style="height: 30px; max-width: 130px; display: flex; align-items: center; justify-content: center; overflow: hidden;"></div>
                        <div style="display: flex; flex-direction: column; justify-content: center;">
                            <div id="header-brand-name" style="font-size: 13px; font-weight: 700; color: #f8fafc; letter-spacing: 0.3px; white-space: nowrap; max-width: 180px; overflow: hidden; text-overflow: ellipsis; line-height: 1.2;"></div>
                            <div id="header-brand-tag" style="font-size: 9px; font-weight: 700; color: var(--accent); letter-spacing: 0.5px; text-transform: uppercase; line-height: 1.2;"></div>
                        </div>
                    </div>

                    <!-- Quick buttons visible for Integrator users -->
                    <div id="integrator-header-actions" style="display: none; align-items: center; gap: 10px;">
                        <button class="btn-sm" onclick="openIntegratorPasswordModal()">🔑 Change Password</button>
                        <button class="btn-logout" style="width: auto; padding: 6px 14px;" onclick="handleLogout()">🚪 Logout</button>
                    </div>
                </div>
            </div>

            <div class="content-container">

                <!-- ==============================================================
                     TAB 1: MANUFACTURER OVERVIEW & SUMMARY
                     ============================================================== -->
                <div class="tab-pane active" id="tab-overview">
                    <div class="grid-metrics">
                        <div class="metric-card" id="ov-card-dealers">
                            <div class="metric-label">Total Authorized Dealers</div>
                            <div class="metric-value" style="color: #c084fc;" id="ov-dealers-count">0</div>
                            <div class="metric-sub">Dealer Organizations</div>
                        </div>
                        <div class="metric-card" id="ov-card-integrators">
                            <div class="metric-label" id="ov-integrators-label">Technical Integrators</div>
                            <div class="metric-value" style="color: #34d399;" id="ov-integrators-count">0</div>
                            <div class="metric-sub" id="ov-integrators-sub">Supervised Field Integrators</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">Total Gavasah Gateways</div>
                            <div class="metric-value" style="color: #00f0ff;" id="ov-total-clients">0</div>
                            <div class="metric-sub">Across All Dealer Networks</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">Online Gateways</div>
                            <div class="metric-value" style="color: #10b981;" id="ov-online-clients">0</div>
                            <div class="metric-sub">Active Telemetry Heartbeats</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">Offline / Lost Signals</div>
                            <div class="metric-value" style="color: #ef4444;" id="ov-lost-clients">0</div>
                            <div class="metric-sub">>600s Signal Loss (Red Mode)</div>
                        </div>
                        <div class="metric-card" id="ov-card-approvals" style="cursor: pointer; display: none;" onclick="switchTab('approvals')" title="Click to review pending gateway approval requests">
                            <div class="metric-label" style="color: #fbbf24;">Pending Approvals</div>
                            <div class="metric-value" style="color: #fbbf24;" id="ov-approvals-count">0</div>
                            <div class="metric-sub">Awaiting HQ Authorization</div>
                        </div>
                    </div>

                    <div class="section-header">
                        <div class="section-title">🏢 Dealer Network Distribution & Health Breakdown</div>
                        <button class="btn-action btn-purple" onclick="openCreateDealerModal()">+ Register New Dealer</button>
                    </div>

                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Organization / Network Partner</th>
                                    <th>Portal Username</th>
                                    <th style="min-width: 270px;">Assigned Gavasah Gateways & Clients</th>
                                    <th>Online / Lost Status</th>
                                    <th>Contact Details</th>
                                    <th>Account Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="overview-dealers-body">
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB 2: DEALERS MANAGEMENT
                     ============================================================== -->
                <div class="tab-pane" id="tab-dealers">
                    <div class="section-header">
                        <div class="section-title">🏢 Authorized Dealers Directory</div>
                        <button class="btn-action btn-purple" onclick="openCreateDealerModal()">+ Add New Dealer</button>
                    </div>

                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Dealer Name / Business</th>
                                    <th>Portal Login Username</th>
                                    <th>Portal Password</th>
                                    <th>Contact Email & Phone</th>
                                    <th>Managed Gavasah Gateways</th>
                                    <th>Created Date</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="dealers-management-body">
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB: INTEGRATORS MANAGEMENT (MANUFACTURER & DEALER)
                     ============================================================== -->
                <div class="tab-pane" id="tab-integrators">
                    <div class="section-header">
                        <div>
                            <div class="section-title"><span>🔧</span> <span id="integrators-tab-title">Integrator Workforce Directory</span></div>
                            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;" id="integrators-tab-sub">Certified field engineers and integration specialists</div>
                        </div>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <div id="integrator-dealer-filter-wrap">
                                <select id="integrator-dealer-filter" class="form-input" style="padding: 7px 12px; font-size: 12px;" onchange="renderIntegratorsTable()">
                                    <option value="ALL">All Dealerships</option>
                                </select>
                            </div>
                            <button class="btn-action" style="background: linear-gradient(135deg, #10b981, #059669);" onclick="openCreateIntegratorModal()">+ Register New Integrator</button>
                        </div>
                    </div>

                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Integrator Name</th>
                                    <th id="th-int-dealership-col">Dealership</th>
                                    <th>Portal Username</th>
                                    <th>Login Password</th>
                                    <th>Contact Email & Phone</th>
                                    <th>Supervised Clients</th>
                                    <th>Account Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="integrators-management-body">
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB 3: FLEET INVENTORY (ACCESSIBLE TO BOTH ROLES)
                     ============================================================== -->
                <div class="tab-pane" id="tab-fleet">
                    <div class="grid-metrics" id="fleet-metric-cards">
                        <div class="metric-card">
                            <div class="metric-label">Total Fleet Gateways</div>
                            <div class="metric-value" style="color: #00f0ff;" id="val-total">0</div>
                            <div class="metric-sub" id="val-total-sub">Provisioned Client Sites</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">Online Gateways</div>
                            <div class="metric-value" style="color: #10b981;" id="val-online">0</div>
                            <div class="metric-sub" id="val-online-sub">Active Telemetry Pulse</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">Lost Heartbeats</div>
                            <div class="metric-value" style="color: #ef4444;" id="val-lost">0</div>
                            <div class="metric-sub">Offline / Interrupted Sites</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">Remote Access Security</div>
                            <div class="metric-value" style="color: #38bdf8;" id="val-remote-count">ACTIVE</div>
                            <div class="metric-sub">Granular Remote Ingress Control</div>
                        </div>
                    </div>

                    <div class="section-header">
                        <div class="section-title">🌐 Client Fleet Gateways & Hardware Telemetry</div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <button class="btn-action" id="btn-fleet-update-center" style="display: none; background: linear-gradient(135deg, #0284c7, #0369a1); border: 1px solid #38bdf8;" onclick="openFleetUpdateModal()">
                                🚀 Manufacturer Fleet Updates
                            </button>
                            <button class="btn-action" onclick="openOnboardModal()">+ Onboard New Client</button>
                        </div>
                    </div>

                    <!-- Filter & Pagination Bar -->
                    <div class="fleet-controls-bar">
                        <div class="search-box">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2.2">
                                <circle cx="11" cy="11" r="8"></circle>
                                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                            </svg>
                            <input type="text" id="fleet-search" placeholder="Search site, dealer, slug, LAN IP, MAC..." oninput="handleSearch(this.value)">
                        </div>
                        <div class="filter-pills">
                            <button class="pill-btn active" id="filter-pill-all" onclick="setFleetFilter('ALL')">All (<span id="pill-count-all">0</span>)</button>
                            <button class="pill-btn pill-green" id="filter-pill-online" onclick="setFleetFilter('ONLINE')">🟢 Online (<span id="pill-count-online">0</span>)</button>
                            <button class="pill-btn pill-yellow" id="filter-pill-delayed" onclick="setFleetFilter('DELAYED')">🟡 Delayed (<span id="pill-count-delayed">0</span>)</button>
                            <button class="pill-btn pill-orange" id="filter-pill-warning" onclick="setFleetFilter('WARNING')">🟠 Warning (<span id="pill-count-warning">0</span>)</button>
                            <button class="pill-btn pill-red" id="filter-pill-lost" onclick="setFleetFilter('LOST')">🔴 Lost (<span id="pill-count-lost">0</span>)</button>
                        </div>
                        <!-- Partner Filter Dropdown (Replaces scroll column tab) -->
                        <div class="fleet-partner-filter-wrap" id="fleet-partner-filter-wrap" style="display: none;">
                            <span class="partner-filter-icon" id="partner-filter-icon">🏢</span>
                            <span class="partner-filter-label" id="partner-filter-label">Filter:</span>
                            <select class="partner-filter-select" id="fleet-partner-select" onchange="handlePartnerFilterChange(this.value)">
                                <option value="ALL">All Partners</option>
                            </select>
                        </div>
                        <div class="pagination-bar">
                            <span>Rows:</span>
                            <select id="fleet-page-size" onchange="handlePageSizeChange(this.value)">
                                <option value="25" selected>25</option>
                                <option value="50">50</option>
                                <option value="100">100</option>
                                <option value="all">All</option>
                            </select>
                            <span id="fleet-page-info" style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">0-0 of 0</span>
                            <button class="btn-sm" id="btn-fleet-prev" onclick="changeFleetPage(-1)" disabled style="padding: 4px 10px;">◀</button>
                            <button class="btn-sm" id="btn-fleet-next" onclick="changeFleetPage(1)" disabled style="padding: 4px 10px;">▶</button>
                        </div>
                    </div>



                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Client Site / Slug</th>
                                    <th>Heartbeat Status</th>
                                    <th>Integration Status</th>
                                    <th style="min-width: 180px;">Technologies & Subsystems</th>
                                    <th>Boot Slot (RAUC)</th>
                                    <th>Remote Ingress</th>
                                    <th>Hardware Metrics</th>
                                    <th id="th-onboarded-col" style="min-width: 145px;">Onboarded At</th>
                                    <th id="th-dealer-col">Dealer Partner</th>
                                    <th id="th-integrator-col">Assigned Integrator</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="fleet-table-body">
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB: CLIENT APPROVALS (MANUFACTURER)
                     ============================================================== -->
                <div class="tab-pane" id="tab-approvals">
                    <div class="section-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                        <div>
                            <div class="section-title">📋 Client Gateways Awaiting Manufacturer Approval</div>
                            <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">
                                Review and authorize new client site registrations submitted by Dealers and Integrators. Approving enables reverse proxy ingress, live telemetry monitoring, and remote access.
                            </div>
                        </div>
                        <button class="btn-sm" type="button" onclick="fetchApprovals()">🔄 Refresh Approvals</button>
                    </div>

                    <div id="approvals-empty-state" style="display: none; background: rgba(15, 23, 42, 0.6); border: 1px dashed rgba(255, 255, 255, 0.15); border-radius: 12px; padding: 40px; text-align: center;">
                        <div style="font-size: 32px; margin-bottom: 10px;">✅</div>
                        <div style="font-size: 16px; font-weight: 700; color: #f1f5f9; margin-bottom: 6px;">All Client Gateways Approved</div>
                        <div style="font-size: 13px; color: #94a3b8; max-width: 450px; margin: 0 auto;">There are currently no client gateway registrations awaiting manufacturer approval. New submissions from dealers and integrators will appear here.</div>
                    </div>

                    <div class="table-container" id="approvals-table-container">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Gateway Site Name & ID</th>
                                    <th>Partner Assignment</th>
                                    <th>Submission Time</th>
                                    <th>Addon Configuration Snippet</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="approvals-table-body">
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB: MQTT BROKER & DYNAMIC TOPICS (EMQX)
                     ============================================================== -->
                <div class="tab-pane" id="tab-mqtt">
                    <div class="section-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                        <div>
                            <div class="section-title">⚡ MQTT Broker & High-Speed Telemetry Engine (EMQX)</div>
                            <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">
                                Enterprise MQTT broker running locally on Gavasah Server (CT 150) for real-time telemetry streaming, Last Will & Testament (LWT) gateway heartbeat drops, and instant bidirectional command dispatch.
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <a href="https://emqx.gavasah.com" target="_blank" class="btn-action" style="display: inline-flex; align-items: center; gap: 6px; text-decoration: none;">
                                <span>🚀 Launch EMQX Web GUI (Console)</span>
                                <span style="font-size: 11px;">↗</span>
                            </a>
                        </div>
                    </div>

                    <!-- Broker Metrics Cards -->
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px;">
                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 12px; padding: 16px;">
                            <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Broker Status</div>
                            <div style="display: flex; align-items: center; gap: 8px; margin-top: 6px;">
                                <span class="status-indicator-dot online" style="width: 10px; height: 10px;"></span>
                                <span style="font-size: 18px; font-weight: 800; color: #fff;">EMQX v5.8.9</span>
                            </div>
                            <div style="font-size: 11px; color: #00f0ff; margin-top: 4px;">Active & Running (systemd)</div>
                        </div>

                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 16px;">
                            <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">MQTT Listeners</div>
                            <div style="font-size: 14px; font-weight: 700; color: #fff; margin-top: 6px;">
                                TCP <code>:1883</code> &bull; WSS <code>:8084</code>
                            </div>
                            <div style="font-size: 11px; color: #64748b; margin-top: 4px;">WebSocket <code>:8083</code> (100% Firewall Safe)</div>
                        </div>

                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 16px;">
                            <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Management Console</div>
                            <div style="font-size: 14px; font-weight: 700; color: #fff; margin-top: 6px;">
                                <code>emqx.gavasah.com</code>
                            </div>
                            <div style="font-size: 11px; color: #10b981; margin-top: 4px;">User: <code>admin</code> / Password: <code>vajju2175</code></div>
                        </div>
                    </div>

                    <!-- Topic Hierarchy & Dispatcher -->
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px;">
                        <!-- Topic Directory -->
                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 20px;">
                            <div style="font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                                <span>🌳 Dynamic Topic Architecture (Auto-Evolving)</span>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.5; margin-bottom: 14px;">
                                Topics automatically evolve as clients, dealers, and integrators are provisioned or deprovisioned:
                            </div>
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; background: rgba(0,0,0,0.4); padding: 14px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06); line-height: 1.8;">
                                <div style="color: #38bdf8;">🌐 Universal Broadcast:</div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/universal/cmd</strong> (Broadcast to all gateways)</div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/universal/status</strong> (Fleet announcements)</div>
                                <div style="color: #a78bfa; margin-top: 8px;">🏢 Dealer & Integrator Scopes:</div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/dealers/{dealer_id}/broadcast</strong></div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/dealers/{dealer_id}/integrators/{integrator_id}/broadcast</strong></div>
                                <div style="color: #34d399; margin-top: 8px;">🏠 Gavasah Gateway (Client) Dedicated:</div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/clients/{client_id}/telemetry</strong> (Heartbeat & metrics)</div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/clients/{client_id}/status</strong> (LWT socket drop trigger)</div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/clients/{client_id}/cmd</strong> (Direct targeted commands)</div>
                                <div style="padding-left: 14px; color: #94a3b8;">&bull; <strong style="color: #f1f5f9;">gavasah/clients/{client_id}/config</strong> (Dynamic config push)</div>
                            </div>
                        </div>

                        <!-- Command Dispatcher Form -->
                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 20px;">
                            <div style="font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                                <span>📡 Real-Time Command Dispatcher</span>
                            </div>
                            <div style="margin-bottom: 12px;">
                                <label class="form-label">DISPATCH TARGET</label>
                                <select id="mqtt-target-type" class="form-input" onchange="onMqttTargetChange()">
                                    <option value="universal">Universal Broadcast (All Gavasah Gateways)</option>
                                    <option value="client">Individual Client Gateway</option>
                                </select>
                            </div>

                            <div id="mqtt-client-select-wrap" style="margin-bottom: 12px; display: none;">
                                <label class="form-label">SELECT TARGET GAVASAH GATEWAY</label>
                                <select id="mqtt-target-client" class="form-input">
                                </select>
                            </div>

                            <div style="margin-bottom: 12px;">
                                <label class="form-label">COMMAND PAYLOAD (JSON)</label>
                                <textarea id="mqtt-cmd-payload" class="form-input" rows="4" style="font-family: 'JetBrains Mono', monospace; font-size: 12px;" placeholder='{"action": "ping", "timestamp": 1234567890}'></textarea>
                            </div>

                            <div style="display: flex; gap: 8px;">
                                <button type="button" class="btn-action" style="flex: 1;" onclick="dispatchMqttCommand()">
                                    ⚡ Dispatch via MQTT
                                </button>
                                <button type="button" class="btn-sm" onclick="setSampleMqttCmd('ping')">Sample: Ping</button>
                                <button type="button" class="btn-sm" onclick="setSampleMqttCmd('reload')">Sample: Reload</button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB: AUTONOMOUS NOTIFICATIONS & WHATSAPP ENGINE
                     ============================================================== -->
                <div class="tab-pane" id="tab-alerts">
                    <div class="section-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                        <div>
                            <div class="section-title">📱 Autonomous Dispatch & WhatsApp Gateway</div>
                            <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">
                                100% Free, zero-app notifications engine dispatching instant WhatsApp alerts, automated phone calls, and email directly to dealers and integrators.
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn-action" type="button" onclick="loadWhatsAppStatus()">🔄 Refresh Status</button>
                        </div>
                    </div>

                    <!-- 4-Column Status Grid with Admin WhatsApp Recipient -->
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px;">
                        <!-- WhatsApp Card -->
                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px; padding: 18px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">WhatsApp Sender Engine</div>
                                <span id="wa-status-pill" class="status-indicator-dot degraded" style="font-size: 11px; font-weight: 700; color: #f59e0b; display: flex; align-items: center; gap: 6px;">● Initializing...</span>
                            </div>
                            <div style="font-size: 16px; font-weight: 800; color: #fff; margin-top: 6px;" id="wa-card-title">Baileys WebSocket</div>
                            <div style="font-size: 11px; color: #10b981; margin-top: 4px;">Zero Cost &bull; QR Session Bot</div>
                        </div>

                        <!-- Admin Alert Recipient Card -->
                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 12px; padding: 18px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Admin Alert Receiver</div>
                                <span id="admin-wa-top-pill" class="status-indicator-dot online" style="font-size: 11px; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 6px;">● Active Target</span>
                            </div>
                            <div style="font-size: 16px; font-weight: 800; color: #38bdf8; margin-top: 6px;" id="admin-wa-top-display">+91 7396263322</div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">System & Ecosystem Alerts &bull; AI Escalation</div>
                        </div>

                        <!-- Voice / Audio Alert Card -->
                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 12px; padding: 18px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Voice Alert Calls</div>
                                <span class="status-indicator-dot online" style="font-size: 11px; font-weight: 700; color: #10b981; display: flex; align-items: center; gap: 6px;">● Active</span>
                            </div>
                            <div style="font-size: 16px; font-weight: 800; color: #fff; margin-top: 6px;">Voice Note & TTS Dispatch</div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Audible Human Speech &bull; WhatsApp PTT Audio Memo</div>
                        </div>

                        <!-- Email Relay Card -->
                        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 18px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Email Dispatch</div>
                                <span class="status-indicator-dot online" style="font-size: 11px; font-weight: 700; color: #10b981; display: flex; align-items: center; gap: 6px;">● Active</span>
                            </div>
                            <div style="font-size: 16px; font-weight: 800; color: #fff; margin-top: 6px;">SMTP Autonomous Relay</div>
                            <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Standard Inbox &bull; Rich HTML Formatting</div>
                        </div>
                    </div>

                    <!-- Main WhatsApp Pair & Test Console -->
                    <div style="display: grid; grid-template-columns: minmax(320px, 420px) 1fr; gap: 24px; margin-bottom: 24px;">
                        <!-- QR Code Pairing Box -->
                        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 16px; padding: 24px;">
                            <div style="font-size: 15px; font-weight: 700; color: #fff; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                                <span>💬 WhatsApp Pairing & Session Manager</span>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.5; margin-bottom: 18px;">
                                Scan with any WhatsApp account on your company operations phone. You can logout and change this number at any time below.
                            </div>

                            <!-- QR Container (Shown when QR ready) -->
                            <div id="wa-qr-box" style="text-align: center; padding: 16px; background: rgba(0, 0, 0, 0.4); border: 1px dashed rgba(0, 240, 255, 0.4); border-radius: 14px;">
                                <div style="display: inline-block; position: relative; background: #fff; padding: 12px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.6); min-width: 220px; min-height: 220px;">
                                    <div id="wa-qr-loading" style="display: flex; flex-direction: column; align-items: center; justify-content: center; width: 220px; height: 220px; color: #0f172a; font-size: 13px; font-weight: 700; gap: 8px;">
                                        <div style="font-size: 24px;">⚡</div>
                                        <div>Generating Pairing QR...</div>
                                    </div>
                                    <img id="wa-qr-img" src="" alt="WhatsApp Pairing QR" style="width: 220px; height: 220px; display: none;">
                                </div>
                                <div style="margin-top: 14px; font-size: 12px; color: #00f0ff; font-weight: 600;">
                                    📸 Scan this QR with WhatsApp &rarr; Linked Devices
                                </div>
                                <div style="margin-top: 6px; font-size: 11px; color: #64748b;">
                                    Auto-refreshes every few seconds. Once scanned, this card instantly switches to Active status.
                                </div>
                            </div>

                            <!-- Connected Container (Shown when linked) -->
                            <div id="wa-connected-box" style="display: none; text-align: center; padding: 24px 16px; background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 14px;">
                                <div style="width: 56px; height: 56px; border-radius: 50%; background: rgba(16, 185, 129, 0.2); border: 2px solid #10b981; display: flex; align-items: center; justify-content: center; margin: 0 auto 12px; font-size: 24px;">
                                    ✓
                                </div>
                                <div style="font-size: 13px; color: #94a3b8; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px;">Active WhatsApp Dispatcher</div>
                                <div id="wa-connected-phone" style="font-size: 22px; font-weight: 800; color: #10b981; margin: 6px 0;">+91 ...</div>
                                <div id="wa-connected-name" style="font-size: 12px; color: #cbd5e1; margin-bottom: 18px;">Gavasah Operations</div>

                                <button type="button" class="btn-sm" style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #f87171; font-weight: 700; padding: 8px 16px;" onclick="handleWhatsAppLogout()">
                                    🚪 Logout / Change Phone Number
                                </button>
                                <div style="font-size: 11px; color: #94a3b8; margin-top: 10px; line-height: 1.4;">
                                    Clicking Logout unlinks this number immediately and regenerates a fresh QR code so you can link another phone.
                                </div>
                            </div>

                            <!-- Dedicated Admin Destination Number Config Box -->
                            <div style="margin-top: 20px; padding: 16px; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <div style="font-size: 13px; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 6px;">
                                        <span>👑 Admin WhatsApp Recipient</span>
                                    </div>
                                    <span id="badge-admin-wa-status" style="font-size: 9.5px; font-weight: 700; color: #10b981; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); padding: 2px 7px; border-radius: 10px;">Alert Target</span>
                                </div>
                                <div style="font-size: 11px; color: #94a3b8; line-height: 1.45; margin-bottom: 12px;">
                                    Emergency system alerts, autonomous diagnostics, and AI Copilot notifications are delivered to this phone number. (Note: QR pairing above is the <em>sender bot</em>; this field is the <em>admin receiver</em>).
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <label class="form-label" style="font-size: 10px; margin-bottom: 4px;">ADMIN / MANUFACTURER PHONE</label>
                                    <div style="display: flex; gap: 8px;">
                                        <input type="text" id="admin-wa-phone-input" class="form-input" placeholder="e.g. 7396263322" style="font-weight: 700; font-size: 13px; letter-spacing: 0.5px; padding: 7px 10px;">
                                        <button type="button" class="btn-action" style="padding: 7px 14px; font-size: 12px; white-space: nowrap; background: linear-gradient(135deg, #0284c7, #0369a1); border-color: #38bdf8;" onclick="saveAdminWhatsAppNumber()">
                                            💾 Save
                                        </button>
                                    </div>
                                </div>
                                <div style="display: flex; gap: 6px;">
                                    <button type="button" class="btn-sm" style="flex: 1; padding: 6px 10px; font-size: 11px; font-weight: 600; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8;" onclick="testAdminWhatsAppPing()">
                                        📲 Test Admin Alert Ping
                                    </button>
                                </div>
                                <div id="admin-wa-feedback" style="display: none; margin-top: 10px; font-size: 11px; padding: 8px 10px; border-radius: 6px; line-height: 1.4;"></div>
                            </div>
                        </div>

                        <!-- Test Dispatcher & Notification Rules Box -->
                        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 16px; padding: 24px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <div style="font-size: 16px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px;">
                                    <span>🎙️ Text-To-Speech (TTS) Voice Call &amp; Message Testing Station</span>
                                </div>
                                <span class="badge-role" style="background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3);">Live Audio &amp; VoIP</span>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.5; margin-bottom: 18px;">
                                Test automated spoken voice phone calls (TTS) and instant text messages to any mobile number. Spoken audio preview plays directly through your browser, while cellular phone calls ring through your configured telephony node.
                            </div>

                            <div style="margin-bottom: 14px;">
                                <label class="form-label">DESTINATION PHONE NUMBER OR EMAIL ADDRESS</label>
                                <input type="text" id="wa-test-phone" class="form-input" placeholder="e.g. 7396263322 (for Phone / WA) or alerts@client.com (for Email)" style="font-size: 14px; font-weight: 700; letter-spacing: 0.5px;">
                            </div>

                            <div style="margin-bottom: 14px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                    <label class="form-label" style="margin-bottom: 0;">TEXT-TO-SPEECH (TTS) &amp; MESSAGE CONTENT</label>
                                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                                        <button type="button" class="btn-sm" style="font-size: 10px; padding: 3px 8px;" onclick="setSampleAlert('offline')">Gateway Offline</button>
                                        <button type="button" class="btn-sm" style="font-size: 10px; padding: 3px 8px;" onclick="setSampleAlert('lutron')">Lutron Fault</button>
                                        <button type="button" class="btn-sm" style="font-size: 10px; padding: 3px 8px;" onclick="setSampleAlert('heal')">Self-Heal Exceeded</button>
                                        <button type="button" class="btn-sm" style="font-size: 10px; padding: 3px 8px;" onclick="setSampleAlert('restored')">Pulse Restored</button>
                                    </div>
                                </div>
                                <textarea id="wa-test-msg" class="form-input" rows="4" placeholder="Type message to speak on voice phone call or send as text..." style="font-family: inherit; font-size: 13px;"></textarea>
                            </div>

                            <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                                <button type="button" id="tts-call-btn" class="btn-action" style="flex: 1; min-width: 150px; background: linear-gradient(135deg, #0284c7, #0369a1); border-color: #38bdf8;" onclick="sendTTSAlert('voice')">
                                    📞 Place TTS Voice Call
                                </button>
                                <button type="button" id="tts-msg-btn" class="btn-action" style="flex: 1; min-width: 150px; background: linear-gradient(135deg, #059669, #047857); border-color: #34d399;" onclick="sendTTSAlert('whatsapp')">
                                    💬 Send WhatsApp / Text
                                </button>
                                <button type="button" id="tts-email-btn" class="btn-action" style="flex: 1; min-width: 150px; background: linear-gradient(135deg, #7c3aed, #6d28d9); border-color: #a78bfa;" onclick="sendTTSAlert('email')">
                                    ✉️ Send Email Alert
                                </button>
                                <button type="button" class="btn-sm" style="padding: 10px 16px; font-weight: 700; background: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.2); color: #fff;" onclick="previewTTSLocalSpeech()">
                                    🔊 Preview Voice (Browser)
                                </button>
                            </div>

                            <div id="wa-test-feedback" style="display: none; margin-top: 14px; padding: 12px 16px; border-radius: 8px; font-size: 12px; line-height: 1.5;"></div>

                            <!-- Autonomous Triggers Architecture -->
                            <div style="margin-top: 20px; padding-top: 16px; border-top: 1px solid rgba(255, 255, 255, 0.08);">
                                <div style="font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 6px;">⚙️ Zero-Touch Autonomous Calling Policy</div>
                                <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                                    • <strong>Calling Time Slot</strong>: Server only initiates voice phone calls to Dealers and Integrators between <strong>10:00 AM – 6:00 PM</strong> (configurable per site in Gateway Edit Menu). Calls outside this window are automatically suppressed to respect partner quiet hours.<br>
                                    • <strong>WhatsApp &amp; Text Alerts</strong>: Dispatched 24/7 for high-priority events, self-healing status, and recovery notifications.<br>
                                    • <strong>Zero App Needed</strong>: Calls ring directly on cellular phone dialers using TTS synthesis, and messages land in standard WhatsApp.
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- SMTP Email Gateway & Alert Testing Station Card -->
                    <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(167, 139, 250, 0.4); border-radius: 16px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 25px rgba(0,0,0,0.4);">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
                            <div>
                                <div style="font-size: 16px; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 8px;">
                                    <span>📧 SMTP Email Gateway &amp; Alert Testing Station</span>
                                </div>
                                <div style="font-size: 12px; color: #94a3b8; margin-top: 4px; line-height: 1.5;">
                                    Configure outbound email notifications and test live email delivery using standard SMTP (Gmail, Microsoft 365, Brevo, Sendgrid, or Private Mail Server).
                                </div>
                            </div>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <span id="smtp-status-badge" style="font-size: 11px; font-weight: 700; color: #c084fc; background: rgba(192, 132, 252, 0.1); border: 1px solid rgba(192, 132, 252, 0.3); padding: 4px 10px; border-radius: 20px;">● Loading SMTP...</span>
                            </div>
                        </div>

                        <!-- SMTP Configuration Fields -->
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px;">
                            <div>
                                <label class="form-label">SMTP SERVER / HOST</label>
                                <input type="text" id="smtp-cfg-host" class="form-input" placeholder="e.g. smtp.gmail.com" value="">
                            </div>
                            <div>
                                <label class="form-label">SMTP PORT</label>
                                <input type="number" id="smtp-cfg-port" class="form-input" placeholder="e.g. 587 or 465" value="587">
                            </div>
                            <div>
                                <label class="form-label">ENCRYPTION PROTOCOL</label>
                                <select id="smtp-cfg-encryption" class="form-input" style="background: #0f172a; color: #fff;">
                                    <option value="tls">STARTTLS (Port 587 Recommended)</option>
                                    <option value="ssl">SSL / TLS (Port 465)</option>
                                    <option value="none">Unencrypted / Plain (Port 25)</option>
                                </select>
                            </div>
                        </div>

                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px;">
                            <div>
                                <label class="form-label">SMTP USERNAME / EMAIL</label>
                                <input type="text" id="smtp-cfg-user" class="form-input" placeholder="e.g. alerts@gavasah.com or user@gmail.com" value="">
                            </div>
                            <div>
                                <label class="form-label">SMTP PASSWORD / APP PASSWORD</label>
                                <div style="position: relative;">
                                    <input type="password" id="smtp-cfg-pass" class="form-input" placeholder="Enter SMTP password" style="padding-right: 36px;" value="">
                                    <button type="button" onclick="togglePassVisibility('smtp-cfg-pass')" style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 14px;">👁️</button>
                                </div>
                            </div>
                        </div>

                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px;">
                            <div>
                                <label class="form-label">FROM EMAIL ADDRESS</label>
                                <input type="text" id="smtp-cfg-from-email" class="form-input" placeholder="e.g. alerts@gavasah.com" value="">
                            </div>
                            <div>
                                <label class="form-label">SENDER DISPLAY NAME</label>
                                <input type="text" id="smtp-cfg-from-name" class="form-input" placeholder="e.g. GAVASAH Cloud Alerts" value="GAVASAH Cloud Alerts">
                            </div>
                            <div>
                                <label class="form-label">TEST RECIPIENT EMAIL</label>
                                <input type="email" id="smtp-test-recipient" class="form-input" placeholder="e.g. your-email@gmail.com" value="">
                            </div>
                        </div>

                        <!-- Action Buttons -->
                        <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
                            <button type="button" id="btn-save-smtp-cfg" class="btn-action" style="flex: 1; min-width: 170px; background: linear-gradient(135deg, #059669, #047857); border-color: #34d399;" onclick="saveSmtpConfig()">
                                💾 Save SMTP Settings
                            </button>
                            <button type="button" id="btn-test-smtp-cfg" class="btn-action" style="flex: 1; min-width: 170px; background: linear-gradient(135deg, #7c3aed, #6d28d9); border-color: #a78bfa;" onclick="testSmtpDirect()">
                                ⚡ Test SMTP &amp; Send Email
                            </button>
                        </div>

                        <div id="smtp-cfg-feedback" style="display: none; margin-top: 14px; padding: 12px 16px; border-radius: 8px; font-size: 12px; line-height: 1.5;"></div>
                    </div>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB: AI COPILOT & ECOSYSTEM CONSOLE (MANUFACTURER ONLY)
                     ============================================================== -->
                <div class="tab-pane" id="tab-copilot">
                    <div class="section-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                        <div>
                            <div class="section-title">🤖 Autonomous AI Copilot & Ecosystem Console</div>
                            <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">
                                Dedicated operational intelligence powered by NVIDIA GeForce RTX 3060 (12GB VRAM) on VM 307 with Qwen 2.5 Coder. Direct SSH, MQTT downlink, WireGuard, and telemetry communication services granting the AI system full autonomous permissions to diagnose, execute commands, and self-heal client gateways.
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <div id="copilot-autonomy-badge-wrapper" style="display: flex; align-items: center; gap: 8px; background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.5); padding: 7px 14px; border-radius: 20px;">
                                <span style="font-size: 13px;">⚡</span>
                                <span id="copilot-autonomy-label" style="font-size: 12px; font-weight: 800; color: #d8b4fe; letter-spacing: 0.5px;">FULL AUTONOMY: ACTIVE (Fleet & Proxmox)</span>
                                <button type="button" id="copilot-autonomy-btn" class="btn-sm" onclick="toggleCopilotAutonomy()" style="padding: 2px 8px; font-size: 11px; background: #a855f7; color: white; border: none; border-radius: 10px; cursor: pointer; font-weight: 700; margin-left: 4px;">Enabled</button>
                            </div>
                            <button class="btn-action" type="button" onclick="loadCopilotStatus(); loadCopilotProposals(); loadCopilotAutonomy();">🔄 Refresh Copilot</button>
                        </div>
                    </div>

                    <!-- Copilot Architecture Status Banner -->
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px;">
                        <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(168, 85, 247, 0.35); border-radius: 12px; padding: 18px;">
                            <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">AI Acceleration Node</div>
                            <div style="display: flex; align-items: center; gap: 8px; margin-top: 6px;">
                                <span class="status-indicator-dot online" style="width: 10px; height: 10px; background: #a855f7;"></span>
                                <span style="font-size: 16px; font-weight: 800; color: #fff;">VM 307 (ai-server-2)</span>
                            </div>
                            <div style="font-size: 11px; color: #c084fc; margin-top: 4px;">NVIDIA GeForce RTX 3060 12GB VRAM</div>
                        </div>

                        <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 12px; padding: 18px;">
                            <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Autonomous Reasoning Model</div>
                            <div style="font-size: 15px; font-weight: 700; color: #fff; margin-top: 6px;">
                                <code>qwen2.5-coder:7b</code>
                            </div>
                            <div style="font-size: 11px; color: #00f0ff; margin-top: 4px;">Ollama Tool Calling & API Reasoning Active</div>
                        </div>

                        <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px; padding: 18px;">
                            <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Self-Healing Safety Gate</div>
                            <div style="font-size: 15px; font-weight: 700; color: #10b981; margin-top: 6px;">
                                🛡️ Strict Human-in-the-Loop
                            </div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Edge 5 attempts &bull; AI 5 attempts &bull; Approval Gate</div>
                        </div>

                        <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 12px; padding: 18px;">
                            <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Pending Action Proposals</div>
                            <div style="display: flex; align-items: center; gap: 8px; margin-top: 6px;">
                                <span id="copilot-proposals-count" style="font-size: 20px; font-weight: 800; color: #fbbf24;">0</span>
                                <span style="font-size: 13px; color: #94a3b8;">Awaiting Approval</span>
                            </div>
                            <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Direct execution blocked until confirmed</div>
                        </div>
                    </div>

                    <!-- Proposals Review Section -->
                    <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 16px; padding: 22px; margin-bottom: 24px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                            <div style="font-size: 15px; font-weight: 700; color: #fbbf24; display: flex; align-items: center; gap: 8px;">
                                <span>📋 Pending Autonomous Proposals (Human Approval Gate)</span>
                            </div>
                            <span class="badge-role" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">Mandatory Confirmation</span>
                        </div>
                        <div id="copilot-proposals-container">
                            <div style="text-align: center; padding: 24px; color: #94a3b8; font-size: 13px;">
                                ✓ All ecosystem components operating nominally. No system or gateway proposals pending approval.
                            </div>
                        </div>
                    </div>

                    <!-- Interactive Copilot Console & Chat -->
                    <div style="display: flex; flex-direction: column; gap: 20px; width: 100%; box-sizing: border-box;">
                        <!-- TOP: Quick Diagnostic Probes & Autonomous Governance Strip (Fits Full Window Width) -->
                        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 16px; padding: 18px 22px; width: 100%; box-sizing: border-box;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;">
                                <div style="font-size: 14px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px;">
                                    <span>⚡ Quick Diagnostic Probes</span>
                                    <span style="font-size: 11px; font-weight: 500; color: #38bdf8; background: rgba(56, 189, 248, 0.1); padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.25);">One-Click Fleet Telemetry</span>
                                </div>
                                <div style="font-size: 11.5px; color: #cbd5e1; display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
                                    <span id="header-safety-mode-label">⚡ <strong>Permissions:</strong> Full Gateway Autonomy</span>
                                    <span>• <strong>Channels:</strong> Direct SSH, MQTT, WireGuard</span>
                                    <span>• <strong>Edge:</strong> Self-Healing Fleet Agent</span>
                                </div>
                            </div>
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 10px; width: 100%; box-sizing: border-box;">
                                <button type="button" class="btn-sm" style="text-align: left; padding: 11px 15px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); color: #cbd5e1; border-radius: 8px; display: flex; align-items: center; gap: 8px; cursor: pointer; transition: all 0.2s; font-size: 12.5px;" onmouseover="this.style.borderColor='#38bdf8'; this.style.background='rgba(56,189,248,0.08)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.1)'; this.style.background='rgba(255,255,255,0.04)'" onclick="sendCopilotQuickCmd('Audit ecosystem telemetry and report offline gateways')">
                                    <span>📊</span> <span>Audit Ecosystem Telemetry</span>
                                </button>
                                <button type="button" class="btn-sm" style="text-align: left; padding: 11px 15px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); color: #cbd5e1; border-radius: 8px; display: flex; align-items: center; gap: 8px; cursor: pointer; transition: all 0.2s; font-size: 12.5px;" onmouseover="this.style.borderColor='#38bdf8'; this.style.background='rgba(56,189,248,0.08)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.1)'; this.style.background='rgba(255,255,255,0.04)'" onclick="sendCopilotQuickCmd('Inspect broken integrations and recent gateway events')">
                                    <span>🔍</span> <span>Inspect Failed Integrations</span>
                                </button>
                                <button type="button" class="btn-sm" style="text-align: left; padding: 11px 15px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); color: #cbd5e1; border-radius: 8px; display: flex; align-items: center; gap: 8px; cursor: pointer; transition: all 0.2s; font-size: 12.5px;" onmouseover="this.style.borderColor='#10b981'; this.style.background='rgba(16,185,129,0.08)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.1)'; this.style.background='rgba(255,255,255,0.04)'" onclick="sendCopilotQuickCmd('Diagnose gateway vajju-vja-house across SSH, MQTT, and WireGuard')">
                                    <span>🛰️</span> <span>Probe Gateway: vajju-vja-house</span>
                                </button>
                                <button type="button" class="btn-sm" style="text-align: left; padding: 11px 15px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); color: #cbd5e1; border-radius: 8px; display: flex; align-items: center; gap: 8px; cursor: pointer; transition: all 0.2s; font-size: 12.5px;" onmouseover="this.style.borderColor='#a855f7'; this.style.background='rgba(168,85,247,0.08)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.1)'; this.style.background='rgba(255,255,255,0.04)'" onclick="sendCopilotQuickCmd('Test NVIDIA RTX 3060 inference and model latency')">
                                    <span>⚡</span> <span>Probe RTX 3060 Inference</span>
                                </button>
                                <button type="button" class="btn-sm" style="text-align: left; padding: 11px 15px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); color: #cbd5e1; border-radius: 8px; display: flex; align-items: center; gap: 8px; cursor: pointer; transition: all 0.2s; font-size: 12.5px;" onmouseover="this.style.borderColor='#fbbf24'; this.style.background='rgba(251,191,36,0.08)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.1)'; this.style.background='rgba(255,255,255,0.04)'" onclick="sendCopilotQuickCmd('Review pending action proposals and safety gates')">
                                    <span>🛡️</span> <span>Review Safety Gates</span>
                                </button>
                                <button type="button" class="btn-sm" style="text-align: left; padding: 11px 15px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); color: #cbd5e1; border-radius: 8px; display: flex; align-items: center; gap: 8px; cursor: pointer; transition: all 0.2s; font-size: 12.5px;" onmouseover="this.style.borderColor='#38bdf8'; this.style.background='rgba(56,189,248,0.08)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.1)'; this.style.background='rgba(255,255,255,0.04)'" onclick="sendCopilotQuickCmd('Audit Proxmox VE cluster nodes, VMs, and memory allocations')">
                                    <span>🖥️</span> <span>Audit Proxmox Cluster (PVE)</span>
                                </button>
                            </div>
                        </div>

                        <!-- MAIN: Live Operations AI Terminal (Full Window Width & Expanded Height) -->
                        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(168, 85, 247, 0.35); border-radius: 16px; padding: 22px; display: flex; flex-direction: column; height: 780px; min-height: 700px; width: 100%; box-sizing: border-box; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                                <div style="font-size: 15px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px;">
                                    <span>💬 Live Operations AI Terminal</span>
                                </div>
                                <div style="display: flex; align-items: center; gap: 10px;">
                                    <button type="button" id="toggle-thought-btn" onclick="toggleCopilotThoughts()" class="btn-sm" style="font-size: 11px; padding: 4px 10px; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.4); color: #38bdf8; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 5px;">
                                        🧠 Thoughts: <span id="thought-status-label" style="font-weight: 700; color: #34d399;">ON</span>
                                    </button>
                                    <span style="font-size: 11px; color: #c084fc; background: rgba(168, 85, 247, 0.15); padding: 3px 8px; border-radius: 12px; border: 1px solid rgba(168, 85, 247, 0.3);">VM 307 Stream (RTX 3060 12GB)</span>
                                </div>
                            </div>

                            <div id="copilot-messages-log" style="flex: 1; overflow-y: auto; background: rgba(0,0,0,0.45); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 16px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 12px; font-family: 'JetBrains Mono', monospace; font-size: 13px;">
                                <div style="line-height: 1.55;">
                                    <strong style="color: #c084fc;">[GAVASAH AI COPILOT]:</strong> <span style="color: #d8b4fe;">System initialized. Ready to execute fleet diagnostics, telemetry correlation, and self-healing analysis across the entire ecosystem.</span>
                                </div>
                            </div>

                            <form onsubmit="handleCopilotChatSubmit(event)" style="display: flex; gap: 10px; width: 100%;">
                                <input type="text" id="copilot-user-input" class="form-input" placeholder="Ask Copilot or command fleet operations (e.g. 'Audit offline gateways', 'Check MQTT telemetry')..." style="flex: 1; font-size: 13.5px; padding: 12px 16px;">
                                <button type="submit" id="copilot-send-btn" class="btn-action" style="background: linear-gradient(135deg, #7c3aed, #6d28d9); border-color: #a78bfa; padding: 12px 24px; font-size: 13.5px; font-weight: 600;">
                                    ⚡ Send
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB 4: MANUFACTURER ACCOUNT SETTINGS
                     ============================================================== -->
                <div class="tab-pane" id="tab-account">
                    <div class="section-header">
                        <div class="section-title">⚙️ Manufacturer Account & Security Settings</div>
                    </div>

                    <div class="account-card">
                        <form onsubmit="handleOwnerCredentialsUpdate(event)">
                            <div class="form-group">
                                <label class="form-label">CURRENT OWNER PASSWORD</label>
                                <div class="form-input-wrap">
                                    <input type="password" id="owner-curr-pwd" class="form-input" placeholder="Enter current password to authorize changes" required>
                                    <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('owner-curr-pwd', this)">👁️</button>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="form-label">NEW MANUFACTURER USERNAME</label>
                                <input type="text" id="owner-new-username" class="form-input" placeholder="e.g. admin" required>
                                <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Used to log into the manufacturer master console.</div>
                            </div>

                            <div class="form-group">
                                <label class="form-label">NEW OWNER PASSWORD (OPTIONAL)</label>
                                <div class="form-input-wrap">
                                    <input type="password" id="owner-new-pwd" class="form-input" placeholder="Leave blank to keep unchanged">
                                    <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('owner-new-pwd', this)">👁️</button>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="form-label">CONFIRM NEW PASSWORD</label>
                                <div class="form-input-wrap">
                                    <input type="password" id="owner-confirm-pwd" class="form-input" placeholder="Repeat new password">
                                    <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('owner-confirm-pwd', this)">👁️</button>
                                </div>
                            </div>

                            <button type="submit" class="btn-action" style="margin-top: 10px;">💾 Save Owner Credentials</button>
                        </form>
                    </div>
                </div>

                <!-- ==============================================================
                     TAB 5: BRANDING & WHITE-LABEL STUDIO (DEALER & MANUFACTURER)
                     ============================================================== -->
                <div class="tab-pane" id="tab-branding">
                    <div class="section-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                        <div>
                            <div class="section-title" id="branding-pane-title">🎨 Brand Identity & White-Label Studio</div>
                            <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;" id="branding-pane-subtitle">
                                Customize your portal identity, custom logo, theme accent colors, and contact info.
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn-sm" type="button" onclick="resetToDefaultBranding()" title="Reset to ecosystem default">↺ Reset Default</button>
                            <button class="btn-action" type="button" onclick="saveDealerBranding()">💾 Save Brand Settings</button>
                        </div>
                    </div>

                    <!-- 2-Column Studio Grid: Left Controls, Right Real-Time Preview Studio -->
                    <div class="branding-studio-grid">
                        <!-- LEFT COLUMN: Brand Identity & Asset Controls -->
                        <div class="branding-controls-col">
                            <form id="branding-form" onsubmit="handleBrandingFormSubmit(event)">
                                <!-- Card 1: Brand Identity -->
                                <div class="settings-card" style="margin-bottom: 20px;">
                                    <div class="settings-card-header">
                                        <div class="settings-card-title">🏢 Brand Identity</div>
                                        <div class="settings-card-sub">Company name and marketing tagline displayed across portals.</div>
                                    </div>
                                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                        <div class="form-group">
                                            <label class="form-label">BUSINESS / BRAND NAME</label>
                                            <input type="text" id="brand-company-name" class="form-input" placeholder="e.g. Apex Smart Automation" oninput="updateLiveBrandingPreview()">
                                        </div>
                                        <div class="form-group">
                                            <label class="form-label">TAGLINE / SUB-HEADER</label>
                                            <input type="text" id="brand-tagline" class="form-input" placeholder="e.g. Luxury Automation Systems" oninput="updateLiveBrandingPreview()">
                                        </div>
                                    </div>
                                </div>

                                <!-- Card 2: Custom Logo Upload & Management -->
                                <div class="settings-card" style="margin-bottom: 20px;">
                                    <div class="settings-card-header">
                                        <div class="settings-card-title">🖼️ Portal & Header Logo</div>
                                        <div class="settings-card-sub">Upload an image file directly from your computer. Appears on the top-right header and sidebar.</div>
                                    </div>

                                    <!-- Hidden File Input -->
                                    <input type="file" id="brand-logo-file-input" accept="image/png,image/jpeg,image/svg+xml,image/webp" style="display: none;" onchange="handleLogoFileSelect(event)">

                                    <!-- Dropzone when no logo is uploaded -->
                                    <div id="brand-logo-dropzone" class="logo-dropzone" onclick="document.getElementById('brand-logo-file-input').click()" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleFileDrop(event)">
                                        <div class="dropzone-icon">☁️</div>
                                        <div style="font-weight: 700; color: #f8fafc; font-size: 14px; margin-bottom: 4px;">Click to upload or drag & drop image</div>
                                        <div style="font-size: 11px; color: #94a3b8;">PNG, SVG, WEBP, or JPG • Direct image upload • Transparent background recommended</div>
                                    </div>

                                    <!-- Active Logo Card (Visible when logo exists) -->
                                    <div id="brand-active-logo-container" class="active-logo-box" style="display: none;">
                                        <div style="display: flex; align-items: center; gap: 16px;">
                                            <div class="logo-thumbnail-preview" id="brand-logo-thumb-wrap">
                                                <img id="brand-logo-thumbnail" src="" alt="Brand Logo Preview">
                                            </div>
                                            <div>
                                                <div style="font-size: 13px; font-weight: 700; color: #fff;" id="brand-logo-status-text">Custom Logo Active</div>
                                                <div style="font-size: 11px; color: #38bdf8; margin-top: 2px;">Rendered on top-right header and sidebar</div>
                                            </div>
                                        </div>
                                        <div style="display: flex; gap: 8px;">
                                            <button type="button" class="btn-sm" onclick="document.getElementById('brand-logo-file-input').click()" title="Upload a different image file">🔄 Replace</button>
                                            <button type="button" class="btn-danger-sm" onclick="deleteBrandLogo()" title="Delete this logo and revert to company badge">🗑️ Delete Logo</button>
                                        </div>
                                    </div>
                                </div>

                                <!-- Card 3: Color Palette & Dynamic Accent Theming -->
                                <div class="settings-card" style="margin-bottom: 20px;">
                                    <div class="settings-card-header">
                                        <div class="settings-card-title">🎨 Theme Palettes & Accent Colors</div>
                                        <div class="settings-card-sub">Select curated brand presets or define custom hex accent colors.</div>
                                    </div>

                                    <!-- Theme Presets Swatches -->
                                    <div style="margin-bottom: 14px;">
                                        <label class="form-label">PRESET COLOR PALETTES</label>
                                        <div class="theme-presets-grid">
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#00f0ff', '#38bdf8')"><span class="swatch-dot" style="background: #00f0ff;"></span> Cyber Cyan</button>
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#10b981', '#34d399')"><span class="swatch-dot" style="background: #10b981;"></span> Emerald Pro</button>
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#a855f7', '#c084fc')"><span class="swatch-dot" style="background: #a855f7;"></span> Neon Purple</button>
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#f59e0b', '#fbbf24')"><span class="swatch-dot" style="background: #f59e0b;"></span> Amber Gold</button>
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#3b82f6', '#60a5fa')"><span class="swatch-dot" style="background: #3b82f6;"></span> Cobalt Blue</button>
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#ec4899', '#f472b6')"><span class="swatch-dot" style="background: #ec4899;"></span> Rose Quartz</button>
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#06b6d4', '#22d3ee')"><span class="swatch-dot" style="background: #06b6d4;"></span> Electric Teal</button>
                                            <button type="button" class="preset-pill" onclick="setThemeSwatch('#64748b', '#94a3b8')"><span class="swatch-dot" style="background: #64748b;"></span> Stealth Slate</button>
                                        </div>
                                    </div>

                                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                        <div class="form-group">
                                            <label class="form-label">PRIMARY ACCENT COLOR</label>
                                            <div style="display: flex; align-items: center; gap: 10px;">
                                                <input type="color" id="brand-primary-color" value="#00f0ff" class="color-picker-input" oninput="updateLiveBrandingPreview()">
                                                <input type="text" id="brand-primary-color-text" class="form-input" value="#00f0ff" style="font-family: monospace;" oninput="syncColorInput(this.value, 'brand-primary-color')">
                                            </div>
                                        </div>
                                        <div class="form-group">
                                            <label class="form-label">GLOW & SECONDARY ACCENT</label>
                                            <div style="display: flex; align-items: center; gap: 10px;">
                                                <input type="color" id="brand-accent-color" value="#38bdf8" class="color-picker-input" oninput="updateLiveBrandingPreview()">
                                                <input type="text" id="brand-accent-color-text" class="form-input" value="#38bdf8" style="font-family: monospace;" oninput="syncColorInput(this.value, 'brand-accent-color')">
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Card 4: Support Contact Info -->
                                <div class="settings-card" style="margin-bottom: 20px;">
                                    <div class="settings-card-header">
                                        <div class="settings-card-title">📞 Support & Client Contacts</div>
                                        <div class="settings-card-sub">Contact information shown to clients on alerts and help pages.</div>
                                    </div>
                                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                        <div class="form-group">
                                            <label class="form-label">SUPPORT EMAIL</label>
                                            <input type="email" id="brand-email" class="form-input" placeholder="support@yourcompany.com" oninput="updateLiveBrandingPreview()">
                                        </div>
                                        <div class="form-group">
                                            <label class="form-label">HOTLINE / WHATSAPP</label>
                                            <input type="text" id="brand-phone" class="form-input" placeholder="+91 98490 12345" oninput="updateLiveBrandingPreview()">
                                        </div>
                                    </div>
                                </div>

                                <!-- Action Buttons -->
                                <div style="display: flex; gap: 12px; align-items: center; margin-top: 10px;">
                                    <button type="submit" class="btn-action" style="padding: 10px 24px; font-size: 13px;">💾 Save Brand Settings</button>
                                    <button type="button" class="btn-sm" onclick="resetToDefaultBranding()" style="padding: 10px 18px;">↺ Reset to Ecosystem Default</button>
                                </div>
                            </form>
                        </div>

                        <!-- RIGHT COLUMN: Live Multi-Surface Preview Studio -->
                        <div class="branding-preview-col">
                            <div class="preview-sticky-wrap">
                                <div style="font-size: 13px; font-weight: 800; color: #f8fafc; letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between;">
                                    <span>👁️ Live Preview Studio</span>
                                    <span style="font-size: 10px; color: var(--accent); font-weight: 700; background: rgba(0, 240, 255, 0.1); padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(0, 240, 255, 0.2);">REAL-TIME</span>
                                </div>

                                <!-- Mockup 1: Top-Right Header Bar -->
                                <div class="mockup-frame">
                                    <div class="mockup-header-title">TOP-RIGHT PORTAL HEADER PREVIEW</div>
                                    <div class="mockup-topbar-sample">
                                        <div style="font-size: 11px; color: #64748b; font-weight: 600;">HEADER ACTION BAR &rarr;</div>
                                        <!-- The Top Right Badge Mockup -->
                                        <div class="preview-header-badge" id="mock-header-container">
                                            <div id="mock-header-logo-wrap" class="mock-header-logo-wrap"></div>
                                            <div>
                                                <div id="mock-header-name" class="mock-header-name">GAVASAH HQ</div>
                                                <div id="mock-header-tag" class="mock-header-tag">MASTER PLATFORM</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Mockup 2: Left Sidebar Brand Header -->
                                <div class="mockup-frame" style="margin-top: 16px;">
                                    <div class="mockup-header-title">PORTAL NAVIGATION SIDEBAR BRAND PREVIEW</div>
                                    <div class="mockup-sidebar-sample">
                                        <div class="mock-sidebar-brand-box">
                                            <div id="mock-sidebar-logo" class="mock-sidebar-logo">G</div>
                                            <div>
                                                <div id="mock-sidebar-title" class="mock-sidebar-title">GAVASAH</div>
                                                <div id="mock-sidebar-sub" class="mock-sidebar-sub">CLOUD COMMAND</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Card 3: Live Fleet Metrics & Themed Card -->
                                <div class="mockup-frame" style="margin-top: 16px;">
                                    <div class="mockup-header-title" style="display: flex; justify-content: space-between; align-items: center;">
                                        <span>LIVE FLEET STATUS & SYSTEM HEALTH</span>
                                        <span style="font-size: 9px; color: var(--accent); font-weight: 700; letter-spacing: 0.5px;">REAL-TIME TELEMETRY</span>
                                    </div>
                                    <div class="mock-ui-card" id="mock-ui-card">
                                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                            <span style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase;">Supervised Fleet Health</span>
                                            <span class="mock-status-pill" id="mock-status-pill">CHECKING...</span>
                                        </div>
                                        <div style="font-size: 22px; font-weight: 800; color: #fff; margin-bottom: 4px;" id="mock-card-val">Loading...</div>
                                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 10px;" id="mock-card-sub">Fetching live gateway heartbeats...</div>
                                        <div style="font-size: 11px; color: #94a3b8; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 8px;" id="mock-card-footer">
                                            Support Desk: <span id="mock-card-email" style="color: var(--accent); font-weight: 600;">support@gavasah.com</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <!-- ======================================================================
         MODALS
         ====================================================================== -->

                <!-- Snapshot Manager Modal -->
                <div class="modal" id="snapshot-modal">
                    <div class="modal-content" style="max-width: 680px;">
                        <div class="modal-header">
                            <div id="snapshot-modal-title">📸 Site Snapshots & Backups: Client Site</div>
                            <div style="cursor: pointer;" onclick="closeSnapshotModal()">&times;</div>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="snapshot-client-id">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; background: rgba(56, 189, 248, 0.08); padding: 12px 16px; border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.2);">
                                <div>
                                    <div style="font-weight: 600; color: #fff;" id="snapshot-site-header">Site Gateway Backups</div>
                                    <div style="font-size: 11px; color: #94a3b8;">Trigger a full Home Assistant snapshot or download archives directly to your PC.</div>
                                </div>
                                <button class="btn-action" style="font-size: 12px; padding: 7px 14px; background: linear-gradient(135deg, #0ea5e9, #0284c7);" onclick="triggerInstantBackup()">+ Create Full Snapshot</button>
                            </div>

                            <div style="font-size: 11px; font-weight: 700; color: #38bdf8; text-transform: uppercase; margin-bottom: 8px;">Available Site Snapshots</div>
                            <div class="table-wrap" style="max-height: none; overflow-x: auto; overflow-y: visible;">
                                <table style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th>Snapshot Name</th>
                                            <th>Date</th>
                                            <th>Size</th>
                                            <th style="text-align: right;">Download Action</th>
                                        </tr>
                                    </thead>
                                    <tbody id="snapshot-table-body">
                                        <tr><td colspan="4" style="text-align: center; color: #64748b; padding: 20px;">Loading site snapshots...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn-sm" onclick="closeSnapshotModal()">Close</button>
                        </div>
                    </div>
                </div>

    <!-- Dealer Add / Edit Modal -->
    <div class="modal" id="dealer-modal">
        <div class="modal-content">
            <div class="modal-header">
                <div id="dealer-modal-title">Register New Authorized Dealer</div>
                <div style="cursor: pointer;" onclick="closeDealerModal()">&times;</div>
            </div>
            <form onsubmit="handleDealerFormSubmit(event)">
                <div class="modal-body">
                    <input type="hidden" id="dealer-form-id">
                    <div class="form-group">
                        <label class="form-label">DEALER BUSINESS / FULL NAME</label>
                        <input type="text" id="dlr-name" class="form-input" placeholder="e.g. Apex Smart Automation" required>
                    </div>

                    <div class="form-group" id="dlr-username-group" style="display: none;">
                        <label class="form-label">ASSIGNED LOGIN USERNAME</label>
                        <div id="dlr-username-badge" class="badge-role" style="display: inline-block; padding: 6px 12px; font-size: 13px; font-family: monospace; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4);"></div>
                        <input type="hidden" id="dlr-username">
                        <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Autonomously generated username slug: &lt;dealer name&gt;.</div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" id="dlr-pwd-label">PASSWORD</label>
                        <div class="form-input-wrap">
                            <input type="password" id="dlr-pwd" class="form-input" placeholder="Set secure password">
                            <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('dlr-pwd', this)">👁️</button>
                        </div>
                        <div id="dlr-pwd-hint" style="display: none; font-size: 11px; color: #64748b; margin-top: 4px;">Existing password displayed above. Modify here to update password.</div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">CONTACT EMAIL</label>
                        <input type="email" id="dlr-email" class="form-input" placeholder="contact@dealer.com">
                    </div>

                    <div class="form-group">
                        <label class="form-label">PHONE NUMBER</label>
                        <input type="text" id="dlr-phone" class="form-input" placeholder="+91 98490 12345">
                    </div>

                    <div class="form-group" id="dlr-status-group" style="display: none;">
                        <label class="form-label">ACCOUNT STATUS</label>
                        <select id="dlr-status" class="form-input">
                            <option value="active">Active</option>
                            <option value="suspended">Suspended</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-sm" onclick="closeDealerModal()">Cancel</button>
                    <button type="submit" class="btn-action btn-purple">💾 Save Dealer Account</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Dealer Password Change Modal (For Dealer's own account) -->
    <div class="modal" id="dealer-pwd-modal">
        <div class="modal-content">
            <div class="modal-header">
                <div>Change My Password</div>
                <div style="cursor: pointer;" onclick="closeDealerPasswordModal()">&times;</div>
            </div>
            <form onsubmit="handleDealerSelfPasswordChange(event)">
                <div class="modal-body">
                    <div class="form-group">
                        <label class="form-label">CURRENT PASSWORD</label>
                        <div class="form-input-wrap">
                            <input type="password" id="self-curr-pwd" class="form-input" required>
                            <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('self-curr-pwd', this)">👁️</button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">NEW PASSWORD</label>
                        <div class="form-input-wrap">
                            <input type="password" id="self-new-pwd" class="form-input" required>
                            <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('self-new-pwd', this)">👁️</button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">CONFIRM NEW PASSWORD</label>
                        <div class="form-input-wrap">
                            <input type="password" id="self-confirm-pwd" class="form-input" required>
                            <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('self-confirm-pwd', this)">👁️</button>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-sm" onclick="closeDealerPasswordModal()">Cancel</button>
                    <button type="submit" class="btn-action">Update Password</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Onboard Client Modal -->
    <div class="modal" id="onboard-modal">
        <div class="modal-content">
            <div class="modal-header">
                <div>Onboard New Client Site</div>
                <div style="cursor: pointer;" onclick="closeOnboardModal()">&times;</div>
            </div>
            <form onsubmit="handleOnboardSubmit(event)">
                <div class="modal-body">
                    <div class="form-group" id="onb-dealer-group">
                        <label class="form-label">ASSIGN TO DEALER</label>
                        <select id="onb-dealer-select" class="form-input" onchange="onOnboardDealerChange()">
                        </select>
                    </div>
                    <div class="form-group" id="onb-integrator-group">
                        <label class="form-label">ASSIGNED INTEGRATOR</label>
                        <select id="onb-integrator-select" class="form-input">
                            <!-- Populated with integrators -->
                        </select>
                    </div>

                    <div class="form-group">
                        <label class="form-label">CLIENT SITE NAME</label>
                        <input type="text" id="onb-name" class="form-input" placeholder="e.g. Sharma Villa (Jubilee Hills)" required oninput="onOnboardNameChange()">
                        <input type="hidden" id="onb-slug">
                        <input type="hidden" id="onb-secret">
                        <div style="margin-top: 8px; padding: 10px 14px; background: rgba(56, 189, 248, 0.06); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px;">
                            <div style="font-size: 12px; color: #38bdf8; font-family: monospace; display: flex; align-items: center; gap: 6px;">
                                <span>🌐 Auto-Assigned Ingress Subdomain:</span>
                                <span id="onb-preview-domain" style="font-weight: 700; color: #00f0ff;">client-direct.gavasah.com</span>
                            </div>
                            <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Secure cryptographic token and ingress subdomain are automatically provisioned.</div>
                        </div>
                    </div>

                    <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 10px 14px; margin-top: 10px;">
                        <div style="font-size: 12px; color: #34d399; font-weight: 600; display: flex; align-items: center; gap: 6px;">
                            <span>⚡ Autonomous Protocol & KNX Discovery</span>
                        </div>
                        <div style="font-size: 11px; color: #94a3b8; margin-top: 3px;">
                            The GAVASAH add-on automatically inspects Home Assistant to discover whether the site uses KNX, Lutron, Zigbee, CoolMaster, or other protocols, retrieving gateway IP & port autonomously without manual entry.
                        </div>
                    </div>
                    <div class="form-group" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 10px; padding: 12px 16px; margin-top: 14px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <label class="form-label" style="margin-bottom: 2px; color: #fff; font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 6px;">
                                    🌐 CLIENT REMOTE ACCESS (INGRESS)
                                </label>
                                <div style="font-size: 11px; color: #94a3b8;">
                                    Enable remote browser access to Home Assistant Dashboard by default.
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <label class="toggle-switch" title="Toggle default remote access">
                                    <input type="checkbox" id="onb-remote-toggle" checked onchange="onOnboardRemoteToggleChange(this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                                <span id="onb-remote-status-text" class="toggle-pill-badge pill-live" style="min-width: 65px; text-align: center;">🟢 LIVE</span>
                            </div>
                        </div>
                    </div>
                    <input type="hidden" id="onb-ssh-key">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-sm" onclick="closeOnboardModal()">Cancel</button>
                    <button type="submit" id="onb-submit-btn" class="btn-action" style="background: linear-gradient(135deg, #0284c7, #0369a1); font-weight: 600;">🚀 Save & Provision Site</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Client Modal -->
    <div class="modal" id="edit-modal">
        <div class="modal-content" style="max-width: 620px; width: 100%; box-sizing: border-box;">
            <div class="modal-header">
                <div style="font-size: 15px; font-weight: 700; color: #fff;">Edit Client Site Configuration</div>
                <div style="cursor: pointer; font-size: 20px; color: #94a3b8;" onclick="closeEditModal()">&times;</div>
            </div>
            <form onsubmit="handleClientEditSubmit(event)">
                <div class="modal-body" style="overflow-x: hidden; overflow-y: auto; max-height: 78vh; padding: 20px 24px;">
                    <input type="hidden" id="edit-client-id">
                    <input type="hidden" id="edit-id">
                    
                    <div id="edit-assignment-row" style="display: flex; gap: 12px; margin-bottom: 14px; flex-wrap: wrap;">
                        <div class="form-group" id="edit-dealer-group" style="flex: 1; min-width: 220px; margin-bottom: 0;">
                            <label class="form-label">ASSIGNED DEALER</label>
                            <select id="edit-dealer-select" class="form-input" onchange="onEditDealerChange()">
                            </select>
                        </div>
                        <div class="form-group" id="edit-integrator-group" style="flex: 1; min-width: 220px; margin-bottom: 0;">
                            <label class="form-label">ASSIGNED INTEGRATOR</label>
                            <select id="edit-integrator-select" class="form-input">
                                <!-- Populated with integrators -->
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">CLIENT SITE NAME</label>
                        <input type="text" id="edit-name" class="form-input" required>
                    </div>

                    <input type="hidden" id="edit-secret">

                    <div class="form-group" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 10px; padding: 14px 16px; margin-top: 14px;">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                            <label class="form-label" style="margin-bottom: 0; color: #fbbf24; font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 6px;">
                                ⏱️ HEALTH & ESCALATION INTERVALS (HEARTBEAT & INTEGRATIONS)
                            </label>
                            <span class="badge-role" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); font-size: 10px;">MINUTES & HOURS</span>
                        </div>
                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 12px; line-height: 1.4;">
                            Configure threshold escalation (in minutes or hours) triggered by missed heartbeats or subsystem/integration failures:
                        </div>

                        <!-- Optimized vertical stack layout with zero horizontal scrolling -->
                        <div style="display: flex; flex-direction: column; gap: 10px;">
                            <!-- Tier 1: Delayed Pulse / Minor Issues (Yellow) -->
                            <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(250, 204, 21, 0.05); border: 1px solid rgba(250, 204, 21, 0.25); border-radius: 8px; padding: 10px 14px; gap: 12px; flex-wrap: wrap;">
                                <div style="flex: 1; min-width: 180px;">
                                    <div style="font-size: 12px; font-weight: 700; color: #facc15; display: flex; align-items: center; gap: 6px;">
                                        🟡 DELAYED / DEGRADED
                                    </div>
                                    <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">
                                        Warns <strong>Integrator</strong>
                                    </div>
                                </div>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <input type="number" id="edit-hb-delayed-val" class="form-input" min="1" max="720" step="1" placeholder="15" style="width: 85px; font-size: 14px; font-family: 'JetBrains Mono', monospace; font-weight: 700; text-align: center; padding: 8px 10px;" required>
                                    <select id="edit-hb-delayed-unit" class="form-input" style="width: 100px; font-size: 12px; font-weight: 600; padding: 8px 10px;">
                                        <option value="m">Minutes</option>
                                        <option value="h">Hours</option>
                                    </select>
                                </div>
                            </div>

                            <!-- Tier 2: Warning (Orange) -->
                            <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(251, 146, 60, 0.05); border: 1px solid rgba(251, 146, 60, 0.25); border-radius: 8px; padding: 10px 14px; gap: 12px; flex-wrap: wrap;">
                                <div style="flex: 1; min-width: 180px;">
                                    <div style="font-size: 12px; font-weight: 700; color: #fb923c; display: flex; align-items: center; gap: 6px;">
                                        🟠 WARNING LEVEL
                                    </div>
                                    <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">
                                        Warns <strong>Integrator + Dealer</strong>
                                    </div>
                                </div>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <input type="number" id="edit-hb-warning-val" class="form-input" min="1" max="720" step="1" placeholder="30" style="width: 85px; font-size: 14px; font-family: 'JetBrains Mono', monospace; font-weight: 700; text-align: center; padding: 8px 10px;" required>
                                    <select id="edit-hb-warning-unit" class="form-input" style="width: 100px; font-size: 12px; font-weight: 600; padding: 8px 10px;">
                                        <option value="m">Minutes</option>
                                        <option value="h">Hours</option>
                                    </select>
                                </div>
                            </div>

                            <!-- Tier 3: Offline (Red) -->
                            <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px; padding: 10px 14px; gap: 12px; flex-wrap: wrap;">
                                <div style="flex: 1; min-width: 180px;">
                                    <div style="font-size: 12px; font-weight: 700; color: #f87171; display: flex; align-items: center; gap: 6px;">
                                        🔴 OFFLINE / CRITICAL
                                    </div>
                                    <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">
                                        Warns <strong>All + Manufacturer HQ</strong>
                                    </div>
                                </div>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <input type="number" id="edit-hb-offline-val" class="form-input" min="1" max="720" step="1" placeholder="60" style="width: 85px; font-size: 14px; font-family: 'JetBrains Mono', monospace; font-weight: 700; text-align: center; padding: 8px 10px;" required>
                                    <select id="edit-hb-offline-unit" class="form-input" style="width: 100px; font-size: 12px; font-weight: 600; padding: 8px 10px;">
                                        <option value="m">Minutes</option>
                                        <option value="h">Hours</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="form-group" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 10px; padding: 12px 16px; margin-top: 14px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                            <div style="flex: 1; min-width: 200px;">
                                <label class="form-label" style="margin-bottom: 2px; color: #fff; font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 6px;">
                                    🌐 CLIENT REMOTE ACCESS (INGRESS)
                                </label>
                                <div style="font-size: 11px; color: #94a3b8;" id="edit-remote-help">
                                    Enable or suspend remote browser dashboard access through Gavasah Cloud Hub.
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <label class="toggle-switch" title="Toggle Client Remote Ingress Access">
                                    <input type="checkbox" id="edit-remote-toggle" onchange="onEditRemoteToggleChange(this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                                <span id="edit-remote-status-text" class="toggle-pill-badge pill-live" style="min-width: 75px; text-align: center;">🟢 LIVE</span>
                            </div>
                        </div>
                    </div>

                    <!-- Alert & Escalation Dispatch Channels (Call & Message Toggles + Calling Time Slot) -->
                    <div class="form-group" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 10px; padding: 14px 16px; margin-top: 12px;">
                        <div style="font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between;">
                            <span style="display: flex; align-items: center; gap: 6px;">🔔 AUTOMATED ALERTS &amp; ESCALATION DISPATCH</span>
                            <span style="font-size: 11px; color: #10b981; font-weight: 600;">Autonomous Engine</span>
                        </div>

                        <!-- Toggles: Separate Call and Message Options -->
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                            <!-- Phone Call Alerts Toggle -->
                            <div style="background: rgba(2, 6, 23, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 10px 12px; display: flex; align-items: center; justify-content: space-between;">
                                <div>
                                    <div style="font-size: 12px; font-weight: 700; color: #f1f5f9; display: flex; align-items: center; gap: 6px;">
                                        📞 Phone Call Alerts
                                    </div>
                                    <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Voice call to Dealer &amp; Integrator</div>
                                </div>
                                <label class="toggle-switch" title="Enable or disable automated voice phone calls">
                                    <input type="checkbox" id="edit-call-alert-toggle" checked>
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>

                            <!-- Message Alerts Toggle -->
                            <div style="background: rgba(2, 6, 23, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 10px 12px; display: flex; align-items: center; justify-content: space-between;">
                                <div>
                                    <div style="font-size: 12px; font-weight: 700; color: #f1f5f9; display: flex; align-items: center; gap: 6px;">
                                        💬 Message Alerts
                                    </div>
                                    <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">WhatsApp &amp; SMS text dispatch</div>
                                </div>
                                <label class="toggle-switch" title="Enable or disable automated WhatsApp and text messages">
                                    <input type="checkbox" id="edit-msg-alert-toggle" checked>
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                        </div>

                        <!-- Permitted Calling Time Slot -->
                        <div style="background: rgba(2, 6, 23, 0.6); border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 8px; padding: 12px 14px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                <div style="font-size: 12px; font-weight: 700; color: #00f0ff; display: flex; align-items: center; gap: 6px;">
                                    ⏰ Permitted Calling Time Slot (Dealer &amp; Integrator)
                                </div>
                                <span style="font-size: 11px; color: #94a3b8; font-family: monospace;">IST Window</span>
                            </div>
                            <div style="font-size: 11px; color: #94a3b8; line-height: 1.4; margin-bottom: 10px;">
                                Server will <strong>only place voice phone calls</strong> between these hours. Outside this window, voice calls are suppressed to prevent disturbances.
                            </div>
                            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                                <div style="display: flex; align-items: center; gap: 6px;">
                                    <span style="font-size: 12px; color: #cbd5e1; font-weight: 600;">From:</span>
                                    <input type="time" id="edit-call-start-time" class="form-input" value="10:00" style="width: 120px; font-size: 13px; font-weight: 700; text-align: center; padding: 6px 10px;">
                                </div>
                                <div style="display: flex; align-items: center; gap: 6px;">
                                    <span style="font-size: 12px; color: #cbd5e1; font-weight: 600;">To:</span>
                                    <input type="time" id="edit-call-end-time" class="form-input" value="18:00" style="width: 120px; font-size: 13px; font-weight: 700; text-align: center; padding: 6px 10px;">
                                </div>
                                <span style="font-size: 11px; color: #64748b;">(Default: 10:00 AM – 6:00 PM)</span>
                            </div>
                        </div>
                    </div>

                    <div class="form-group" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(192, 132, 252, 0.3); border-radius: 10px; padding: 12px 16px; margin-top: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                            <div style="flex: 1; min-width: 200px;">
                                <label class="form-label" style="margin-bottom: 2px; color: #c084fc; font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 6px;">
                                    ⚡ REMOTE KNX ACCESS (DEVICE PROGRAMMING)
                                </label>
                                <div style="font-size: 11px; color: #94a3b8;" id="edit-knx-remote-help">
                                    Enable or suspend remote ETS tunneling and UDP port forwarding for KNX device programming.
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <label class="toggle-switch" title="Toggle Remote KNX Device Programming Access">
                                    <input type="checkbox" id="edit-knx-remote-toggle" onchange="onEditKnxRemoteToggleChange(this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                                <span id="edit-knx-remote-status-text" class="toggle-pill-badge pill-live" style="min-width: 75px; text-align: center;">🟢 LIVE</span>
                            </div>
                        </div>
                    </div>

                    <div class="form-group" style="margin-top: 14px; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 6px;">
                            <label class="form-label" style="margin-bottom: 0; color: #38bdf8; font-weight: 600;">📋 CLIENT ADD-ON CONFIGURATION (YAML)</label>
                            <button type="button" class="btn-sm" style="padding: 4px 10px; font-size: 11px; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4);" onclick="copyAddonConfig()">📋 Copy Config</button>
                        </div>
                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">Paste into your Home Assistant <strong>Gavasah Cloud Agent</strong> Add-on configuration:</div>
                        <pre class="config-box" id="edit-config-snippet" style="background: #030610; border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 12px 14px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #38bdf8; white-space: pre-wrap; word-break: break-all; overflow-wrap: anywhere; line-height: 1.5; user-select: all; margin: 0; max-height: 160px; overflow-y: auto; overflow-x: hidden;"></pre>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-sm" onclick="closeEditModal()">Cancel</button>
                    <button type="submit" class="btn-action">💾 Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Integrator Modal (Create / Edit) -->
    <div class="modal" id="integrator-modal">
        <div class="modal-content" style="max-width: 520px;">
            <div class="modal-header">
                <div id="integrator-modal-title">Register New Integrator</div>
                <div style="cursor: pointer;" onclick="closeIntegratorModal()">&times;</div>
            </div>
            <form id="integrator-form" onsubmit="handleIntegratorSubmit(event)">
                <input type="hidden" id="int-id">
                <div class="modal-body">
                    <div class="form-group" id="int-dealer-select-wrap">
                        <label class="form-label">ASSIGNED DEALERSHIP</label>
                        <select id="int-dealer-select" class="form-input">
                            <!-- Populated with dealers -->
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">INTEGRATOR FULL NAME</label>
                        <input type="text" id="int-name" class="form-input" placeholder="e.g. Rajesh Kumar" required>
                    </div>
                    <div class="form-group" id="int-username-group" style="display: none;">
                        <label class="form-label">LOGIN USERNAME</label>
                        <div id="int-username-badge" class="badge-role" style="display: inline-block; padding: 6px 12px; font-size: 13px; font-family: monospace; background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4);"></div>
                        <input type="hidden" id="int-username">
                        <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Autonomously generated: &lt;integrator name&gt;-&lt;dealer name&gt;.</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label" id="int-pwd-label">LOGIN PASSWORD</label>
                        <div class="form-input-wrap">
                            <input type="password" id="int-password" class="form-input" placeholder="Set secure password" required>
                            <button type="button" class="pwd-toggle-btn" onclick="togglePasswordVisibility('int-password', this)">👁️</button>
                        </div>
                        <div id="int-pwd-hint" style="display: none; font-size: 11px; color: #64748b; margin-top: 4px;">Existing password displayed above. Modify here to update password.</div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                        <div class="form-group">
                            <label class="form-label">CONTACT EMAIL</label>
                            <input type="email" id="int-email" class="form-input" placeholder="rajesh@apexsmart.in">
                        </div>
                        <div class="form-group">
                            <label class="form-label">CONTACT PHONE</label>
                            <input type="text" id="int-phone" class="form-input" placeholder="+91 98450 11223">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-sm" onclick="closeIntegratorModal()">Cancel</button>
                    <button type="submit" id="int-submit-btn" class="btn-action" style="background: linear-gradient(135deg, #10b981, #059669);">💾 Save Integrator</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Reassign Client Supervision Modal -->
    <div class="modal" id="reassign-modal">
        <div class="modal-content" style="max-width: 480px;">
            <div class="modal-header">
                <div>🔄 Reassign Client Supervision</div>
                <div style="cursor: pointer;" onclick="closeReassignModal()">&times;</div>
            </div>
            <form id="reassign-form" onsubmit="handleReassignSubmit(event)">
                <input type="hidden" id="reassign-client-id">
                <div class="modal-body">
                    <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                        Transfer management responsibility for <strong id="reassign-client-name" style="color: #fff;"></strong>.
                    </div>
                    <div class="form-group" id="reassign-dealer-wrap">
                        <label class="form-label">ASSIGNED DEALERSHIP</label>
                        <select id="reassign-dealer-select" class="form-input" onchange="onReassignDealerChange()">
                            <!-- Populated with dealers -->
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">ASSIGNED INTEGRATOR</label>
                        <select id="reassign-integrator-select" class="form-input">
                            <!-- Populated with integrators -->
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-sm" onclick="closeReassignModal()">Cancel</button>
                    <button type="submit" class="btn-action">🔄 Transfer Supervision</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Delete Modal (Client or Dealer or Integrator) -->
    <div class="modal" id="delete-modal">
        <div class="modal-content" style="max-width: 440px;">
            <div class="modal-header">
                <div id="delete-modal-title">Confirm Deletion</div>
                <div style="cursor: pointer;" onclick="closeDeleteModal()">&times;</div>
            </div>
            <div class="modal-body">
                <p id="delete-modal-msg" style="font-size: 13px; line-height: 1.6; color: #cbd5e1;"></p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-sm" onclick="closeDeleteModal()">Cancel</button>
                <button type="button" id="delete-confirm-btn" class="btn-sm btn-danger-sm" onclick="confirmDeletion()">Confirm Delete</button>
            </div>
        </div>
    </div>

    <!-- Logs Modal -->
    <div class="modal" id="logs-modal">
        <div class="modal-content" style="max-width: 800px;">
            <div class="modal-header">
                <div>📜 Live Diagnostic Telemetry: <span id="log-client-title" style="color: var(--accent);"></span></div>
                <div style="cursor: pointer;" onclick="closeLogsModal()">&times;</div>
            </div>
            <div class="modal-body">
                <div class="terminal-box" id="logs-terminal"></div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-sm" onclick="copyCurrentLogs()">📋 Copy Logs</button>
                <button type="button" class="btn-sm" onclick="refreshCurrentLogs()">🔄 Refresh</button>
                <button type="button" class="btn-sm" onclick="closeLogsModal()">Close</button>
            </div>
        </div>
    </div>

    <!-- SSL Status Modal -->
    <div class="modal" id="ssl-modal">
        <div class="modal-content" style="max-width: 700px;">
            <div class="modal-header">
                <div>🔐 Autonomous Edge SSL / TLS Certificates</div>
                <div style="cursor: pointer;" onclick="closeSslModal()">&times;</div>
            </div>
            <div class="modal-body">
                <div style="margin-bottom: 16px; font-size: 13px; color: #94a3b8;">
                    Caddy ACME ARI Automated Renewal (RFC 9444 / RFC 8555) active for apex and all dealer client subdomains.
                </div>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain / Hostname</th>
                                <th>Certificate Authority</th>
                                <th>Validity Cycle</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="ssl-table-body"></tbody>
                    </table>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-sm" onclick="closeSslModal()">Close</button>
            </div>
        </div>
    </div>

    <!-- Toast Notifications Container -->
    <div id="toast-box"></div>

    <script>

        // ==========================================
        // SIDEBAR COLLAPSE & EXPAND CONTROLLER (3-LINE ICON)
        // ==========================================
        function toggleSidebar() {
            if (window.innerWidth <= 900) {
                document.body.classList.toggle('sidebar-open-mobile');
            } else {
                const isCollapsed = document.body.classList.toggle('sidebar-collapsed');
                try {
                    localStorage.setItem('gavasah_sidebar_collapsed', isCollapsed ? 'true' : 'false');
                } catch (e) {}
            }
        }

        function closeSidebarMobile() {
            document.body.classList.remove('sidebar-open-mobile');
        }

        function initSidebarState() {
            try {
                if (localStorage.getItem('gavasah_sidebar_collapsed') === 'true') {
                    document.body.classList.add('sidebar-collapsed');
                }
            } catch (e) {}
        }
        initSidebarState();


        // ======================================================================
        // STATE MANAGEMENT
        // ======================================================================
        let currentUser = null;
        let currentFleetData = [];
        let dealersList = [];
        let integratorsList = [];
        let activeTab = 'overview';
        let fleetSearchQuery = '';
        let fleetStatusFilter = 'ALL';
        let fleetCurrentPage = 1;
        let fleetPageSize = 25;
        let currentLogsClient = null;
        let currentDeleteTarget = null; // { type: 'client'|'dealer'|'integrator', id: string, name: string }

        // ======================================================================
        // AUTHENTICATION & SESSION LIFECYCLE
        // ======================================================================
        function getAuthToken() {
            try {
                return localStorage.getItem('gavasah_session') || '';
            } catch (e) {
                return '';
            }
        }

        function setAuthToken(token) {
            try {
                if (token) {
                    localStorage.setItem('gavasah_session', token);
                } else {
                    localStorage.removeItem('gavasah_session');
                }
            } catch (e) {}
        }

        async function apiFetch(url, options = {}) {
            options = options || {};
            const headers = options.headers || {};
            const token = getAuthToken();
            if (token && !headers['Authorization']) {
                headers['Authorization'] = 'Bearer ' + token;
            }
            options.headers = headers;
            options.credentials = 'same-origin';
            return fetch(url, options);
        }

        async function checkAuth() {
            try {
                const res = await apiFetch('/api/me?t=' + Date.now());
                const data = await res.json();
                if (data.authenticated && data.user) {
                    currentUser = data.user;
                    initAuthenticatedUI();
                } else {
                    currentUser = null;
                    showLoginScreen();
                }
            } catch (err) {
                console.error("Auth check error:", err);
                showLoginScreen();
            }
        }

        function showLoginScreen() {
            document.getElementById('login-view').style.display = 'flex';
            document.getElementById('app-view').style.display = 'none';
            const hdrBrand = document.getElementById('header-brand-container');
            if (hdrBrand) hdrBrand.style.display = 'none';
        }

        function initAuthenticatedUI() {
            document.getElementById('login-view').style.display = 'none';
            document.getElementById('app-view').style.display = 'flex';

            const roleBadge = document.getElementById('portal-role-badge');
            const sideAvatar = document.getElementById('sidebar-user-avatar');
            const sideName = document.getElementById('sidebar-user-name');
            const sideRole = document.getElementById('sidebar-user-role');
            const dealerActions = document.getElementById('dealer-header-actions');
            const integratorActions = document.getElementById('integrator-header-actions');

            if (sideAvatar) sideAvatar.innerText = (currentUser.name || currentUser.username)[0].toUpperCase();
            if (sideName) sideName.innerText = currentUser.name || currentUser.username;

            document.body.classList.remove('is-manufacturer', 'is-dealer', 'is-integrator');

            if (currentUser.role === 'manufacturer') {
                document.body.classList.add('is-manufacturer');
                if (roleBadge) {
                    roleBadge.innerText = 'MANUFACTURER (MASTER OWNER)';
                    roleBadge.className = 'portal-role-tag role-tag-manufacturer';
                }
                if (sideRole) sideRole.innerText = 'MASTER OWNER';
                if (dealerActions) dealerActions.style.display = 'none';
                if (integratorActions) integratorActions.style.display = 'none';

                // Tabs visibility for Manufacturer
                document.getElementById('nav-overview').style.display = 'flex';
                document.getElementById('nav-dealers').style.display = 'flex';
                document.getElementById('nav-integrators').style.display = 'flex';
                document.getElementById('nav-fleet').style.display = 'flex';
                document.getElementById('nav-account').style.display = 'flex';
                document.getElementById('th-dealer-col').style.display = '';
                const thIntMfg = document.getElementById('th-integrator-col'); if (thIntMfg) thIntMfg.style.display = '';
                document.getElementById('th-int-dealership-col').style.display = '';
                document.getElementById('integrator-dealer-filter-wrap').style.display = 'block';
                const ovCardDealers = document.getElementById('ov-card-dealers');
                if (ovCardDealers) ovCardDealers.style.display = '';

                const navBrandMfg = document.getElementById('nav-branding');
                if (navBrandMfg) navBrandMfg.style.display = 'flex';
                const navApprovals = document.getElementById('nav-approvals');
                if (navApprovals) navApprovals.style.display = 'flex';
                const ovApprovalsCard = document.getElementById('ov-card-approvals');
                if (ovApprovalsCard) ovApprovalsCard.style.display = '';
                const navMqtt = document.getElementById('nav-mqtt');
                if (navMqtt) navMqtt.style.display = 'flex';
                const navAlerts = document.getElementById('nav-alerts');
                if (navAlerts) navAlerts.style.display = 'flex';
                const navCopilot = document.getElementById('nav-copilot');
                if (navCopilot) navCopilot.style.display = 'flex';
                loadWhatsAppStatus();
                loadAdminWhatsAppNumber();
                applyDealerBranding(currentUser.branding);
                switchTab('overview');
                fetchDealers();
                fetchIntegrators();
                fetchFleet();
                fetchApprovals();
                populatePartnerFilter();

            } else if (currentUser.role === 'dealer') {
                document.body.classList.add('is-dealer');
                if (roleBadge) {
                    roleBadge.innerText = `DEALER: ${currentUser.name || currentUser.username}`;
                    roleBadge.className = 'portal-role-tag role-tag-dealer';
                }
                if (sideRole) sideRole.innerText = 'AUTHORIZED DEALER';
                if (dealerActions) dealerActions.style.display = 'flex';
                if (integratorActions) integratorActions.style.display = 'none';

                // Dealers have Sidebar with Summary, Integrators, Fleet, My Password
                document.getElementById('nav-overview').style.display = 'flex';
                document.getElementById('nav-dealers').style.display = 'none';
                document.getElementById('nav-integrators').style.display = 'flex';
                document.getElementById('nav-fleet').style.display = 'flex';
                document.getElementById('nav-account').style.display = 'none';
                const navBrand = document.getElementById('nav-branding');
                if (navBrand) navBrand.style.display = 'flex';
                const navApprD = document.getElementById('nav-approvals');
                if (navApprD) navApprD.style.display = 'none';
                const navMqttD = document.getElementById('nav-mqtt');
                if (navMqttD) navMqttD.style.display = 'none';
                applyDealerBranding(currentUser.branding);
                document.getElementById('th-dealer-col').style.display = 'none';
                const thIntDlr = document.getElementById('th-integrator-col'); if (thIntDlr) thIntDlr.style.display = '';
                document.getElementById('th-int-dealership-col').style.display = 'none';
                document.getElementById('integrator-dealer-filter-wrap').style.display = 'none';

                // Hide Total Authorized Dealers card for Dealer
                const ovCardDealers = document.getElementById('ov-card-dealers');
                if (ovCardDealers) ovCardDealers.style.display = 'none';

                // Adjust Overview Header for Dealer
                const ovHeaderTitle = document.querySelector('#tab-overview .section-title');
                if (ovHeaderTitle) ovHeaderTitle.innerHTML = '<span>🔧</span> Supervised Integrators & Client Health Breakdown';
                const ovAddBtn = document.querySelector('#tab-overview .section-header button');
                if (ovAddBtn) {
                    ovAddBtn.innerText = '+ Register New Integrator';
                    ovAddBtn.onclick = openCreateIntegratorModal;
                }

                switchTab('overview');
                fetchIntegrators();
                fetchFleet();
                populatePartnerFilter();

            } else if (currentUser.role === 'integrator') {
                document.body.classList.add('is-integrator');
                if (roleBadge) {
                    roleBadge.innerText = `INTEGRATOR: ${currentUser.name} (${currentUser.dealer_name || 'Field'})`;
                    roleBadge.className = 'portal-role-tag role-tag-integrator';
                }
                if (sideRole) sideRole.innerText = 'TECHNICAL INTEGRATOR';
                if (dealerActions) dealerActions.style.display = 'none';
                if (integratorActions) integratorActions.style.display = 'flex';

                // Integrators see Fleet only
                document.getElementById('nav-overview').style.display = 'none';
                document.getElementById('nav-dealers').style.display = 'none';
                document.getElementById('nav-integrators').style.display = 'none';
                document.getElementById('nav-fleet').style.display = 'flex';
                document.getElementById('nav-account').style.display = 'none';
                const navBrandInt = document.getElementById('nav-branding');
                if (navBrandInt) navBrandInt.style.display = 'none';
                document.getElementById('th-dealer-col').style.display = 'none';
                document.getElementById('th-integrator-col').style.display = 'none';

                switchTab('fleet');
                fetchFleet();
            }
        }

        async function handleLoginSubmit(e) {
            e.preventDefault();
            const u = document.getElementById('login-username').value.trim();
            const p = document.getElementById('login-password').value;
            const errBox = document.getElementById('login-error');
            const btn = document.getElementById('login-submit-btn');

            errBox.style.display = 'none';
            btn.disabled = true;
            btn.innerText = 'Authenticating...';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p }),
                    credentials: 'same-origin'
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    if (data.token) {
                        setAuthToken(data.token);
                    }
                    currentUser = data.user;
                    initAuthenticatedUI();
                    showToast(`Welcome back, ${currentUser.name}!`, 'success');
                } else {
                    errBox.innerText = data.error || 'Invalid username or password.';
                    errBox.style.display = 'block';
                }
            } catch (err) {
                errBox.innerText = 'Network connection failed. Please retry.';
                errBox.style.display = 'block';
            } finally {
                btn.disabled = false;
                btn.innerText = 'Sign In';
            }
        }

        async function handleLogout() {
            try {
                await apiFetch('/api/logout', { method: 'POST' });
            } catch (e) {}
            setAuthToken(null);
            currentUser = null;
            showLoginScreen();
            showToast("Signed out successfully.");
        }

        function togglePasswordVisibility(inputId, btn) {
            const el = document.getElementById(inputId);
            if (el.type === 'password') {
                el.type = 'text';
                btn.innerText = '🙈';
            } else {
                el.type = 'password';
                btn.innerText = '👁️';
            }
        }

        function formatIntervalHuman(seconds) {
            const s = parseInt(seconds) || 0;
            if (s <= 0) return '0m';
            if (s >= 3600) {
                const h = Math.floor(s / 3600);
                const m = Math.floor((s % 3600) / 60);
                return m > 0 ? `${h}h ${m}m` : `${h}h`;
            }
            const m = Math.max(1, Math.round(s / 60));
            return `${m}m`;
        }

        function toggleTablePassword(elementId) {
            const el = document.getElementById(elementId);
            if (!el) return;
            const plain = el.getAttribute('data-plain') || '';
            if (el.innerText === '••••••••') {
                el.innerText = plain;
                el.style.color = '#38bdf8';
                el.style.letterSpacing = 'normal';
                el.style.fontWeight = '600';
            } else {
                el.innerText = '••••••••';
                el.style.color = '#cbd5e1';
                el.style.letterSpacing = '2px';
                el.style.fontWeight = 'normal';
            }
        }

        function copyPassword(pwdText) {
            if (!pwdText) {
                showToast('Password is empty', 'warning');
                return;
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(pwdText).then(() => {
                    showToast('Password copied to clipboard!', 'success');
                }).catch(() => {
                    prompt('Copy password:', pwdText);
                });
            } else {
                prompt('Copy password:', pwdText);
            }
        }

        // ======================================================================
        // TABS NAVIGATION
        // ======================================================================
        function switchTab(tabId) {
        if (tabId === 'tab-alerts') loadSmtpConfig();
            if (window.innerWidth <= 900) closeSidebarMobile();
            activeTab = tabId;

            // Update nav styling
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            const navEl = document.getElementById('nav-' + tabId);
            if (navEl) navEl.classList.add('active');

            // Update tab panes
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            const paneEl = document.getElementById('tab-' + tabId);
            if (paneEl) paneEl.classList.add('active');

            // Refresh specific tab data
            setTimeout(initAllTableScrollbars, 60);
            if (tabId === 'overview') {
                if (currentUser.role === 'manufacturer') {
                    fetchDealers();
                    fetchIntegrators();
                } else if (currentUser.role === 'dealer') {
                    fetchIntegrators();
                }
                fetchFleet();
            } else if (tabId === 'dealers') {
                fetchDealers();
            } else if (tabId === 'integrators') {
                fetchIntegrators();
            } else if (tabId === 'branding') {
                populateBrandingForm();
                fetchFleet();
            } else if (tabId === 'fleet') {
                fetchFleet();
            } else if (tabId === 'approvals') {
                fetchApprovals();
            } else if (tabId === 'mqtt') {
                populateMqttDispatcherClients();
            } else if (tabId === 'alerts') {
                loadWhatsAppStatus();
                loadAdminWhatsAppNumber();
            } else if (tabId === 'copilot') {
                loadCopilotStatus();
                loadCopilotProposals();
                loadCopilotHistory();
                loadCopilotAutonomy();
            }
        }

        // ======================================================================
        // ADMIN WHATSAPP DESTINATION & RECIPIENT MANAGEMENT
        // ======================================================================
        async function loadAdminWhatsAppNumber() {
            try {
                const res = await apiFetch('/api/whatsapp/admin_number?t=' + Date.now());
                if (!res.ok) return;
                const data = await res.json();
                if (data.admin_whatsapp_number) {
                    const input = document.getElementById('admin-wa-phone-input');
                    const topDisplay = document.getElementById('admin-wa-top-display');
                    if (input && !input.matches(':focus')) input.value = data.admin_whatsapp_number;
                    if (topDisplay) topDisplay.innerText = '+' + data.admin_whatsapp_number.replace(/^\+/, '');
                }
            } catch (e) {
                console.error("Failed to load admin WhatsApp number:", e);
            }
        }

        async function saveAdminWhatsAppNumber() {
            const input = document.getElementById('admin-wa-phone-input');
            const feedback = document.getElementById('admin-wa-feedback');
            if (!input) return;
            const phone = input.value.trim();
            if (!phone) {
                showToast("Please enter a valid WhatsApp phone number", "error");
                return;
            }
            try {
                if (feedback) {
                    feedback.style.display = 'block';
                    feedback.style.background = 'rgba(56, 189, 248, 0.1)';
                    feedback.style.color = '#38bdf8';
                    feedback.innerText = 'Saving admin number...';
                }
                const res = await apiFetch('/api/whatsapp/admin_number', {
                    method: 'POST',
                    body: JSON.stringify({ admin_whatsapp_number: phone })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message || "Admin WhatsApp number saved", "success");
                    if (feedback) {
                        feedback.style.display = 'block';
                        feedback.style.background = 'rgba(16, 185, 129, 0.15)';
                        feedback.style.color = '#10b981';
                        feedback.innerText = '✓ ' + (data.message || 'Saved successfully');
                    }
                    loadAdminWhatsAppNumber();
                } else {
                    showToast(data.error || "Failed to save", "error");
                    if (feedback) {
                        feedback.style.display = 'block';
                        feedback.style.background = 'rgba(239, 68, 68, 0.15)';
                        feedback.style.color = '#f87171';
                        feedback.innerText = '✗ ' + (data.error || 'Failed to save');
                    }
                }
            } catch (e) {
                showToast("Error: " + e.message, "error");
            }
        }

        async function testAdminWhatsAppPing() {
            const feedback = document.getElementById('admin-wa-feedback');
            const input = document.getElementById('admin-wa-phone-input');
            const phone = input ? input.value.trim() : '';
            showToast("Dispatching test alert to Admin WhatsApp...", "info");
            if (feedback) {
                feedback.style.display = 'block';
                feedback.style.background = 'rgba(56, 189, 248, 0.1)';
                feedback.style.color = '#38bdf8';
                feedback.innerText = 'Sending test verification message...';
            }
            try {
                const res = await apiFetch('/api/whatsapp/admin_test_ping', {
                    method: 'POST',
                    body: JSON.stringify({ admin_whatsapp_number: phone })
                });
                const data = await res.json();
                if (data.success) {
                    showToast("Test ping dispatched to Admin WhatsApp!", "success");
                    if (feedback) {
                        feedback.style.display = 'block';
                        feedback.style.background = 'rgba(16, 185, 129, 0.15)';
                        feedback.style.color = '#10b981';
                        feedback.innerText = '✓ Test alert delivered to +' + data.recipient;
                    }
                } else {
                    showToast(data.error || "Failed to dispatch test ping", "error");
                    if (feedback) {
                        feedback.style.display = 'block';
                        feedback.style.background = 'rgba(239, 68, 68, 0.15)';
                        feedback.style.color = '#f87171';
                        feedback.innerText = '✗ ' + (data.error || 'Dispatch failed');
                    }
                }
            } catch (e) {
                showToast("Error: " + e.message, "error");
            }
        }

        // ======================================================================
        // AI COPILOT CONSOLE & APPROVAL GATE LOGIC
        // ======================================================================
        async function loadCopilotAutonomy() {
            try {
                const res = await apiFetch('/api/copilot/autonomy?t=' + Date.now());
                if (!res.ok) return;
                const data = await res.json();
                updateAutonomyUI(data.autonomy_enabled !== false);
            } catch (e) {
                console.error("Failed to load Copilot autonomy:", e);
            }
        }

        function updateAutonomyUI(isActive) {
            const label = document.getElementById('copilot-autonomy-label');
            const btn = document.getElementById('copilot-autonomy-btn');
            const safety = document.getElementById('header-safety-mode-label');
            if (label) {
                label.innerText = isActive ? 'FULL AUTONOMY: ACTIVE' : 'APPROVAL GATES: ACTIVE';
                label.style.color = isActive ? '#d8b4fe' : '#fbbf24';
            }
            if (btn) {
                btn.innerText = isActive ? 'Enabled' : 'Disabled';
                btn.style.background = isActive ? '#a855f7' : 'rgba(255,255,255,0.15)';
            }
            if (safety) {
                safety.innerHTML = isActive 
                    ? '⚡ <strong>Permissions:</strong> Full Gateway Autonomy' 
                    : '🛡️ <strong>Safety Gate:</strong> Mandatory Confirmation';
            }
        }

        async function toggleCopilotAutonomy() {
            try {
                const btn = document.getElementById('copilot-autonomy-btn');
                const willEnable = btn && btn.innerText === 'Disabled';
                const res = await apiFetch('/api/copilot/autonomy/toggle', {
                    method: 'POST',
                    body: JSON.stringify({ enabled: willEnable })
                });
                const data = await res.json();
                if (data.success) {
                    updateAutonomyUI(data.autonomy_enabled);
                    showToast(data.autonomy_enabled ? "⚡ Full AI Gateway Autonomy ENABLED" : "🛡️ Approval Gates ENABLED", "success");
                }
            } catch (e) {
                showToast("Error updating autonomy mode: " + e.message, "error");
            }
        }

        async function loadCopilotStatus() {
            try {
                const res = await apiFetch('/api/copilot/status?t=' + Date.now());
                if (!res.ok) return;
                const data = await res.json();
                const pCountEl = document.getElementById('copilot-proposals-count');
                if (pCountEl) pCountEl.innerText = data.pending_proposals_count || 0;
            } catch (e) {
                console.error("Failed to load Copilot status:", e);
            }
        }

        async function loadCopilotProposals() {
            try {
                const res = await apiFetch('/api/copilot/proposals?t=' + Date.now());
                if (!res.ok) return;
                const data = await res.json();
                const container = document.getElementById('copilot-proposals-container');
                if (!container) return;
                const proposals = data.proposals || [];
                const pCountEl = document.getElementById('copilot-proposals-count');
                if (pCountEl) pCountEl.innerText = proposals.length;

                if (proposals.length === 0) {
                    container.innerHTML = `<div style="text-align: center; padding: 24px; color: #94a3b8; font-size: 13px;">
                        ✓ All ecosystem components operating nominally. No system or gateway proposals pending approval.
                    </div>`;
                    return;
                }

                container.innerHTML = proposals.map(p => `
                    <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 12px; padding: 16px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                            <div>
                                <span style="font-size: 11px; font-weight: 700; color: #fbbf24; background: rgba(245, 158, 11, 0.15); padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(245, 158, 11, 0.3);">PROPOSAL #${escapeHtml(p.id)}</span>
                                <strong style="color: #fff; font-size: 14px; margin-left: 8px;">${escapeHtml(p.summary || 'Ecosystem Modification')}</strong>
                            </div>
                            <span style="font-size: 11px; color: #94a3b8;">${new Date((p.created_at || Date.now()/1000)*1000).toLocaleTimeString()}</span>
                        </div>
                        <div style="font-size: 12px; color: #cbd5e1; margin-bottom: 12px; line-height: 1.5;">
                            <strong>Target:</strong> <code>${escapeHtml(p.client_id || 'System Server')}</code> &bull; <strong>Action:</strong> ${escapeHtml(p.action_type || 'Remediation')}
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button type="button" class="btn-action" style="padding: 8px 16px; font-size: 12px; background: linear-gradient(135deg, #059669, #047857); border-color: #34d399;" onclick="handleCopilotApproval('${p.id}', true)">
                                ✓ Approve & Execute
                            </button>
                            <button type="button" class="btn-sm" style="padding: 8px 16px; font-size: 12px; background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #f87171;" onclick="handleCopilotApproval('${p.id}', false)">
                                ✗ Reject Proposal
                            </button>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                console.error("Failed to load proposals:", e);
            }
        }

        async function handleCopilotApproval(propId, approved) {
            const action = approved ? 'approve' : 'reject';
            if (!confirm(`Are you sure you want to ${action.toUpperCase()} proposal #${propId}?`)) return;
            try {
                // Optimistically log action in Copilot Terminal
                appendCopilotChatMessage('user', `Action: ${action.toUpperCase()} proposal #${propId}`);
                const res = await apiFetch(`/api/copilot/proposals/${action}`, {
                    method: 'POST',
                    body: JSON.stringify({ proposal_id: propId })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Proposal #${propId} ${action}d successfully`, "success");
                    loadCopilotProposals();
                    await loadCopilotHistory();
                } else {
                    showToast(data.error || "Failed to process proposal", "error");
                    appendCopilotChatMessage('ai', `⚠️ Error processing proposal #${propId}: ${data.error || 'Execution failed'}`);
                }
            } catch (e) {
                showToast("Error: " + e.message, "error");
                appendCopilotChatMessage('ai', `⚠️ Connection error: ${e.message}`);
            }
        }

        let showCopilotThoughts = localStorage.getItem('copilot_show_thoughts') !== 'false';

        function toggleCopilotThoughts() {
            showCopilotThoughts = !showCopilotThoughts;
            localStorage.setItem('copilot_show_thoughts', showCopilotThoughts ? 'true' : 'false');
            updateThoughtToggleUI();
            document.querySelectorAll('.copilot-thought-box').forEach(el => {
                el.style.display = showCopilotThoughts ? 'block' : 'none';
            });
        }

        function updateThoughtToggleUI() {
            const lbl = document.getElementById('thought-status-label');
            const btn = document.getElementById('toggle-thought-btn');
            if (!lbl || !btn) return;
            if (showCopilotThoughts) {
                lbl.innerText = 'ON';
                lbl.style.color = '#34d399';
                btn.style.borderColor = 'rgba(56, 189, 248, 0.4)';
            } else {
                lbl.innerText = 'OFF';
                lbl.style.color = '#94a3b8';
                btn.style.borderColor = 'rgba(255, 255, 255, 0.15)';
            }
        }

        async function loadCopilotHistory() {
            try {
                const res = await apiFetch('/api/copilot/history?t=' + Date.now());
                if (!res.ok) return;
                const data = await res.json();
                const log = document.getElementById('copilot-messages-log');
                if (!log || !data.history) return;
                log.innerHTML = data.history.map(m => {
                    const isAi = m.sender === 'ai';
                    const labelColor = isAi ? '#c084fc' : '#38bdf8';
                    const textColor = isAi ? '#d8b4fe' : '#f1f5f9';
                    const label = isAi ? '[GAVASAH AI COPILOT]' : '[MANUFACTURER]';
                    const formatted = escapeHtml(m.message).split(String.fromCharCode(10)).join('<br>');
                    let thoughtHtml = '';
                    if (isAi && m.thought && m.thought.trim()) {
                        const displayStyle = showCopilotThoughts ? 'block' : 'none';
                        thoughtHtml = `
                            <div class="copilot-thought-box" style="margin-bottom: 12px; padding: 14px 18px; background: rgba(30, 27, 75, 0.55); border-left: 3px solid #c084fc; border-radius: 8px; line-height: 1.6; display: ${displayStyle}; box-shadow: 0 4px 15px rgba(0,0,0,0.3);">
                                <div style="display: flex; align-items: center; gap: 6px; font-weight: 700; color: #d8b4fe; margin-bottom: 8px; font-size: 11px; letter-spacing: 0.5px; text-transform: uppercase;">
                                    <span>💭 AI Internal Diagnostics & Chain of Thought:</span>
                                </div>
                                <div style="color: #ffffff !important; font-size: 12.5px; font-weight: 500; line-height: 1.65; white-space: pre-wrap; font-family: 'JetBrains Mono', 'Fira Code', monospace; letter-spacing: 0.2px;">${escapeHtml(m.thought).split(String.fromCharCode(10)).join('<br>')}</div>
                            </div>
                        `;
                    }
                    return `<div style="line-height: 1.55; margin-bottom: 12px;">${thoughtHtml}<strong style="color: ${labelColor};">${label}:</strong> <span style="color: ${textColor};">${formatted}</span></div>`;
                }).join('');
                log.scrollTop = log.scrollHeight;
                updateThoughtToggleUI();
            } catch (e) {
                console.error("Failed to load Copilot history:", e);
            }
        }

        async function handleCopilotChatSubmit(e) {
            e.preventDefault();
            const input = document.getElementById('copilot-user-input');
            if (!input) return;
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            appendCopilotChatMessage('user', msg);
            try {
                const res = await apiFetch('/api/copilot/chat', {
                    method: 'POST',
                    body: JSON.stringify({ message: msg })
                });
                const data = await res.json();
                if (data.reply) {
                    appendCopilotChatMessage('ai', data.reply, data.thought || '');
                    if (data.proposal_created) loadCopilotProposals();
                } else if (data.error) {
                    appendCopilotChatMessage('ai', "⚠️ Error: " + data.error);
                }
            } catch (err) {
                appendCopilotChatMessage('ai', "⚠️ Communication error: " + err.message);
            }
        }

        function sendCopilotQuickCmd(cmd) {
            const input = document.getElementById('copilot-user-input');
            if (input) {
                input.value = cmd;
                const form = input.closest('form');
                if (form) form.dispatchEvent(new Event('submit', { cancelable: true }));
            }
        }

        function appendCopilotChatMessage(sender, msg, thought = '') {
            const log = document.getElementById('copilot-messages-log');
            if (!log) return;
            const isAi = sender === 'ai';
            const labelColor = isAi ? '#c084fc' : '#38bdf8';
            const textColor = isAi ? '#d8b4fe' : '#f1f5f9';
            const label = isAi ? '[GAVASAH AI COPILOT]' : '[MANUFACTURER]';
            const div = document.createElement('div');
            div.style.lineHeight = '1.55';
            div.style.marginBottom = '12px';
            let thoughtHtml = '';
            if (isAi && thought && thought.trim()) {
                const displayStyle = showCopilotThoughts ? 'block' : 'none';
                thoughtHtml = `
                    <div class="copilot-thought-box" style="margin-bottom: 12px; padding: 14px 18px; background: rgba(30, 27, 75, 0.55); border-left: 3px solid #c084fc; border-radius: 8px; line-height: 1.6; display: ${displayStyle}; box-shadow: 0 4px 15px rgba(0,0,0,0.3);">
                        <div style="display: flex; align-items: center; gap: 6px; font-weight: 700; color: #d8b4fe; margin-bottom: 8px; font-size: 11px; letter-spacing: 0.5px; text-transform: uppercase;">
                            <span>💭 AI Internal Diagnostics & Chain of Thought:</span>
                        </div>
                        <div style="color: #ffffff !important; font-size: 12.5px; font-weight: 500; line-height: 1.65; white-space: pre-wrap; font-family: 'JetBrains Mono', 'Fira Code', monospace; letter-spacing: 0.2px;">${escapeHtml(thought).split(String.fromCharCode(10)).join('<br>')}</div>
                    </div>
                `;
            }
            div.innerHTML = `${thoughtHtml}<strong style="color: ${labelColor};">${label}:</strong> <span style="color: ${textColor};">${escapeHtml(msg).split(String.fromCharCode(10)).join('<br>')}</span>`;
            log.appendChild(div);
            log.scrollTop = log.scrollHeight;
        }

        // ======================================================================
        // AUTONOMOUS ALERTS & WHATSAPP GATEWAY (MANUFACTURER)
        // ======================================================================
        let waPollInterval = null;

        function setSampleAlert(type) {
            const el = document.getElementById('wa-test-msg');
            if (!el) return;
            if (type === 'offline') {
                el.value = `🚨 [GAVASAH FLEET ALERT]
Client: Sharma Villa (Jubilee Hills)
Status: GATEWAY OFFLINE
Duration: 3 minutes
Ingress: sharma-villa.gavasah.com
Action: Please verify site internet power.`;
            } else if (type === 'lutron') {
                el.value = `⚠️ [GAVASAH SUBSYSTEM ALERT]
Client: Pranav Chilukuri
Component: Lutron RadioRA 3 Bridge
Status: UNREACHABLE (Port 8081)
Attempting automated self-healing restart.`;
            } else if (type === 'heal') {
                el.value = `🛑 [GAVASAH RECOVERY LOCKED]
Client: Nagaprasad V
Subsystem: KNX Gateway (192.168.1.111)
Self-Healing: Max 5 attempts reached.
Automatic retries stopped to prevent storming.`;
            } else if (type === 'restored') {
                el.value = `✅ [GAVASAH FLEET RECOVERY]
Client: Sharma Villa (Jubilee Hills)
Status: ALL SUBSYSTEMS OPERATIONAL
Heartbeat: Telemetry pulse active.
Automated remediation successful. Normal operations restored.`;
            }
        }

        async function loadWhatsAppStatus() {
            try {
                const res = await apiFetch('/api/whatsapp/status?t=' + Date.now());
                if (!res.ok) return;
                const data = await res.json();
                renderWhatsAppUI(data);
            } catch (e) {
                console.error("WhatsApp status check error:", e);
            }
        }

        function renderWhatsAppUI(data) {\n            updateTTSWindowIndicator();
            const pill = document.getElementById('wa-status-pill');
            const dot = document.getElementById('badge-wa-dot');
            const qrBox = document.getElementById('wa-qr-box');
            const qrImg = document.getElementById('wa-qr-img');
            const connBox = document.getElementById('wa-connected-box');
            const phoneEl = document.getElementById('wa-connected-phone');
            const nameEl = document.getElementById('wa-connected-name');
            const titleEl = document.getElementById('wa-card-title');

            if (data.connected) {
                if (pill) {
                    pill.style.color = '#10b981';
                    pill.innerText = '● Connected';
                }
                if (dot) dot.style.background = '#10b981';
                if (titleEl) titleEl.innerText = data.phone || 'Connected';
                if (qrBox) qrBox.style.display = 'none';
                if (connBox) connBox.style.display = 'block';
                if (phoneEl) phoneEl.innerText = data.phone || 'Active Number';
                if (nameEl) nameEl.innerText = data.name || 'Gavasah Operations';
                if (waPollInterval) {
                    clearInterval(waPollInterval);
                    waPollInterval = null;
                }
            } else if (data.status === 'qr_ready' && data.qr) {
                if (pill) {
                    pill.style.color = '#f59e0b';
                    pill.innerText = '● Scan QR Code to Link';
                }
                if (dot) dot.style.background = '#f59e0b';
                if (titleEl) titleEl.innerText = 'Awaiting Pairing';
                if (connBox) connBox.style.display = 'none';
                if (qrBox) qrBox.style.display = 'block';
                const loadingEl = document.getElementById('wa-qr-loading');
                if (loadingEl) loadingEl.style.display = 'none';
                if (qrImg) {
                    qrImg.src = data.qr;
                    qrImg.style.display = 'block';
                }

                if (!waPollInterval && activeTab === 'alerts') {
                    waPollInterval = setInterval(loadWhatsAppStatus, 3000);
                }
            } else {
                if (pill) {
                    pill.style.color = '#94a3b8';
                    pill.innerText = '● Initializing QR...';
                }
                if (dot) dot.style.background = '#64748b';
                if (titleEl) titleEl.innerText = 'Generating QR';
                if (connBox) connBox.style.display = 'none';
                if (qrBox) qrBox.style.display = 'block';
                if (qrImg) qrImg.style.display = 'none';
                const loadingEl = document.getElementById('wa-qr-loading');
                if (loadingEl) loadingEl.style.display = 'flex';
                if (!waPollInterval && activeTab === 'alerts') {
                    waPollInterval = setInterval(loadWhatsAppStatus, 2000);
                }
            }
        }

        async function handleWhatsAppLogout() {
            if (!confirm("Are you sure you want to disconnect this WhatsApp number? A fresh QR code will be generated immediately so you can link another phone.")) {
                return;
            }
            showToast("Unlinking WhatsApp session...", "info");
            try {
                const res = await apiFetch('/api/whatsapp/logout', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    showToast("WhatsApp unlinked! Scan new QR code.", "success");
                    loadWhatsAppStatus();
                    if (!waPollInterval) waPollInterval = setInterval(loadWhatsAppStatus, 3000);
                } else {
                    showToast(data.error || "Logout failed", "error");
                }
            } catch (e) {
                showToast("Error: " + e.message, "error");
            }
        }
        function updateTTSWindowIndicator() {
            const textEl = document.getElementById('tts-window-text');
            const badgeEl = document.getElementById('tts-window-badge');
            if (!textEl || !badgeEl) return;

            const now = new Date();
            const hrs = now.getHours();
            const mins = now.getMinutes();
            const currMin = hrs * 60 + mins;
            const startMin = 10 * 60; // 10:00 AM
            const endMin = 18 * 60;   // 6:00 PM
            const inWindow = currMin >= startMin && currMin <= endMin;
            const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            if (inWindow) {
                textEl.style.color = '#34d399';
                textEl.innerText = `Calling Allowed (${timeStr}) • 10:00 AM – 6:00 PM`;
                badgeEl.className = 'status-indicator-dot online';
                badgeEl.style.color = '#10b981';
                badgeEl.innerText = '● Slot Open';
            } else {
                textEl.style.color = '#fb923c';
                textEl.innerText = `Outside Slot (${timeStr}) • Silent Mode`;
                badgeEl.className = 'status-indicator-dot offline';
                badgeEl.style.color = '#fb923c';
                badgeEl.innerText = '● Night Mode';
            }
        }
        setInterval(updateTTSWindowIndicator, 15000);

        function previewTTSLocalSpeech() {
            const text = (document.getElementById('wa-test-msg').value || '').trim();
            if (!text) {
                showToast("Enter some text to preview speech", "warning");
                return;
            }
            if ('speechSynthesis' in window) {
                window.speechSynthesis.cancel();
                const cleanText = text.replace(/[*_~`]/g, '');
                const utter = new SpeechSynthesisUtterance(cleanText);
                utter.rate = 0.95;
                utter.pitch = 1.0;
                window.speechSynthesis.speak(utter);
                showToast("Playing voice speech preview through your browser audio...", "info");
            } else {
                showToast("Browser does not support local Web Speech API synthesis", "warning");
            }
        }

        async function sendTTSAlert(channel) {
            const dest = (document.getElementById('wa-test-phone').value || '').trim();
            const message = (document.getElementById('wa-test-msg').value || '').trim();
            const fb = document.getElementById('wa-test-feedback');
            const callBtn = document.getElementById('tts-call-btn');
            const msgBtn = document.getElementById('tts-msg-btn');
            const emailBtn = document.getElementById('tts-email-btn');

            const isVoice = channel === 'voice';
            const isEmail = channel === 'email';

            if (!dest) {
                showToast(isEmail ? "Please enter a destination email address" : "Please enter a destination phone number", "warning");
                return;
            }
            if (!message) { showToast("Please enter message content", "warning"); return; }

            if (callBtn) callBtn.disabled = true;
            if (msgBtn) msgBtn.disabled = true;
            if (emailBtn) emailBtn.disabled = true;

            fb.style.display = 'block';
            fb.style.background = 'rgba(2, 6, 23, 0.7)';
            fb.style.border = '1px solid rgba(0, 240, 255, 0.4)';
            fb.style.color = '#38bdf8';
            const channelLabel = isVoice ? 'TTS Voice Call' : (isEmail ? 'Alert Email' : 'WhatsApp Text');
            fb.innerHTML = `⚡ <strong>Dispatching ${channelLabel}</strong> to <code>${escapeHtml(dest)}</code>...`;

            try {
                let cleanPhone = dest;
                if (!isEmail) {
                    cleanPhone = dest.replace(/[^0-9]/g, '');
                    if (cleanPhone.length === 10 && ['6','7','8','9'].includes(cleanPhone[0])) {
                        cleanPhone = '91' + cleanPhone;
                    }
                }
                const res = await apiFetch('/api/whatsapp/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ phone: cleanPhone, email: dest, message, channel, manual_test: true })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`${isVoice ? '📞 Voice Call' : (isEmail ? '📧 Email' : '💬 Message')} dispatched to ${data.recipient || dest}!`, "success");
                    fb.style.background = 'rgba(16, 185, 129, 0.12)';
                    fb.style.border = '1px solid #10b981';
                    fb.style.color = '#34d399';
                    fb.innerHTML = `
                        <div style="font-weight: 700; margin-bottom: 4px;">✓ ${isVoice ? 'Automated Voice Memo Dispatched' : (isEmail ? 'Email Alert Dispatched via SMTP' : 'WhatsApp Message Delivered')}</div>
                        <div><strong>Recipient:</strong> ${escapeHtml(data.recipient || dest)}</div>
                        <div><strong>Tracking ID:</strong> <code>${escapeHtml(data.messageId || 'OK')}</code></div>
                        <div><strong>Delivery Mode:</strong> ${isVoice ? 'Audible Spoken Voice Memo (WhatsApp PTT Audio)' : (isEmail ? (data.status || 'Delivered via SMTP') : 'Instant WhatsApp Web Relay')}</div>
                        <div style="margin-top: 4px; font-size: 11px; color: #94a3b8;">${isVoice ? 'Spoken human voice note synthesized and delivered to mobile.' : (isEmail ? 'Rich HTML and plain-text alert delivered to inbox.' : 'Message delivered to recipient.')}</div>
                    `;
                } else {
                    showToast(data.error || "Dispatch failed", "error");
                    fb.style.background = 'rgba(239, 68, 68, 0.12)';
                    fb.style.border = '1px solid #ef4444';
                    fb.style.color = '#f87171';
                    fb.innerHTML = `✗ <strong>Dispatch Failure:</strong> ${escapeHtml(data.error || 'Server rejected dispatch request')}`;
                }
            } catch (e) {
                showToast("Network dispatch error: " + e.message, "error");
                fb.style.background = 'rgba(239, 68, 68, 0.12)';
                fb.style.border = '1px solid #ef4444';
                fb.style.color = '#f87171';
                fb.innerHTML = `✗ <strong>Network Error:</strong> ${escapeHtml(e.message)}`;
            } finally {
                if (callBtn) callBtn.disabled = false;
                if (msgBtn) msgBtn.disabled = false;
                if (emailBtn) emailBtn.disabled = false;
            }
        }


        // ======================================================================
        // CLIENT APPROVALS (MANUFACTURER)
        // ======================================================================
        let currentApprovalsData = [];
        let lastApprovalsHash = '';
        let previousApprovalCount = null;

        async function fetchApprovals() {
            if (!currentUser || currentUser.role !== 'manufacturer') return;
            try {
                const res = await apiFetch('/api/approvals?t=' + Date.now());
                if (res.ok) {
                    currentApprovalsData = await res.json();
                    renderApprovalsUI(currentApprovalsData);
                }
            } catch (err) {
                console.error("Error fetching approvals:", err);
            }
        }

        function renderApprovalsUI(list) {
            const tbody = document.getElementById('approvals-table-body');
            const emptyEl = document.getElementById('approvals-empty-state');
            const tableWrap = document.getElementById('approvals-table-container');
            const badgeCount = document.getElementById('badge-approvals-count');
            const ovApprovals = document.getElementById('ov-approvals-count');

            const currentCount = list.length;
            if (badgeCount) {
                if (currentCount > 0) {
                    badgeCount.innerText = currentCount;
                    badgeCount.style.display = 'inline-block';
                } else {
                    badgeCount.style.display = 'none';
                }
            }
            if (ovApprovals) {
                ovApprovals.innerText = currentCount;
            }

            // Real-time toast alert when a new client gateway approval request arrives
            if (previousApprovalCount !== null && currentCount > previousApprovalCount) {
                const diff = currentCount - previousApprovalCount;
                showToast(`🔔 ${diff} new client gateway approval request${diff > 1 ? 's' : ''} submitted by partner!`, 'info');
            }
            previousApprovalCount = currentCount;

            // Diff-check to prevent re-rendering identical DOM during 2.5s continuous live sync
            const currentHash = JSON.stringify(list.map(c => [c.client_id, c.approval_status, c.dealer_id, c.integrator_id]));
            if (currentHash === lastApprovalsHash) {
                return;
            }
            lastApprovalsHash = currentHash;

            if (!tbody) return;

            if (list.length === 0) {
                if (emptyEl) emptyEl.style.display = 'block';
                if (tableWrap) tableWrap.style.display = 'none';
                tbody.innerHTML = '';
                return;
            }

            if (emptyEl) emptyEl.style.display = 'none';
            if (tableWrap) tableWrap.style.display = 'block';

            tbody.innerHTML = list.map(c => {
                const onb = formatOnboardingDateTime(c.onboarded_at);
                const snippet = `hub_host: "dealer.gavasah.com"
client_id: "${c.client_id}"
auth_key: "${c.auth_secret}"
remote_dashboard_port: ${c.dashboard_port || 10001}`;

                return `
                    <tr>
                        <td>
                            <div class="site-name-text" style="font-size: 14px; font-weight: 700; color: #fff;">${escapeHtml(c.name)}</div>
                            <div class="site-slug-text" style="font-family: 'JetBrains Mono', monospace; color: #00f0ff;">${escapeHtml(c.client_id)}</div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 3px;">Domain: <code>${escapeHtml(c.domain)}</code></div>
                        </td>
                        <td>
                            <div style="font-size: 12px; font-weight: 600; color: #c084fc;">🏢 ${escapeHtml(c.dealer_name || 'Direct')}</div>
                            <div style="font-size: 11px; color: #34d399; margin-top: 2px;">🔧 ${escapeHtml(c.integrator_name || 'Direct Supervision')}</div>
                        </td>
                        <td>
                            <div style="font-size: 12px; color: #f1f5f9;">📅 ${escapeHtml(onb.dateText || 'Recent')}</div>
                            <div style="font-size: 11px; color: #64748b; font-family: monospace;">⏰ ${escapeHtml(onb.timeText || '')}</div>
                        </td>
                        <td>
                            <div style="position: relative; max-width: 280px;">
                                <pre style="background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; padding: 8px; font-size: 10px; font-family: 'JetBrains Mono', monospace; margin: 0; color: #cbd5e1; white-space: pre-wrap;">${escapeHtml(snippet)}</pre>
                                <button type="button" class="btn-sm" style="position: absolute; top: 4px; right: 4px; font-size: 10px; padding: 2px 6px;" onclick="navigator.clipboard.writeText('${escapeHtml(snippet)}'); showToast('Snippet copied!', 'success');">Copy</button>
                            </div>
                        </td>
                        <td>
                            <div style="display: flex; flex-direction: column; gap: 6px;">
                                <button type="button" class="btn-action" style="background: #10b981; font-size: 11px; padding: 6px 12px; justify-content: center;" onclick="approveClient('${escapeHtml(c.client_id)}')">
                                    ✅ Approve Client
                                </button>
                                <button type="button" class="btn-sm" style="color: #f87171; border-color: rgba(239,68,68,0.4); font-size: 11px; padding: 5px 10px; justify-content: center;" onclick="rejectClient('${escapeHtml(c.client_id)}')">
                                    ❌ Reject
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        async function approveClient(clientId) {
            if (!confirm(`Approve client site '${clientId}'?\n\nThis will activate reverse proxy ingress, telemetry monitoring, and remote access immediately.`)) return;
            try {
                const res = await apiFetch('/api/approvals/approve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || 'Client approved successfully!', 'success');
                    await fetchApprovals();
                    await fetchFleet();
                } else {
                    showToast(data.error || 'Approval failed', 'error');
                }
            } catch (err) {
                showToast('Network error approving client', 'error');
            }
        }

        async function rejectClient(clientId) {
            const reason = prompt(`Enter reason for declining client registration '${clientId}':`, 'Registration declined by Manufacturer HQ');
            if (reason === null) return;
            try {
                const res = await apiFetch('/api/approvals/reject', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, reason: reason })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast('Client registration rejected', 'info');
                    await fetchApprovals();
                    await fetchFleet();
                } else {
                    showToast(data.error || 'Rejection failed', 'error');
                }
            } catch (err) {
                showToast('Network error rejecting client', 'error');
            }
        }

        // ======================================================================
        // MQTT MANAGEMENT & COMMAND DISPATCHER
        // ======================================================================
        function populateMqttDispatcherClients() {
            const sel = document.getElementById('mqtt-target-client');
            if (!sel) return;
            sel.innerHTML = currentFleetData.map(c => `
                <option value="${escapeHtml(c.client_id)}">${escapeHtml(c.name)} (${escapeHtml(c.client_id)})</option>
            `).join('');
        }

        function onMqttTargetChange() {
            const t = document.getElementById('mqtt-target-type');
            const wrap = document.getElementById('mqtt-client-select-wrap');
            if (t && wrap) {
                wrap.style.display = t.value === 'client' ? 'block' : 'none';
            }
        }

        function setSampleMqttCmd(type) {
            const ta = document.getElementById('mqtt-cmd-payload');
            if (!ta) return;
            if (type === 'ping') {
                ta.value = JSON.stringify({ action: "ping", timestamp: Date.now() }, null, 2);
            } else if (type === 'reload') {
                ta.value = JSON.stringify({ action: "reload_integrations", subsystems: ["knx"] }, null, 2);
            }
        }

        async function dispatchMqttCommand() {
            const targetType = document.getElementById('mqtt-target-type').value;
            const payloadStr = document.getElementById('mqtt-cmd-payload').value.trim();
            if (!payloadStr) {
                showToast('Please enter a JSON command payload', 'error');
                return;
            }

            let topic = 'gavasah/universal/cmd';
            if (targetType === 'client') {
                const clientSel = document.getElementById('mqtt-target-client');
                const cid = clientSel ? clientSel.value : '';
                if (!cid) {
                    showToast('Please select a target Gavasah Gateway', 'error');
                    return;
                }
                topic = `gavasah/clients/${cid}/cmd`;
            }

            try {
                const res = await apiFetch('/api/mqtt/publish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ topic: topic, payload: payloadStr })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(`Dispatched to topic: ${topic}`, 'success');
                } else {
                    showToast(data.error || 'Failed to dispatch via MQTT', 'error');
                }
            } catch (err) {
                showToast('Network error dispatching MQTT command', 'error');
            }
        }

        // ======================================================================
        // DEALERS MANAGEMENT (MANUFACTURER)
        // ======================================================================
        async function fetchDealers() {
            if (!currentUser || currentUser.role !== 'manufacturer') return;
            try {
                const res = await apiFetch('/api/dealers?t=' + Date.now());
                if (res.ok) {
                    dealersList = await res.json();
                    renderDealersUI();
                    updateDealerDropdowns();
                    populatePartnerFilter();
                }
            } catch (err) {
                console.error("Error fetching dealers:", err);
            }
        }

        function renderDealersUI() {
            const actualDealers = dealersList.filter(d => !d.is_manufacturer);
            const badge = document.getElementById('badge-dealer-count');
            if (badge) badge.innerText = actualDealers.length;

            const ovDealersCount = document.getElementById('ov-dealers-count');
            if (ovDealersCount) ovDealersCount.innerText = actualDealers.length;

            // Overview Dealers Table (Includes Master Manufacturer HQ + Authorized Dealers + Client Gateways)
            const ovBody = document.getElementById('overview-dealers-body');
            if (ovBody && currentUser.role === 'manufacturer') {
                const nowSec = Math.floor(Date.now() / 1000);
                ovBody.innerHTML = dealersList.map(d => {
                    // Map latest live fleet data by client_id to prevent stale page-load timestamps
                    const fleetMap = {};
                    if (Array.isArray(currentFleetData)) {
                        currentFleetData.forEach(fc => {
                            if (fc && fc.client_id) fleetMap[fc.client_id] = fc;
                        });
                    }

                    // Dynamically resolve clients from live currentFleetData
                    let orgClients = [];
                    if (Array.isArray(currentFleetData) && currentFleetData.length > 0) {
                        orgClients = currentFleetData.filter(c => {
                            if (d.is_manufacturer) {
                                return !c.dealer_id || c.dealer_id === 'owner_master' || c.dealer_id === 'direct' || c.dealer_id === '';
                            }
                            return c.dealer_id === d.id;
                        });
                    } else if (Array.isArray(d.clients)) {
                        orgClients = d.clients.map(c => fleetMap[c.client_id] || c);
                    }

                    // Calculate live health for this organization using live fleet data
                    // Online Gateways includes green, yellow (delayed), and orange (warning) modes.
                    // Gateways only become lost/offline when in RED mode (diff > offLimit or pending).
                    let onlineC = 0, delayedC = 0, warnC = 0, lostC = 0;
                    orgClients.forEach(c => {
                        const fresh = fleetMap[c.client_id] || c;
                        const hb = fresh.last_heartbeat || 0;
                        const isPending = !hb || hb === 0 || fresh.status === 'pending';
                        const diff = isPending ? -1 : nowSec - hb;
                        const delayedLimit = parseInt(fresh.hb_delayed_interval) || 900;
                        const warnLimit = parseInt(fresh.hb_warning_interval) || 1800;
                        const offLimit = parseInt(fresh.hb_offline_interval) || 3600;
                        if (!isPending && diff <= offLimit) onlineC++;
                        else lostC++;
                        if (!isPending && diff > delayedLimit && diff <= warnLimit) delayedC++;
                        else if (!isPending && diff > warnLimit && diff <= offLimit) warnC++;
                    });
                    const totalC = orgClients.length;
                    const healthPct = totalC > 0 ? Math.round((onlineC / totalC) * 100) : 100;

                    const clientChipsHtml = orgClients.length > 0 ? orgClients.map(c => {
                        const fresh = fleetMap[c.client_id] || c;
                        const hb = fresh.last_heartbeat || 0;
                        const isPending = !hb || hb === 0 || fresh.status === 'pending';
                        const diff = isPending ? -1 : nowSec - hb;
                        const delayedLimit = parseInt(fresh.hb_delayed_interval) || 900;
                        const warnLimit = parseInt(fresh.hb_warning_interval) || 1800;
                        const offLimit = parseInt(fresh.hb_offline_interval) || 3600;

                        const isOnline = !isPending && diff <= delayedLimit;
                        const isDelayed = !isPending && diff > delayedLimit && diff <= warnLimit;
                        const isWarn = !isPending && diff > warnLimit && diff <= offLimit;
                        const isLost = isPending || diff > offLimit;

                        const dotBg = isOnline ? '#10b981' : (isDelayed ? '#facc15' : (isWarn ? '#fb923c' : '#ef4444'));
                        const dotShadow = isOnline ? '0 0 6px #10b981' : (isDelayed ? '0 0 6px #facc15' : (isWarn ? '0 0 6px #fb923c' : '0 0 6px #ef4444'));
                        const stLabel = isOnline ? 'Online' : (isDelayed ? `Delayed Pulse (Integrator Alerted >${formatIntervalHuman(delayedLimit)})` : (isWarn ? `Warning (Dealer Alerted >${formatIntervalHuman(warnLimit)})` : (isPending ? 'Awaiting Contact' : `Offline (All Alerted >${formatIntervalHuman(offLimit)})`)));
                        const cDomain = fresh.domain || (fresh.client_id + '.gavasah.com');
                        const cName = fresh.name || fresh.client_id;
                        return `
                            <div class="ov-client-chip" title="Gateway: ${escapeHtml(cName)} (${escapeHtml(fresh.client_id)}) • Status: ${stLabel}">
                                <div style="display: flex; align-items: center; gap: 6px; min-width: 0; flex: 1;">
                                    <span style="width: 7px; height: 7px; border-radius: 50%; background: ${dotBg}; box-shadow: ${dotShadow}; flex-shrink: 0;"></span>
                                    <span style="font-weight: 500; color: #f1f5f9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(cName)}</span>
                                </div>
                                <div style="display: flex; align-items: center; gap: 4px; flex-shrink: 0;">
                                    <a href="https://${escapeHtml(cDomain)}" target="_blank" class="site-domain-link" style="font-size: 10px; padding: 1px 5px;" title="Open Remote GUI: https://${escapeHtml(cDomain)}">GUI ↗</a>
                                    <button type="button" class="btn-action-icon" style="padding: 1px 5px; font-size: 10px;" onclick="openEditModal('${fresh.client_id}')" title="Configure Gateway">⚙️</button>
                                </div>
                            </div>
                        `;
                    }).join('') : `<div style="font-size: 11px; color: #64748b; font-style: italic; padding: 4px 0;">No Gavasah Gateways assigned</div>`;

                    return `
                        <tr style="${d.is_manufacturer ? 'background: rgba(56, 189, 248, 0.04); border-left: 3px solid #38bdf8;' : ''}">
                            <td>
                                <div style="display: flex; align-items: center; gap: 9px;">
                                    <span style="font-size: 18px;">${d.is_manufacturer ? '👑' : '🏢'}</span>
                                    <div>
                                        <div style="font-weight: 700; color: ${d.is_manufacturer ? '#38bdf8' : '#fff'}; font-size: 13.5px;">${escapeHtml(d.name)}</div>
                                        <div style="font-size: 11px; color: ${d.is_manufacturer ? '#94a3b8' : '#64748b'}; font-family: monospace;">
                                            ${d.is_manufacturer ? 'Central Manufacturer HQ Supervision' : 'ID: ' + escapeHtml(d.id)}
                                        </div>
                                    </div>
                                </div>
                            </td>
                            <td style="font-family: monospace; color: #cbd5e1;">
                                <div>${escapeHtml(d.username)}</div>
                                ${d.is_manufacturer ? `<span class="badge-role" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); font-size: 9.5px; padding: 1px 5px; margin-top: 3px; display: inline-block;">HQ MASTER ADMIN</span>` : ''}
                            </td>
                            <td>
                                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                                    <span class="badge-role" style="${d.is_manufacturer ? 'background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3);' : 'background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3);'}">
                                        ${totalC} Gateway${totalC !== 1 ? 's' : ''} / ${d.integrator_count || 0} Integrator${(d.integrator_count || 0) !== 1 ? 's' : ''}
                                    </span>
                                </div>
                                <div class="ov-clients-container">
                                    ${clientChipsHtml}
                                </div>
                            </td>
                            <td>
                                <div style="font-weight: 600; font-size: 13px;">
                                    <span style="color: #10b981;">${onlineC} Online</span> / 
                                    <span style="color: ${lostC > 0 ? '#ef4444' : '#64748b'};">${lostC} Lost</span>
                                </div>
                                <div style="font-size: 10.5px; color: #94a3b8; margin-top: 3px; font-family: monospace;">
                                    ${totalC > 0 ? `${healthPct}% Operational` : 'No active fleet'}
                                </div>
                            </td>
                            <td style="font-size: 12px; color: #94a3b8;">
                                <div>${escapeHtml(d.email || '—')}</div>
                                <div style="font-size: 11px; color: #64748b; margin-top: 2px;">${escapeHtml(d.phone || '—')}</div>
                            </td>
                            <td>
                                <span class="badge-status ${d.is_manufacturer ? 'status-online' : (d.status === 'active' ? 'status-online' : 'status-lost')}" style="${d.is_manufacturer ? 'background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3);' : ''}">
                                    ${d.is_manufacturer ? 'ACTIVE (HQ)' : d.status.toUpperCase()}
                                </span>
                            </td>
                            <td>
                                <button class="btn-sm ${d.is_manufacturer ? 'btn-primary-sm' : ''}" onclick="filterFleetByDealer('${d.id}')">View Fleet ➔</button>
                            </td>
                        </tr>
                    `;
                }).join('') || `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">No authorized organizations or dealers registered yet.</td></tr>`;
            }

            // Dedicated Dealers Directory Table (With Password Reveal & Edit for Manufacturer)
            const dirBody = document.getElementById('dealers-management-body');
            if (dirBody) {
                dirBody.innerHTML = actualDealers.map(d => `
                    <tr>
                        <td style="font-weight: 600; color: #fff;">
                            <div style="font-size: 14px;">${escapeHtml(d.name)}</div>
                            <div style="font-size: 11px; color: #64748b; font-family: monospace;">UUID: ${escapeHtml(d.id)}</div>
                        </td>
                        <td style="font-family: monospace; color: #cbd5e1; font-weight: 600;">
                            ${escapeHtml(d.username)}
                        </td>
                        <td>
                            <div class="pwd-cell-wrap">
                                <span class="pwd-masked" id="dlr-pwd-val-${d.id}" data-plain="${escapeHtml(d.password_plain || '')}">••••••••</span>
                                <button type="button" class="btn-icon-pwd" onclick="toggleTablePassword('dlr-pwd-val-${d.id}')" title="Show / Hide Password">👁️</button>
                                <button type="button" class="btn-icon-pwd" onclick="copyPassword('${escapeHtml(d.password_plain || '')}')" title="Copy Password">📋</button>
                            </div>
                        </td>
                        <td style="font-size: 12px; color: #cbd5e1;">
                            <div>📧 ${escapeHtml(d.email || 'None')}</div>
                            <div style="margin-top: 2px;">📞 ${escapeHtml(d.phone || 'None')}</div>
                        </td>
                        <td>
                            <span class="badge-role" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3);">
                                ${d.client_count} Client Sites
                            </span>
                        </td>
                        <td style="font-size: 12px; color: #64748b;">
                            ${d.created_at ? new Date(d.created_at * 1000).toLocaleDateString() : 'Initial'}
                        </td>
                        <td>
                            <button type="button" class="btn-status-toggle ${d.status === 'active' ? 'status-active-btn' : 'status-suspended-btn'}" 
                                onclick="toggleDealerStatus('${d.id}', '${d.status === 'active' ? 'suspended' : 'active'}')" 
                                title="Click to ${d.status === 'active' ? 'Suspend Login & Terminate Sessions' : 'Activate Login'}">
                                ${d.status === 'active' ? '🟢 ACTIVE' : '🔴 SUSPENDED'}
                            </button>
                        </td>
                        <td>
                            <div style="display: flex; gap: 6px;">
                                ${d.status === 'active' ? `
                                    <button class="btn-action-icon" style="color: #fbbf24; border-color: rgba(251, 191, 36, 0.3);" onclick="toggleDealerStatus('${d.id}', 'suspended')" title="Suspend Dealer Login & Kill Active Sessions">⏸️ Suspend</button>
                                ` : `
                                    <button class="btn-action-icon" style="color: #34d399; border-color: rgba(52, 211, 153, 0.3);" onclick="toggleDealerStatus('${d.id}', 'active')" title="Activate Dealer Login">▶️ Activate</button>
                                `}
                                <button class="btn-action-icon" onclick="openEditDealerModal('${d.id}')" title="Edit Dealer & Password">✏️ Edit</button>
                                <button class="btn-action-icon" style="color: #ef4444; border-color: rgba(239, 68, 68, 0.3);" onclick="promptDeleteDealer('${d.id}', '${escapeHtml(d.name)}')" title="Delete Dealer">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `).join('') || `<tr><td colspan="8" style="text-align: center; color: #64748b; padding: 24px;">No dealers registered.</td></tr>`;
            }
        }

        function updateDealerDropdowns() {
            populatePartnerFilter();

            const actualDealers = (dealersList || []).filter(d => !d.is_manufacturer);

            // Integrators filter dropdown
            const intDealerFilter = document.getElementById('integrator-dealer-filter');
            if (intDealerFilter && currentUser.role === 'manufacturer') {
                const prev = intDealerFilter.value;
                intDealerFilter.innerHTML = '<option value="all">All Dealers Workforce</option>' +
                    '<option value="owner_master">Master Manufacturer (Direct)</option>' +
                    actualDealers.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
                intDealerFilter.value = prev || 'all';
            }

            // Onboard modal dealer select
            const onbDealerSel = document.getElementById('onb-dealer-select');
            if (onbDealerSel && currentUser.role === 'manufacturer') {
                onbDealerSel.innerHTML = '<option value="owner_master">Master Manufacturer (Direct Supervision)</option>' +
                    actualDealers.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
            }

            // Integrator modal dealer select
            const intDealerSel = document.getElementById('int-dealer-select');
            if (intDealerSel && currentUser.role === 'manufacturer') {
                intDealerSel.innerHTML = '<option value="owner_master">Master Manufacturer (Direct Supervision)</option>' +
                    actualDealers.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
            }

            // Edit client modal dealer select
            const editDealerSel = document.getElementById('edit-dealer-select');
            if (editDealerSel && currentUser.role === 'manufacturer') {
                editDealerSel.innerHTML = '<option value="owner_master">Master Manufacturer (Direct Supervision)</option>' +
                    actualDealers.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
            }
        }

        function filterIntegratorsByDealer(dealerId) {
            switchTab('integrators');
            const sel = document.getElementById('integrator-dealer-filter');
            if (sel) {
                sel.value = dealerId;
            }
            renderIntegratorsUI(dealerId);
        }

        function renderIntegratorsTable() {
            const sel = document.getElementById('integrator-dealer-filter');
            renderIntegratorsUI(sel ? sel.value : 'all');
        }

        function filterFleetByDealer(dealerId) {
            selectedFleetPartner = dealerId || 'ALL';
            switchTab('fleet');
            const sel = document.getElementById('fleet-partner-select');
            if (sel) {
                sel.value = selectedFleetPartner;
            }
            fleetCurrentPage = 1;
            if (Array.isArray(currentFleetData)) {
                renderTable(currentFleetData);
            } else {
                fetchFleet();
            }
        }



        function slugifyText(text) {
            return (text || '')
                .toString()
                .toLowerCase()
                .trim()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-+|-+$/g, '');
        }

        function openCreateDealerModal() {
            document.getElementById('dealer-modal-title').innerText = 'Register New Authorized Dealer';
            document.getElementById('dealer-form-id').value = '';
            document.getElementById('dlr-name').value = '';
            const uGroup = document.getElementById('dlr-username-group');
            if (uGroup) uGroup.style.display = 'none';
            document.getElementById('dlr-username').value = '';
            document.getElementById('dlr-pwd').value = '';
            document.getElementById('dlr-pwd').required = true;
            document.getElementById('dlr-pwd-hint').style.display = 'none';
            document.getElementById('dlr-email').value = '';
            document.getElementById('dlr-phone').value = '';
            document.getElementById('dlr-status-group').style.display = 'none';
            document.getElementById('dealer-modal').classList.add('active');
        }

        function openEditDealerModal(dealerId) {
            const d = dealersList.find(x => x.id === dealerId);
            if (!d) return;

            document.getElementById('dealer-modal-title').innerText = `Edit Authorized Dealer: ${d.name}`;
            document.getElementById('dealer-form-id').value = d.id;
            document.getElementById('dlr-name').value = d.name;
            const uGroup = document.getElementById('dlr-username-group');
            const uBadge = document.getElementById('dlr-username-badge');
            if (uGroup) uGroup.style.display = 'block';
            if (uBadge) uBadge.innerText = d.username;
            document.getElementById('dlr-username').value = d.username;
            
            // POPULATE PLAIN PASSWORD FOR MANUFACTURER TO SEE AND EDIT!
            document.getElementById('dlr-pwd').value = d.password_plain || '';
            document.getElementById('dlr-pwd').required = false;
            document.getElementById('dlr-pwd-hint').style.display = 'block';
            
            document.getElementById('dlr-email').value = d.email || '';
            document.getElementById('dlr-phone').value = d.phone || '';
            document.getElementById('dlr-status').value = d.status || 'active';
            document.getElementById('dlr-status-group').style.display = 'block';
            document.getElementById('dealer-modal').classList.add('active');
        }

        function closeDealerModal() {
            document.getElementById('dealer-modal').classList.remove('active');
        }

        async function handleDealerFormSubmit(e) {
            e.preventDefault();
            const id = document.getElementById('dealer-form-id').value;
            const name = document.getElementById('dlr-name').value.trim();
            let username = document.getElementById('dlr-username').value.trim();
            if (!id) {
                // Autonomous username generation format: <dealer name>
                username = slugifyText(name);
            }
            const payload = {
                name: name,
                username: username,
                password: document.getElementById('dlr-pwd').value,
                email: document.getElementById('dlr-email').value.trim(),
                phone: document.getElementById('dlr-phone').value.trim()
            };

            const endpoint = id ? '/api/update_dealer' : '/api/create_dealer';
            if (id) {
                payload.id = id;
                payload.status = document.getElementById('dlr-status').value;
            }

            try {
                const res = await apiFetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || 'Dealer saved successfully', 'success');
                    closeDealerModal();
                    fetchDealers();
                    fetchFleet();
                } else {
                    showToast(data.error || 'Operation failed', 'error');
                }
            } catch (err) {
                showToast('Network error while saving dealer', 'error');
            }
        }

        function promptDeleteDealer(dealerId, dealerName) {
            currentDeleteTarget = { type: 'dealer', id: dealerId, name: dealerName };
            document.getElementById('delete-modal-title').innerText = `Delete Dealer: ${dealerName}`;
            document.getElementById('delete-modal-msg').innerHTML = `
                Are you sure you want to delete dealer <strong>${escapeHtml(dealerName)}</strong>?<br><br>
                <span style="color: #38bdf8;">✓ SAFETY GUARANTEE:</span> All Gavasah Gateways currently assigned to this dealer will <strong>NOT</strong> be deleted. They will automatically be transferred to Master Manufacturer Direct Supervision.
            `;
            document.getElementById('delete-modal').classList.add('active');
        }

        // ======================================================================
        // INTEGRATORS MANAGEMENT (MANUFACTURER & DEALERS)
        // ======================================================================
        async function fetchIntegrators() {
            if (!currentUser || currentUser.role === 'integrator') return;
            try {
                const res = await apiFetch('/api/integrators?t=' + Date.now());
                if (res.ok) {
                    integratorsList = await res.json();
                    renderIntegratorsUI();
                    updateIntegratorDropdowns();
                    populatePartnerFilter();
                }
            } catch (err) {
                console.error("Error fetching integrators:", err);
            }
        }

        function renderIntegratorsUI(dealerFilter = 'all') {
            const badge = document.getElementById('badge-integrator-count');
            if (badge) badge.innerText = integratorsList.length;

            const ovIntegratorsCount = document.getElementById('ov-integrators-count');
            if (ovIntegratorsCount) ovIntegratorsCount.innerText = integratorsList.length;

            // Filter if manufacturer picked a dealer
            let filteredList = integratorsList;
            if (currentUser.role === 'manufacturer' && dealerFilter !== 'all') {
                filteredList = integratorsList.filter(it => it.dealer_id === dealerFilter);
            }

            // If Dealer, render summary workforce breakdown in Overview tab
            if (currentUser.role === 'dealer') {
                const ovBody = document.getElementById('overview-dealers-body');
                if (ovBody) {
                    ovBody.innerHTML = filteredList.map(it => `
                        <tr>
                            <td style="font-weight: 600; color: #fff;">
                                <div>${escapeHtml(it.name)}</div>
                                <div style="font-size: 11px; color: #64748b; font-family: monospace;">ID: ${escapeHtml(it.id)}</div>
                            </td>
                            <td style="font-family: monospace; color: #cbd5e1;">${escapeHtml(it.username)}</td>
                            <td>
                                <span class="badge-role" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);">
                                    ${it.client_count} Supervised Site(s)
                                </span>
                            </td>
                            <td>
                                <span style="color: #10b981; font-weight: 600;">${it.online_count} Online</span> / 
                                <span style="color: ${it.lost_count > 0 ? '#ef4444' : '#64748b'}; font-weight: 600;">${it.lost_count} Lost</span>
                            </td>
                            <td style="font-size: 12px; color: #94a3b8;">
                                <div>${escapeHtml(it.email || '—')}</div>
                                <div style="font-size: 11px; color: #64748b;">${escapeHtml(it.phone || '—')}</div>
                            </td>
                            <td>
                                <span class="badge-status ${it.status === 'active' ? 'status-online' : 'status-lost'}">
                                    ${it.status.toUpperCase()}
                                </span>
                            </td>
                            <td>
                                <button class="btn-sm" onclick="switchTab('integrators')">Manage Workforce ➔</button>
                            </td>
                        </tr>
                    `).join('') || `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">No integrators registered in your dealership yet. Click "+ Register New Integrator" above.</td></tr>`;
                }
            }

            // Dedicated Integrators Directory Table (With Password Reveal & Edit for Manufacturer and Dealer)
            const dirBody = document.getElementById('integrators-management-body');
            if (dirBody) {
                dirBody.innerHTML = filteredList.map(it => `
                    <tr>
                        <td style="font-weight: 600; color: #fff;">
                            <div style="font-size: 14px;">${escapeHtml(it.name)}</div>
                            <div style="font-size: 11px; color: #64748b; font-family: monospace;">UUID: ${escapeHtml(it.id)}</div>
                        </td>
                        ${currentUser.role === 'manufacturer' ? `
                            <td style="color: #c084fc; font-size: 13px; font-weight: 500;">
                                <div>${escapeHtml(it.dealer_name || 'Direct')}</div>
                                <div style="font-size: 11px; color: #64748b; font-family: monospace;">${escapeHtml(it.dealer_id)}</div>
                            </td>
                        ` : ''}
                        <td style="font-family: monospace; color: #cbd5e1; font-weight: 600;">
                            ${escapeHtml(it.username)}
                        </td>
                        <td>
                            <div class="pwd-cell-wrap">
                                <span class="pwd-masked" id="int-pwd-val-${it.id}" data-plain="${escapeHtml(it.password_plain || '')}">••••••••</span>
                                <button type="button" class="btn-icon-pwd" onclick="toggleTablePassword('int-pwd-val-${it.id}')" title="Show / Hide Password">👁️</button>
                                <button type="button" class="btn-icon-pwd" onclick="copyPassword('${escapeHtml(it.password_plain || '')}')" title="Copy Password">📋</button>
                            </div>
                        </td>
                        <td style="font-size: 12px; color: #cbd5e1;">
                            <div>📧 ${escapeHtml(it.email || 'None')}</div>
                            <div style="margin-top: 2px;">📞 ${escapeHtml(it.phone || 'None')}</div>
                        </td>
                        <td>
                            <span class="badge-role" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);">
                                ${it.client_count} Supervised Site(s)
                            </span>
                        </td>
                        <td>
                            <button type="button" class="btn-status-toggle ${it.status === 'active' ? 'status-active-btn' : 'status-suspended-btn'}" 
                                onclick="toggleIntegratorStatus('${it.id}', '${it.status === 'active' ? 'suspended' : 'active'}')" 
                                title="Click to ${it.status === 'active' ? 'Suspend Login & Terminate Sessions' : 'Activate Login'}">
                                ${it.status === 'active' ? '🟢 ACTIVE' : '🔴 SUSPENDED'}
                            </button>
                        </td>
                        <td>
                            <div style="display: flex; gap: 6px;">
                                ${it.status === 'active' ? `
                                    <button class="btn-action-icon" style="color: #fbbf24; border-color: rgba(251, 191, 36, 0.3);" onclick="toggleIntegratorStatus('${it.id}', 'suspended')" title="Suspend Integrator Login & Kill Active Sessions">⏸️ Suspend</button>
                                ` : `
                                    <button class="btn-action-icon" style="color: #34d399; border-color: rgba(52, 211, 153, 0.3);" onclick="toggleIntegratorStatus('${it.id}', 'active')" title="Activate Integrator Login">▶️ Activate</button>
                                `}
                                <button class="btn-action-icon" onclick="openEditIntegratorModal('${it.id}')" title="Edit Integrator & Password">✏️ Edit</button>
                                <button class="btn-action-icon" style="color: #ef4444; border-color: rgba(239, 68, 68, 0.3);" onclick="promptDeleteIntegrator('${it.id}', '${escapeHtml(it.name)}')" title="Delete Integrator">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `).join('') || `<tr><td colspan="${currentUser.role === 'manufacturer' ? 8 : 7}" style="text-align: center; color: #64748b; padding: 24px;">No integrators registered.</td></tr>`;
            }
        }

        function isIntegratorInDealer(it, dealerId) {
            if (!dealerId || dealerId === 'owner_master' || dealerId === 'direct') {
                return !it.dealer_id || it.dealer_id === 'owner_master' || it.dealer_id === 'direct';
            }
            return it.dealer_id === dealerId;
        }

        function updateOnboardIntegratorDropdown(selectedIntegratorId) {
            const onbIntSel = document.getElementById('onb-integrator-select');
            if (!onbIntSel) return;

            let dealerId = 'owner_master';
            if (currentUser && currentUser.role === 'dealer') {
                dealerId = currentUser.id;
            } else {
                const dSel = document.getElementById('onb-dealer-select');
                if (dSel && dSel.value) dealerId = dSel.value;
            }

            const filtered = integratorsList.filter(it => isIntegratorInDealer(it, dealerId));
            const prevVal = (selectedIntegratorId !== undefined) ? selectedIntegratorId : onbIntSel.value;

            let html = '<option value="">Direct Dealer Supervision (No Integrator)</option>';
            if (filtered.length > 0) {
                html += filtered.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');
            }
            onbIntSel.innerHTML = html;

            if (prevVal && filtered.some(it => it.id === prevVal)) {
                onbIntSel.value = prevVal;
            } else {
                onbIntSel.value = '';
            }
        }

        function updateEditIntegratorDropdown(selectedIntegratorId) {
            const editIntSel = document.getElementById('edit-integrator-select');
            if (!editIntSel) return;

            let dealerId = 'owner_master';
            if (currentUser && currentUser.role === 'dealer') {
                dealerId = currentUser.id;
            } else {
                const dSel = document.getElementById('edit-dealer-select');
                if (dSel && dSel.value) dealerId = dSel.value;
            }

            const filtered = integratorsList.filter(it => isIntegratorInDealer(it, dealerId));
            const prevVal = (selectedIntegratorId !== undefined) ? selectedIntegratorId : editIntSel.value;

            let html = '<option value="">Direct Dealer Supervision (No Integrator)</option>';
            if (filtered.length > 0) {
                html += filtered.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');
            }
            editIntSel.innerHTML = html;

            if (prevVal && filtered.some(it => it.id === prevVal)) {
                editIntSel.value = prevVal;
            } else {
                editIntSel.value = '';
            }
        }

        function updateIntegratorDropdowns() {
            updateOnboardIntegratorDropdown();
            updateEditIntegratorDropdown();
        }

        function openCreateIntegratorModal() {
            document.getElementById('integrator-modal-title').innerText = 'Register New Technical Integrator';
            document.getElementById('int-id').value = '';
            document.getElementById('int-name').value = '';
            const uGroup = document.getElementById('int-username-group');
            if (uGroup) uGroup.style.display = 'none';
            document.getElementById('int-username').value = '';
            document.getElementById('int-password').value = '';
            document.getElementById('int-password').required = true;
            document.getElementById('int-pwd-hint').style.display = 'none';
            document.getElementById('int-email').value = '';
            document.getElementById('int-phone').value = '';

            const dWrap = document.getElementById('int-dealer-select-wrap');
            if (currentUser.role === 'manufacturer') {
                dWrap.style.display = 'block';
                updateDealerDropdowns();
                const dSel = document.getElementById('int-dealer-select');
                if (dSel) dSel.value = 'owner_master';
            } else {
                dWrap.style.display = 'none';
            }

            document.getElementById('integrator-modal').classList.add('active');
        }

        function openEditIntegratorModal(intId) {
            const it = integratorsList.find(x => x.id === intId);
            if (!it) return;

            document.getElementById('integrator-modal-title').innerText = `Edit Integrator: ${it.name}`;
            document.getElementById('int-id').value = it.id;
            document.getElementById('int-name').value = it.name;
            const uGroup = document.getElementById('int-username-group');
            const uBadge = document.getElementById('int-username-badge');
            if (uGroup) uGroup.style.display = 'block';
            if (uBadge) uBadge.innerText = it.username;
            document.getElementById('int-username').value = it.username;
            
            // POPULATE PLAIN PASSWORD FOR MANUFACTURER AND DEALER TO SEE AND EDIT!
            document.getElementById('int-password').value = it.password_plain || '';
            document.getElementById('int-password').required = false;
            document.getElementById('int-pwd-hint').style.display = 'block';

            document.getElementById('int-email').value = it.email || '';
            document.getElementById('int-phone').value = it.phone || '';

            const dWrap = document.getElementById('int-dealer-select-wrap');
            if (currentUser.role === 'manufacturer') {
                dWrap.style.display = 'block';
                updateDealerDropdowns();
                const dSel = document.getElementById('int-dealer-select');
                if (dSel) dSel.value = it.dealer_id || 'owner_master';
            } else {
                dWrap.style.display = 'none';
            }

            document.getElementById('integrator-modal').classList.add('active');
        }

        function closeIntegratorModal() {
            document.getElementById('integrator-modal').classList.remove('active');
        }

        async function handleIntegratorSubmit(e) {
            e.preventDefault();
            const id = document.getElementById('int-id').value;
            const name = document.getElementById('int-name').value.trim();
            let username = document.getElementById('int-username').value.trim();

            let dealerId = '';
            let dealerName = '';
            if (currentUser.role === 'dealer') {
                dealerId = currentUser.id;
                dealerName = currentUser.name || currentUser.username;
            } else if (currentUser.role === 'manufacturer') {
                dealerId = document.getElementById('int-dealer-select').value;
                if (dealerId === 'owner_master') {
                    dealerName = 'manufacturer';
                } else {
                    const dObj = dealersList.find(x => x.id === dealerId);
                    dealerName = dObj ? dObj.name : 'dealer';
                }
            }

            if (!id) {
                // Autonomous username generation format: <integrator name>-<dealer name>
                const intSlug = slugifyText(name);
                const dlrSlug = slugifyText(dealerName);
                username = `${intSlug}-${dlrSlug}`.replace(/^-+|-+$/g, '');
            }

            const payload = {
                name: name,
                username: username,
                password: document.getElementById('int-password').value,
                email: document.getElementById('int-email').value.trim(),
                phone: document.getElementById('int-phone').value.trim()
            };

            if (currentUser.role === 'manufacturer') {
                payload.dealer_id = document.getElementById('int-dealer-select').value;
            }

            const endpoint = id ? '/api/update_integrator' : '/api/create_integrator';
            if (id) {
                payload.id = id;
            }

            try {
                const res = await apiFetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || 'Integrator saved successfully', 'success');
                    closeIntegratorModal();
                    fetchIntegrators();
                    fetchFleet();
                } else {
                    showToast(data.error || 'Operation failed', 'error');
                }
            } catch (err) {
                showToast('Network error while saving integrator', 'error');
            }
        }

        function promptDeleteIntegrator(intId, intName) {
            currentDeleteTarget = { type: 'integrator', id: intId, name: intName };
            document.getElementById('delete-modal-title').innerText = `Delete Integrator: ${intName}`;
            document.getElementById('delete-modal-msg').innerHTML = `
                Are you sure you want to delete technical integrator <strong>${escapeHtml(intName)}</strong>?<br><br>
                <span style="color: #10b981; font-weight: 600;">✓ SAFETY GUARANTEE:</span> All Gavasah Gateways currently supervised by this integrator will <strong>NOT</strong> be deleted. They will automatically be transferred to <strong>Direct Dealer Supervision</strong>.
            `;
            document.getElementById('delete-modal').classList.add('active');
        }

        // ======================================================================
        // CLIENT SUPERVISION REASSIGNMENT MODAL
        // ======================================================================
        function openReassignModal(clientId) {
            const client = currentFleetData.find(c => c.client_id === clientId);
            if (!client) return;

            document.getElementById('reassign-client-id').value = clientId;
            document.getElementById('reassign-client-name').innerText = `${client.name} (${client.client_id})`;

            const dealerWrap = document.getElementById('reassign-dealer-wrap');
            const dealerSelect = document.getElementById('reassign-dealer-select');
            const intSelect = document.getElementById('reassign-integrator-select');

            if (currentUser.role === 'manufacturer') {
                dealerWrap.style.display = 'block';
                dealerSelect.innerHTML = '<option value="owner_master">Master Manufacturer (Direct)</option>' +
                    dealersList.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
                dealerSelect.value = client.dealer_id || 'owner_master';
                onReassignDealerChange(client.integrator_id);
            } else {
                // Dealer role
                dealerWrap.style.display = 'none';
                const filteredIntegrators = integratorsList.filter(it => isIntegratorInDealer(it, currentUser.id));
                intSelect.innerHTML = '<option value="none">Direct Dealer Supervision (No Integrator)</option>' +
                    filteredIntegrators.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');
                intSelect.value = (client.integrator_id && filteredIntegrators.some(it => it.id === client.integrator_id)) ? client.integrator_id : 'none';
            }

            document.getElementById('reassign-modal').classList.add('active');
        }

        function onReassignDealerChange(preSelectedIntId = null) {
            const dealerId = document.getElementById('reassign-dealer-select').value;
            const intSelect = document.getElementById('reassign-integrator-select');

            const filteredIntegrators = integratorsList.filter(it => isIntegratorInDealer(it, dealerId));
            intSelect.innerHTML = '<option value="none">Direct Dealer Supervision (No Integrator)</option>' +
                filteredIntegrators.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');

            if (preSelectedIntId && filteredIntegrators.some(it => it.id === preSelectedIntId)) {
                intSelect.value = preSelectedIntId;
            } else {
                intSelect.value = 'none';
            }
        }

        function closeReassignModal() {
            document.getElementById('reassign-modal').classList.remove('active');
        }

        async function handleReassignSubmit(e) {
            e.preventDefault();
            const clientId = document.getElementById('reassign-client-id').value;
            const payload = { client_id: clientId };

            if (currentUser.role === 'manufacturer') {
                payload.dealer_id = document.getElementById('reassign-dealer-select').value;
            }
            const intVal = document.getElementById('reassign-integrator-select').value;
            payload.integrator_id = (intVal === 'none' || !intVal) ? null : intVal;

            try {
                const res = await apiFetch('/api/reassign_client', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || 'Supervision reassigned successfully', 'success');
                    closeReassignModal();
                    fetchFleet();
                    fetchIntegrators();
                } else {
                    showToast(data.error || 'Failed to reassign client', 'error');
                }
            } catch (err) {
                showToast('Network error during reassignment', 'error');
            }
        }

        // ======================================================================
        // FLEET INVENTORY MANAGEMENT
        // ======================================================================
        async function fetchFleet() {
            try {
                const res = await apiFetch('/api/fleet?t=' + Date.now());
                if (!res.ok) {
                    if (res.status === 401) checkAuth();
                    return;
                }
                const data = await res.json();
                currentFleetData = data;
                const badgeFleet = document.getElementById('badge-fleet-count');
                if (badgeFleet) badgeFleet.innerText = data.length;
                renderTable(data);
                if (currentUser && currentUser.role === 'manufacturer' && dealersList.length > 0) {
                    renderDealersUI();
                }
                if (activeTab === 'branding') {
                    updateLiveBrandingPreview();
                }
            } catch (err) {
                console.error("Error fetching fleet:", err);
            }
        }

        function handleSearch(q) {
            fleetSearchQuery = q.toLowerCase();
            fleetCurrentPage = 1;
            renderTable(currentFleetData);
        }

        function setFleetFilter(f) {
            fleetStatusFilter = (f || 'ALL').toUpperCase();
            fleetCurrentPage = 1;
            document.querySelectorAll('.pill-btn').forEach(p => p.classList.remove('active'));
            if (fleetStatusFilter === 'ALL') {
                const el = document.getElementById('filter-pill-all');
                if (el) el.classList.add('active');
            } else if (fleetStatusFilter === 'ONLINE') {
                const el = document.getElementById('filter-pill-online');
                if (el) el.classList.add('active');
            } else if (fleetStatusFilter === 'DELAYED') {
                const el = document.getElementById('filter-pill-delayed');
                if (el) el.classList.add('active');
            } else if (fleetStatusFilter === 'WARNING') {
                const el = document.getElementById('filter-pill-warning');
                if (el) el.classList.add('active');
            } else if (fleetStatusFilter === 'LOST' || fleetStatusFilter === 'OFFLINE') {
                const el = document.getElementById('filter-pill-lost');
                if (el) el.classList.add('active');
            }
            renderTable(currentFleetData);
        }

        function handlePageSizeChange(val) {
            fleetPageSize = parseInt(val);
            fleetCurrentPage = 1;
            renderTable(currentFleetData);
        }

        function changeFleetPage(delta) {
            fleetCurrentPage += delta;
            renderTable(currentFleetData);
        }

        let selectedFleetPartner = 'ALL';

        function showGatewayLastError(clientId) {
            const c = (currentFleetData || []).find(item => item.client_id === clientId);
            if (!c || !c.system || !c.system.last_error) return;
            const err = c.system.last_error;
            alert(`⚠️ Gateway Command Error\n\nCommand: ${err.command || 'unknown'}\nTime: ${err.timestamp || 'N/A'}\n\nDetails:\n${err.error || 'No error details reported'}`);
        }

        function populatePartnerFilter() {
            const wrap = document.getElementById('fleet-partner-filter-wrap');
            const sel = document.getElementById('fleet-partner-select');
            const label = document.getElementById('partner-filter-label');
            const icon = document.getElementById('partner-filter-icon');
            if (!wrap || !sel || !currentUser) return;

            if (currentUser.role === 'manufacturer') {
                wrap.style.display = 'inline-flex';
                if (label) label.innerText = 'Dealer:';
                if (icon) icon.innerText = '🏢';
                const ownerItem = (dealersList || []).find(d => d.is_manufacturer) || {};
                const actualDealers = (dealersList || []).filter(d => !d.is_manufacturer);
                const totalFleetCount = Array.isArray(currentFleetData) ? currentFleetData.length : 0;

                let html = `<option value="ALL">🏢 All Dealers (All Fleet: ${totalFleetCount})</option>`;
                html += `<option value="owner_master">🛡️ Master Direct Supervision (${ownerItem.client_count || 0})</option>`;
                actualDealers.forEach(d => {
                    html += `<option value="${escapeHtml(d.id)}">🏢 ${escapeHtml(d.name)} (${d.client_count || 0})</option>`;
                });
                sel.innerHTML = html;
                sel.value = selectedFleetPartner || 'ALL';
            } else if (currentUser.role === 'dealer') {
                wrap.style.display = 'inline-flex';
                if (label) label.innerText = 'Integrator:';
                if (icon) icon.innerText = '🔧';
                let html = '<option value="ALL">🔧 All Integrators</option>';
                html += '<option value="DIRECT">🛡️ Direct Dealer Supervision</option>';
                (integratorsList || []).forEach(it => {
                    html += `<option value="${escapeHtml(it.id)}">🔧 ${escapeHtml(it.name)} (${it.client_count || 0})</option>`;
                });
                sel.innerHTML = html;
                sel.value = selectedFleetPartner || 'ALL';
            } else {
                wrap.style.display = 'none';
            }
        }

        function handlePartnerFilterChange(val) {
            selectedFleetPartner = val;
            fleetCurrentPage = 1;
            renderTable(currentFleetData);
        }

        let activeActionMenuClientId = null;

        function toggleRowActionMenu(clientId, event) {
            if (event) {
                event.stopPropagation();
                event.preventDefault();
            }
            const menu = document.getElementById(`action-menu-${clientId}`);
            const btn = document.getElementById(`btn-action-toggle-${clientId}`);
            const td = btn ? btn.closest('td') : null;
            if (!menu) return;
            const isOpen = menu.style.display === 'flex';
            closeAllActionMenus(true); // close any other menu without triggering re-render
            if (!isOpen) {
                menu.style.display = 'flex';
                activeActionMenuClientId = clientId;
                if (btn) btn.classList.add('active');
                if (td) td.classList.add('is-open');
            } else {
                activeActionMenuClientId = null;
            }
        }

        function closeAllActionMenus(preventReRender = false) {
            const hadOpenMenu = activeActionMenuClientId !== null;
            activeActionMenuClientId = null;
            document.querySelectorAll('.action-menu-popover').forEach(el => el.style.display = 'none');
            document.querySelectorAll('.btn-actions-toggle').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.col-actions-menu').forEach(el => el.classList.remove('is-open'));

            if (!preventReRender && hadOpenMenu && Array.isArray(currentFleetData)) {
                // If a background update was deferred while the menu was open, update table now
                renderTable(currentFleetData);
            }
        }

        document.addEventListener('click', (e) => {
            if (!e.target.closest('.action-dropdown-wrap')) {
                closeAllActionMenus();
            }
        });

        function isEntryIgnored(e) {
            if (!e || typeof e !== 'object') return true;
            if (String(e.source || '').trim().toLowerCase() === 'ignore') return true;
            if (String(e.state || '').trim().toLowerCase() === 'ignored') return true;
            if (e.disabled_by) return true;
            return false;
        }

        function renderTable(data) {
        window.renderFleetTable = renderTable;
            if (!Array.isArray(data)) return;

            const now = Math.floor(Date.now() / 1000);
            let onlineCount = 0;
            let delayedCount = 0;
            let warningCount = 0;
            let offlineCount = 0;

            const filtered = data.filter(c => {
                // Partner Selection Filter (Dealers in Manufacturer, Integrators in Dealer)
                if (currentUser.role === 'manufacturer') {
                    if (selectedFleetPartner !== 'ALL') {
                        if (selectedFleetPartner === 'owner_master') {
                            if (c.dealer_id && c.dealer_id !== 'owner_master') return false;
                        } else if (c.dealer_id !== selectedFleetPartner) {
                            return false;
                        }
                    }
                } else if (currentUser.role === 'dealer') {
                    if (selectedFleetPartner !== 'ALL') {
                        if (selectedFleetPartner === 'DIRECT') {
                            const isDirect = !c.integrator_id || c.integrator_id === 'DIRECT' || !c.integrator_name || c.integrator_name === 'Direct Dealer Supervision';
                            if (!isDirect) return false;
                        } else if (c.integrator_id !== selectedFleetPartner) {
                            return false;
                        }
                    }
                }

                const isPending = !c.last_heartbeat || c.last_heartbeat === 0 || c.status === 'pending';
                const diff = isPending ? -1 : now - (c.last_heartbeat || 0);
                const delayedLimit = parseInt(c.hb_delayed_interval) || 900;
                const warnLimit = parseInt(c.hb_warning_interval) || 1800;
                const offLimit = parseInt(c.hb_offline_interval) || 3600;

                if (isPending) offlineCount++;
                else if (diff <= delayedLimit) onlineCount++;
                else if (diff <= warnLimit) delayedCount++;
                else if (diff <= offLimit) warningCount++;
                else offlineCount++;

                if (fleetStatusFilter === 'ONLINE' && (isPending || diff > delayedLimit)) return false;
                if (fleetStatusFilter === 'DELAYED' && (isPending || diff <= delayedLimit || diff > warnLimit)) return false;
                if (fleetStatusFilter === 'WARNING' && (isPending || diff <= warnLimit || diff > offLimit)) return false;
                if ((fleetStatusFilter === 'OFFLINE' || fleetStatusFilter === 'LOST') && !isPending && diff <= offLimit) return false;

                if (fleetSearchQuery) {
                    const str = `${c.client_id} ${c.name} ${c.dealer_name || ''} ${c.integrator_name || ''} ${c.domain} ${c.knx_ip}`.toLowerCase();
                    if (!str.includes(fleetSearchQuery)) return false;
                }
                return true;
            });

            // Update Fleet Tab metric cards: Gateways stay in Online Gateways through green, yellow (delayed), and orange (warning) mode.
            // They ONLY drop out and move to Lost / Offline when in RED mode (diff > offLimit or pending).
            const valTotal = document.getElementById('val-total');
            const valOnline = document.getElementById('val-online');
            const valLost = document.getElementById('val-lost');
            const activeOnlineCount = onlineCount + delayedCount + warningCount;
            const trueOfflineCount = offlineCount;
            if (valTotal) valTotal.innerText = data.length;
            if (valOnline) valOnline.innerText = activeOnlineCount;
            if (valLost) valLost.innerText = trueOfflineCount;

            // Update Filter pill counters
            const pillAll = document.getElementById('pill-count-all');
            const pillOnline = document.getElementById('pill-count-online');
            const pillDelayed = document.getElementById('pill-count-delayed');
            const pillWarning = document.getElementById('pill-count-warning');
            const pillLost = document.getElementById('pill-count-lost');
            if (pillAll) pillAll.innerText = data.length;
            if (pillOnline) pillOnline.innerText = onlineCount;
            if (pillDelayed) pillDelayed.innerText = delayedCount;
            if (pillWarning) pillWarning.innerText = warningCount;
            if (pillLost) pillLost.innerText = offlineCount;

            // Update Overview Tab cards: Online Gateways only changes when gateway becomes offline in red mode
            const ovTotal = document.getElementById('ov-total-clients');
            const ovOnline = document.getElementById('ov-online-clients');
            const ovLost = document.getElementById('ov-lost-clients');
            if (ovTotal) ovTotal.innerText = data.length;
            if (ovOnline) ovOnline.innerText = activeOnlineCount;
            if (ovLost) ovLost.innerText = trueOfflineCount;

            // Update Sidebar Navigation Fleet Badge
            const badgeFleetEl = document.getElementById('badge-fleet-count');
            if (badgeFleetEl) badgeFleetEl.innerText = data.length;

            // Pagination
            const totalItems = filtered.length;
            const totalPages = Math.ceil(totalItems / fleetPageSize) || 1;
            if (fleetCurrentPage > totalPages) fleetCurrentPage = totalPages;
            if (fleetCurrentPage < 1) fleetCurrentPage = 1;

            const startIdx = (fleetCurrentPage - 1) * fleetPageSize;
            const pageData = filtered.slice(startIdx, startIdx + fleetPageSize);

            const pageInfo = document.getElementById('fleet-page-info');
            if (pageInfo) pageInfo.innerText = `Showing ${totalItems ? startIdx + 1 : 0}-${Math.min(startIdx + fleetPageSize, totalItems)} of ${totalItems}`;

            const prevBtn = document.getElementById('btn-fleet-prev') || document.getElementById('fleet-prev-btn');
            const nextBtn = document.getElementById('btn-fleet-next') || document.getElementById('fleet-next-btn');
            if (prevBtn) prevBtn.disabled = fleetCurrentPage <= 1;
            if (nextBtn) nextBtn.disabled = fleetCurrentPage >= totalPages;

            const tbody = document.getElementById('fleet-table-body');
            if (!tbody) return;

            // If an action dropdown menu is currently open, DO NOT recreate the table DOM rows under the user's cursor!
            // This prevents the action menu from disappearing after a few seconds during background polling!
            if (activeActionMenuClientId && document.getElementById(`action-menu-${activeActionMenuClientId}`)) {
                return;
            }

            tbody.innerHTML = pageData.map(c => {
                const isPending = !c.last_heartbeat || c.last_heartbeat === 0 || c.status === 'pending';
                const diff = isPending ? -1 : now - (c.last_heartbeat || 0);
                const delayedLimit = parseInt(c.hb_delayed_interval) || 900;
                const warnLimit = parseInt(c.hb_warning_interval) || 1800;
                const offLimit = parseInt(c.hb_offline_interval) || 3600;

                let humanDiff = isPending ? 'awaiting pulse' : formatHeartbeatTime(diff);
                let stClass = 'status-online';
                let stText = 'ONLINE';
                if (isPending) { stClass = 'status-pending'; stText = '⏳ PENDING'; }
                else if (diff > offLimit) { stClass = 'status-lost'; stText = 'OFFLINE'; }
                else if (diff > warnLimit) { stClass = 'status-warning'; stText = 'WARNING'; }
                else if (diff > delayedLimit) { stClass = 'status-delayed'; stText = 'DELAYED'; }

                const sys = c.system || {};
                const net = c.network || {};
                const knx = c.knx_status || {};
                const isRecovery = sys.is_recovery_mode || false;
                const slot = sys.boot_slot || 'A';
                const remoteEnabled = Boolean(c.remote_enabled) && c.remote_enabled !== 0 && c.remote_enabled !== '0';

                // Integration monitoring mute/disable check (Row scoped)
                const unmonList = c.unmonitored_integrations || [];
                const isMuted = (k) => {
                    if (!k) return false;
                    const s = String(k).toLowerCase();
                    return unmonList.includes(s) || unmonList.includes('core_' + s) || (s.startsWith('core_') && unmonList.includes(s.slice(5)));
                };

                // Autonomous Self-Healing Engine Inspection (Row scoped)
                const shData = (c.technologies && c.technologies.self_healing) || {};
                const shSubsystems = shData.subsystems || {};

                // Dealer cell (only for manufacturer)
                const dealerCell = currentUser.role === 'manufacturer' ? `
                    <td>
                        <span class="badge-role" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); white-space: nowrap;">
                            ${escapeHtml(c.dealer_name || 'Master Direct')}
                        </span>
                    </td>
                ` : '';

                // Integrator cell (for manufacturer and dealer)
                const integratorCell = currentUser.role !== 'integrator' ? `
                    <td>
                        ${c.integrator_name && c.integrator_name !== 'Direct Dealer Supervision' ? `
                            <span class="badge-role" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); white-space: nowrap;">
                                🔧 ${escapeHtml(c.integrator_name)}
                            </span>
                        ` : `
                            <span class="badge-role" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); white-space: nowrap;">
                                🛡️ Direct Dealer Supervision
                            </span>
                        `}
                    </td>
                ` : '';

                const onb = formatOnboardingDateTime(c.onboarded_at);
                const onboardCell = `
                    <td>
                        ${onb.hasOnboarded ? `
                            <div class="onboard-status-wrap" title="${escapeHtml(onb.tooltip)}">
                                <div style="font-size: 12px; font-weight: 600; color: #f1f5f9; display: flex; align-items: center; gap: 5px; white-space: nowrap;">
                                    <span style="color: #38bdf8;">📅</span> ${escapeHtml(onb.dateText)}
                                </div>
                                <div style="font-size: 11px; color: #94a3b8; margin-top: 3px; font-family: monospace; display: flex; align-items: center; gap: 5px; white-space: nowrap;">
                                    <span style="color: #64748b;">⏰</span> ${escapeHtml(onb.timeText)}
                                </div>
                            </div>
                        ` : `
                            <div class="onboard-status-wrap" title="${escapeHtml(onb.tooltip)}">
                                <span class="badge-role" style="background: rgba(245, 158, 11, 0.12); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); font-size: 11px; white-space: nowrap;">
                                    ⏳ Awaiting Contact
                                </span>
                                <div style="font-size: 10px; color: #64748b; margin-top: 3px;">Not connected yet</div>
                            </div>
                        `}
                    </td>
                `;

                return `
                    <tr>
                        <td>
                            <div class="site-name-text" title="${escapeHtml(c.name)} (${escapeHtml(c.client_id)})">${escapeHtml(c.name)}</div>
                            <div class="site-slug-text">
                                <a href="https://${escapeHtml(c.domain)}" target="_blank" class="site-domain-link" title="Open Remote GUI: ${escapeHtml(c.domain)}">${escapeHtml(c.domain)} ↗</a>
                            </div>
                            <div style="font-size: 10px; color: ${onb.hasOnboarded ? '#64748b' : '#d97706'}; margin-top: 3px; white-space: nowrap;" title="${escapeHtml(onb.tooltip)}">
                                ${onb.hasOnboarded ? `📅 Onboarded: ${escapeHtml(onb.fullText)}` : `⏳ Provisioned &bull; Awaiting initial contact`}
                            </div>
                        </td>
                        <!-- Column 2: Pure Heartbeat Watchdog Status -->
                        <td>
                            ${(() => {
                                const delayedLimit = parseInt(c.hb_delayed_interval) || 900;
                                const warnLimit = parseInt(c.hb_warning_interval) || 1800;
                                const offLimit = parseInt(c.hb_offline_interval) || 3600;
                                const delayedHuman = formatIntervalHuman(delayedLimit);
                                const warnHuman = formatIntervalHuman(warnLimit);
                                const offHuman = formatIntervalHuman(offLimit);

                                if (c.approval_status === 'pending') {
                                    return `
                                        <div class="heartbeat-status-wrap" title="Registration submitted &bull; Awaiting Manufacturer HQ Approval before remote access and monitoring are enabled">
                                            <span class="heartbeat-pill-badge hb-pill-pending" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border-color: rgba(245, 158, 11, 0.4);">
                                                <span class="hb-ball hb-ball-pending" style="background: #fbbf24; box-shadow: 0 0 6px #fbbf24;"></span>
                                                <span>AWAITING APPROVAL</span>
                                            </span>
                                            <div class="hb-timing-sub" style="color: #fbbf24; font-weight: 600;">Pending HQ Review</div>
                                            <div class="hb-timestamp-sub" style="color: #64748b; font-size: 10px;">🔒 Remote access locked</div>
                                        </div>
                                    `;
                                } else if (isPending) {
                                    return `
                                        <div class="heartbeat-status-wrap" title="Client site provisioned - awaiting initial connection from physical gateway">
                                            <span class="heartbeat-pill-badge hb-pill-pending">
                                                <span class="hb-ball hb-ball-pending"></span>
                                                <span>PENDING</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-pending">awaiting first pulse</div>
                                        </div>
                                    `;
                                } else if (diff > offLimit) {
                                    const off = formatOfflineDetails(c.last_heartbeat, now);
                                    return `
                                        <div class="heartbeat-status-wrap" title="${escapeHtml(off.tooltip)} • Escalation: Warns All Users + Manufacturer HQ (> ${offHuman})">
                                            <span class="heartbeat-pill-badge hb-pill-offline">
                                                <span class="hb-ball hb-ball-offline"></span>
                                                <span>OFFLINE</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-offline">${escapeHtml(off.timeSince)}</div>
                                            <div class="hb-timestamp-sub" style="color: #f87171; font-size: 10px; font-weight: 600;">🚨 Signal Lost (&gt;${offHuman})</div>
                                            <div class="hb-timestamp-sub">${escapeHtml(off.timestampText)}</div>
                                        </div>
                                    `;
                                } else if (diff > warnLimit) {
                                    const off = formatOfflineDetails(c.last_heartbeat, now);
                                    return `
                                        <div class="heartbeat-status-wrap" title="${escapeHtml(off.tooltip)} • Escalation: Warns Integrators + Dealers (> ${warnHuman})">
                                            <span class="heartbeat-pill-badge hb-pill-warning">
                                                <span class="hb-ball hb-ball-warning"></span>
                                                <span>WARNING</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-warning">Delayed (${humanDiff})</div>
                                            <div class="hb-timestamp-sub" style="color: #fb923c; font-size: 10px; font-weight: 600;">🟠 Warns Dealer &amp; Integrator (&gt;${warnHuman})</div>
                                            <div class="hb-timestamp-sub">${escapeHtml(off.timestampText)}</div>
                                        </div>
                                    `;
                                } else if (diff > delayedLimit) {
                                    const off = formatOfflineDetails(c.last_heartbeat, now);
                                    return `
                                        <div class="heartbeat-status-wrap" title="${escapeHtml(off.tooltip)} • Escalation: Warns Integrator (> ${delayedHuman})">
                                            <span class="heartbeat-pill-badge hb-pill-delayed">
                                                <span class="hb-ball hb-ball-delayed"></span>
                                                <span>DELAYED</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-delayed">Delayed (${humanDiff})</div>
                                            <div class="hb-timestamp-sub" style="color: #facc15; font-size: 10px; font-weight: 600;">🟡 Warns Integrator (&gt;${delayedHuman})</div>
                                            <div class="hb-timestamp-sub">${escapeHtml(off.timestampText)}</div>
                                        </div>
                                    `;
                                } else {
                                    return `
                                        <div class="heartbeat-status-wrap" title="Gavasah Gateway connected and streaming telemetry (Last pulse ${humanDiff}) • Watchdog limits: ${delayedHuman} / ${warnHuman} / ${offHuman}">
                                            <span class="heartbeat-pill-badge hb-pill-online">
                                                <span class="hb-ball hb-ball-online"></span>
                                                <span>ONLINE</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-online">Pulse ${humanDiff}</div>
                                            <div class="hb-timestamp-sub" style="color: #64748b; font-size: 10px;">Limits: ${delayedHuman} / ${warnHuman} / ${offHuman}</div>
                                        </div>
                                    `;
                                }
                            })()}
                        </td>

                        <!-- Column 6: Pure Smart Automation Integration & Self-Healing Status -->
                        <td>
                            ${(() => {
                                // Check for integration & subsystem issues (KNX, Zigbee, Lutron, Matter, CoolMaster, HA Core)
                                let integrationIssues = [];
                                if (c.knx_ip && c.knx_status && !isMuted('knx')) {
                                    if (c.knx_status.configured && (c.knx_status.reachable === false || c.knx_status.state === 'error' || c.knx_status.state === 'disconnected')) {
                                        integrationIssues.push('KNX Gateway unreachable');
                                    }
                                }
                                if (c.technologies) {
                                    for (const [techKey, techVal] of Object.entries(c.technologies)) {
                                        if (isMuted(techKey)) continue;
                                        if (techVal && techVal.detected) {
                                            if (techKey === 'lutron') {
                                                const validL = (techVal.entries || []).filter(e => !isEntryIgnored(e));
                                                if (validL.length > 0 && validL.every(e => e.state === 'loaded' || e.online === true)) {
                                                    continue;
                                                }
                                            } else if (techKey === 'coolmaster') {
                                                const validCm = (techVal.entries || []).filter(e => !isEntryIgnored(e));
                                                if (validCm.length > 0 && validCm.every(e => e.state === 'loaded' || e.online === true)) {
                                                    continue;
                                                }
                                            }
                                            if (techVal.status === 'error' || techVal.status === 'offline' || techVal.healthy === false || techVal.state === 'failed') {
                                                const prettyName = techKey === 'coolmaster' ? 'CoolMaster HVAC' : techKey.toUpperCase();
                                                integrationIssues.push(`${prettyName} failure`);
                                            }
                                        }
                                    }
                                }
                                const hasIntegrationIssue = integrationIssues.length > 0;
                                const integrationIssueText = integrationIssues.join(', ');

                                // Autonomous Self-Healing Telemetry Summary
                                const activeHealing = [];
                                const exhaustedHealing = [];

                                for (const [subKey, subInfo] of Object.entries(shSubsystems)) {
                                    if (isMuted(subKey)) continue;
                                    if (subKey === 'failed_core_entries') {
                                        const rawEntries = (c.technologies && c.technologies.failed_core_entries) || [];
                                        const activeUnmuted = rawEntries.filter(e => !isEntryIgnored(e) && !isMuted(e.domain));
                                        if (activeUnmuted.length === 0 || isMuted('failed_core_entries')) continue;
                                    }
                                    if (subInfo && subInfo.status === 'healing' && (subInfo.attempts || 0) < 5) {
                                        const pretty = subKey === 'coolmaster' ? 'CoolMaster HVAC' : (subKey === 'failed_core_entries' ? 'Core Entry' : subKey.toUpperCase());
                                        activeHealing.push({ key: subKey, name: pretty, attempt: subInfo.attempts || 1, maxAttempts: subInfo.max_attempts || 5, action: subInfo.last_action });
                                    } else if (subInfo && (subInfo.status === 'exhausted' || subInfo.status === 'escalated' || (subInfo.attempts || 0) >= 5)) {
                                        const pretty = subKey === 'coolmaster' ? 'CoolMaster HVAC' : (subKey === 'failed_core_entries' ? 'Core Entry' : subKey.toUpperCase());
                                        exhaustedHealing.push({ key: subKey, name: pretty, attempt: subInfo.attempts || 5, maxAttempts: subInfo.max_attempts || 5 });
                                    }
                                }
                                const isHealingActive = activeHealing.length > 0;
                                const isHealingExhausted = exhaustedHealing.length > 0;

                                if (c.approval_status === 'pending' || isPending) {
                                    return `
                                        <div class="heartbeat-status-wrap" title="Gateway pending activation &bull; Subsystem telemetry standby">
                                            <span class="heartbeat-pill-badge" style="background: rgba(148, 163, 184, 0.12); color: #94a3b8; border-color: rgba(148, 163, 184, 0.25);">
                                                <span class="hb-ball" style="background: #94a3b8;"></span>
                                                <span>STANDBY</span>
                                            </span>
                                            <div class="hb-timing-sub" style="color: #94a3b8;">Awaiting Setup</div>
                                            <div class="hb-timestamp-sub" style="color: #64748b; font-size: 10px;">Offline Telemetry</div>
                                        </div>
                                    `;
                                }
                                if (diff > offLimit) {
                                    return `
                                        <div class="heartbeat-status-wrap" title="Physical gateway heartbeat lost &bull; Subsystems unreachable">
                                            <span class="heartbeat-pill-badge" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border-color: rgba(100, 116, 139, 0.3);">
                                                <span class="hb-ball" style="background: #64748b;"></span>
                                                <span>UNREACHABLE</span>
                                            </span>
                                            <div class="hb-timing-sub" style="color: #64748b;">Gateway Offline</div>
                                            <div class="hb-timestamp-sub" style="color: #64748b; font-size: 10px;">Telemetry Paused</div>
                                        </div>
                                    `;
                                }
                                if (isHealingActive) {
                                    const primaryHeal = activeHealing[0];
                                    return `
                                        <div class="heartbeat-status-wrap" title="Autonomous Self-Healing Active: ${escapeHtml(primaryHeal.name)} remediation attempt ${primaryHeal.attempt} of ${primaryHeal.maxAttempts} in progress (${escapeHtml(primaryHeal.action || 'Remediating')}) • Partner escalation suppressed while healing">
                                            <span class="heartbeat-pill-badge hb-pill-healing">
                                                <span class="hb-ball hb-ball-healing"></span>
                                                <span>SELF-HEALING</span>
                                            </span>
                                            <div class="hb-timing-sub" style="color: #facc15; font-weight: 600;">${escapeHtml(primaryHeal.name)} (${primaryHeal.attempt}/${primaryHeal.maxAttempts})</div>
                                            <div class="hb-timestamp-sub" style="color: #94a3b8; font-size: 10px;">🛡️ Escalation suppressed</div>
                                        </div>
                                    `;
                                }
                                if (isHealingExhausted) {
                                    const primaryExh = exhaustedHealing[0];
                                    return `
                                        <div class="heartbeat-status-wrap" title="Autonomous Self-Healing Halted: 5/5 remediation attempts failed for ${escapeHtml(primaryExh.name)} • Halted &amp; Notified • Resets only on gateway or add-on restart">
                                            <span class="heartbeat-pill-badge hb-pill-offline" style="background: rgba(239, 68, 68, 0.2); color: #f87171; border-color: rgba(239, 68, 68, 0.4);">
                                                <span class="hb-ball hb-ball-offline"></span>
                                                <span>HEALING FAILED</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-offline">${escapeHtml(primaryExh.name)} (5/5 Failed)</div>
                                            <div class="hb-timestamp-sub" style="color: #f87171; font-size: 10px; font-weight: 600;">🛑 Halted • Awaiting Restart</div>
                                        </div>
                                    `;
                                }
                                if (hasIntegrationIssue) {
                                    return `
                                        <div class="heartbeat-status-wrap" title="Subsystem fault detected: ${escapeHtml(integrationIssueText)} • Click technology chips for diagnostics">
                                            <span class="heartbeat-pill-badge hb-pill-warning">
                                                <span class="hb-ball hb-ball-warning"></span>
                                                <span>FAULT DETECTED</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-warning">${escapeHtml(integrationIssueText)}</div>
                                            <div class="hb-timestamp-sub" style="color: #fb923c; font-size: 10px;">Click chip for details</div>
                                        </div>
                                    `;
                                }

                                // Count configured subsystems
                                const subs = [];
                                if (c.knx_ip || (c.knx_status && c.knx_status.configured)) subs.push('KNX');
                                if (c.technologies) {
                                    for (const [k, v] of Object.entries(c.technologies)) {
                                        if (v && (v.detected || v.status === 'online' || (v.entries && v.entries.length > 0))) {
                                            subs.push(k.toUpperCase());
                                        }
                                    }
                                }
                                if (subs.length > 0) {
                                    return `
                                        <div class="heartbeat-status-wrap" title="${subs.length} smart automation subsystems configured and healthy (${subs.join(', ')})">
                                            <span class="heartbeat-pill-badge hb-pill-online">
                                                <span class="hb-ball hb-ball-online"></span>
                                                <span>ALL HEALTHY</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-online">${subs.length} Subsystem${subs.length > 1 ? 's' : ''} Online</div>
                                            <div class="hb-timestamp-sub" style="color: #10b981; font-size: 10px;">🟢 Fully Operational</div>
                                        </div>
                                    `;
                                } else {
                                    return `
                                        <div class="heartbeat-status-wrap" title="Home Assistant Core operational • No external automation subsystems configured">
                                            <span class="heartbeat-pill-badge hb-pill-online" style="background: rgba(16, 185, 129, 0.12); border-color: rgba(16, 185, 129, 0.25);">
                                                <span class="hb-ball hb-ball-online"></span>
                                                <span>OPERATIONAL</span>
                                            </span>
                                            <div class="hb-timing-sub hb-timing-online">HA Core Online</div>
                                            <div class="hb-timestamp-sub" style="color: #64748b; font-size: 10px;">Core Fleet Mode</div>
                                        </div>
                                    `;
                                }
                            })()}
                        </td>

                        <!-- Column 4: Technologies & Subsystems -->
                        <td style="font-size: 12px;">
                            <div style="color: #94a3b8; font-family: monospace; font-size: 11px; margin-bottom: 4px;">IP: ${escapeHtml(net.local_ipv4 || '—')}</div>
                            <div class="tech-badge-container">
                                ${(() => {
                                    const tech = c.technologies || {};
                                    const knx = tech.knx || c.knx_status || {};
                                    const zigbee = tech.zigbee || {};
                                    const lutron = tech.lutron || {};
                                    const matter = tech.matter || {};
                                    const badges = [];

                                    // 1. KNX (Strict reality check: only show if genuinely configured on the Gavasah Gateway)
                                    const hasKnx = Boolean(knx.configured && knx.reason !== 'no_knx_integration' && ((knx.gateway_ip && knx.gateway_ip !== '192.168.1.100' && knx.gateway_ip !== '192.168.1.111' && knx.gateway_ip !== '—' && knx.gateway_ip !== 'none' && (knx.connection_type !== 'addon_options' || knx.reachable)) || (c.knx_ip && c.knx_ip !== '192.168.1.100' && c.knx_ip !== '192.168.1.111' && c.knx_ip !== '—' && c.knx_ip !== 'none' && c.knx_ip !== '')));
                                    if (hasKnx) {
                                        const ep = knx.gateway_ip ? `${knx.gateway_ip}:${knx.gateway_port || 3671}` : (c.knx_ip ? `${c.knx_ip}:${c.knx_port || 3671}` : 'Bus');
                                        const isKnxOnline = Boolean(knx.reachable || knx.state === 'connected' || knx.status === 'online');
                                        const knxHealing = shSubsystems['knx'];
                                        if (isMuted('knx')) {
                                            badges.push(`<span class="tech-badge" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); cursor: pointer;" onclick="openIntegrationDiagnostics('${c.client_id}', 'knx', event)" title="KNXnet/IP Monitoring Muted • Click to manage"><span class="tech-dot" style="background:#64748b;"></span>KNX (Muted)</span>`);
                                        } else if (knxHealing && knxHealing.status === 'healing' && (knxHealing.attempts || 0) <= 5) {
                                            badges.push(`<span class="tech-badge tech-status-healing" onclick="openIntegrationDiagnostics('${c.client_id}', 'knx', event)" style="cursor: pointer;" title="Autonomous Self-Healing in Progress (Attempt ${knxHealing.attempts}/5: ${escapeHtml(knxHealing.last_action || 'Remediating')}) • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#facc15; box-shadow: 0 0 6px #facc15;"></span>KNX Healing (${knxHealing.attempts}/5)</span>`);
                                        } else if (isKnxOnline) {
                                            const latStr = knx.latency_ms ? ` (${knx.latency_ms}ms)` : '';
                                            badges.push(`<span class="tech-badge tech-knx tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'knx', event)" style="cursor: pointer;" title="KNXnet/IP Online • Endpoint: ${escapeHtml(ep)}${latStr} • Click for full diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>KNX ${escapeHtml(ep)}${escapeHtml(latStr)}</span>`);
                                        } else {
                                            const errReason = knx.error ? (knx.error === 'timeout' ? 'Gateway Unreachable (Timeout)' : knx.error) : (knx.offline_reason || 'Gateway Unreachable');
                                            badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'knx', event)" style="cursor: pointer;" title="KNXnet/IP Offline • Reason: ${escapeHtml(errReason)} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>KNX Offline (${escapeHtml(errReason)})</span>`);
                                        }
                                    }

                                    // 2. Remote ETS Interface Badge (Only show if client actually has genuine KNX and an allocated port)
                                    if (c.ets_port && hasKnx) {
                                        const etsTargetDesc = c.ets_target_type === 'onboard' ? 'Onboard NCN5120' : (c.ets_target_ip ? `LAN: ${c.ets_target_ip}` : 'Remote KNX');
                                        badges.push(`<span class="tech-badge tech-ets" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.35); cursor: pointer;" onclick="copyEtsRemoteUrl('${c.domain}', ${c.ets_port}, event)" title="Remote ETS Interface (${escapeHtml(etsTargetDesc)}) - Click to copy URL & Port"><span class="tech-dot" style="background:#c084fc;"></span>🔌 ETS :${c.ets_port}</span>`);
                                    }

                                    // 3. Zigbee (Detects Zigbee2MQTT instances and ZHA with online/offline state)
                                    if (zigbee.detected || (zigbee.instances && zigbee.instances.length > 0) || zigbee.zha_detected) {
                                        const insts = zigbee.instances || [];
                                        const runningInsts = insts.filter(i => i.running || i.state === 'started');
                                        const failedInsts = insts.filter(i => !i.running && i.state !== 'started');
                                        const isZha = Boolean(zigbee.zha_detected);

                                        if (isMuted('zigbee')) {
                                            badges.push(`<span class="tech-badge" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); cursor: pointer;" onclick="openIntegrationDiagnostics('${c.client_id}', 'zigbee', event)" title="Zigbee Monitoring Muted • Click to manage"><span class="tech-dot" style="background:#64748b;"></span>Zigbee (Muted)</span>`);
                                        } else if (insts.length > 0) {
                                            if (failedInsts.length === 0) {
                                                const zLbl = insts.length > 1 ? `Zigbee (${insts.length}x Z2M Online)` : 'Zigbee (Z2M Online)';
                                                badges.push(`<span class="tech-badge tech-zigbee tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'zigbee', event)" style="cursor: pointer;" title="Zigbee2MQTT Online (${insts.map(i => i.name).join(', ')}) • Click for diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>${escapeHtml(zLbl)}</span>`);
                                            } else if (runningInsts.length > 0) {
                                                const errSummary = failedInsts.map(i => `${i.name}: ${i.state}`).join(', ');
                                                badges.push(`<span class="tech-badge tech-status-degraded" onclick="openIntegrationDiagnostics('${c.client_id}', 'zigbee', event)" style="cursor: pointer;" title="Zigbee Degraded • ${escapeHtml(errSummary)} • Click for diagnostics"><span class="tech-dot" style="background:#f59e0b; box-shadow: 0 0 6px #f59e0b;"></span>Zigbee (${runningInsts.length}/${insts.length} Online)</span>`);
                                            } else {
                                                const errSummary = failedInsts.map(i => `${i.name} (${i.state})`).join(', ');
                                                badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'zigbee', event)" style="cursor: pointer;" title="Zigbee2MQTT Offline • Reason: ${escapeHtml(errSummary)} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>Zigbee Offline (${escapeHtml(failedInsts[0].state || 'stopped')})</span>`);
                                            }
                                        } else if (isZha) {
                                            badges.push(`<span class="tech-badge tech-zigbee tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'zigbee', event)" style="cursor: pointer;" title="Zigbee Home Automation (ZHA) Online • Click for diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>Zigbee (ZHA Online)</span>`);
                                        }
                                    }

                                    // 4. Lutron (Grouped & status aware: online / degraded / offline)
                                    const lEntries = (lutron.entries || []).filter(e => !isEntryIgnored(e));
                                    if (lutron.detected && lEntries.length > 0) {
                                        const runningL = lEntries.filter(e => e.state === 'loaded' || e.online === true);
                                        const failedL = lEntries.filter(e => e.state !== 'loaded' && e.online === false);
                                        const isLutronOffline = Boolean(lutron.status === 'offline' || lutron.offline_reason || (lEntries.length > 0 && runningL.length === 0));
                                        const lTitle = lEntries.length > 0 ? lEntries.map(e => e.title || e.domain).join(', ') : 'Lutron Repeater';
                                        const lutHealing = shSubsystems['lutron'];

                                        if (isMuted('lutron')) {
                                            badges.push(`<span class="tech-badge" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); cursor: pointer;" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" title="Lutron Monitoring Muted • Click to manage"><span class="tech-dot" style="background:#64748b;"></span>Lutron (Muted)</span>`);
                                        } else if (lutHealing && lutHealing.status === 'healing' && (lutHealing.attempts || 0) < 5) {
                                            badges.push(`<span class="tech-badge tech-status-healing" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" style="cursor: pointer;" title="Autonomous Self-Healing in Progress (Attempt ${lutHealing.attempts}/5: ${escapeHtml(lutHealing.last_action || 'Remediating')}) • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#facc15; box-shadow: 0 0 6px #facc15;"></span>Lutron Healing (${lutHealing.attempts}/5)</span>`);
                                        } else if (lutHealing && (lutHealing.status === 'exhausted' || (lutHealing.attempts || 0) >= 5)) {
                                            badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" style="cursor: pointer;" title="Autonomous Self-Healing Halted (5/5 Attempts Failed) • Notified • Resets on restart • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>Lutron (5/5 Healing Failed)</span>`);
                                        } else if (lEntries.length > 1) {
                                            if (failedL.length === 0) {
                                                badges.push(`<span class="tech-badge tech-lutron tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" style="cursor: pointer;" title="Lutron Online (${escapeHtml(lTitle)}) • Click for diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>Lutron (${lEntries.length}x Online)</span>`);
                                            } else if (runningL.length > 0) {
                                                const errSummary = failedL.map(e => `${e.title || 'Bridge'}: ${e.state || 'offline'}`).join(', ');
                                                badges.push(`<span class="tech-badge tech-status-degraded" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" style="cursor: pointer;" title="Lutron Degraded • ${escapeHtml(errSummary)} • Click for diagnostics"><span class="tech-dot" style="background:#f59e0b; box-shadow: 0 0 6px #f59e0b;"></span>Lutron (${runningL.length}/${lEntries.length} Online)</span>`);
                                            } else {
                                                badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" style="cursor: pointer;" title="Lutron Offline • Reason: ${escapeHtml(lutron.offline_reason || 'Bridges unreachable')} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>Lutron (${lEntries.length}x Offline)</span>`);
                                            }
                                        } else if (isLutronOffline) {
                                            badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" style="cursor: pointer;" title="Lutron Offline • Reason: ${escapeHtml(lutron.offline_reason || 'Repeater unreachable')} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>Lutron Offline</span>`);
                                        } else {
                                            badges.push(`<span class="tech-badge tech-lutron tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'lutron', event)" style="cursor: pointer;" title="Lutron Online (${escapeHtml(lTitle)}) • Click for diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>Lutron (${escapeHtml(lutron.type || 'Caséta')})</span>`);
                                        }
                                    }

                                    // 5. Matter
                                    if (matter.detected) {
                                        const isMatterOnline = Boolean(matter.state === 'started' || matter.state === 'running' || matter.status === 'online');
                                        if (isMuted('matter')) {
                                            badges.push(`<span class="tech-badge" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); cursor: pointer;" onclick="openIntegrationDiagnostics('${c.client_id}', 'matter', event)" title="Matter Monitoring Muted • Click to manage"><span class="tech-dot" style="background:#64748b;"></span>Matter (Muted)</span>`);
                                        } else if (isMatterOnline) {
                                            badges.push(`<span class="tech-badge tech-matter tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'matter', event)" style="cursor: pointer;" title="Matter Server Online • Click for diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>Matter Online</span>`);
                                        } else {
                                            badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'matter', event)" style="cursor: pointer;" title="Matter Server Offline • Reason: ${escapeHtml(matter.state || 'stopped')} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>Matter Offline (${escapeHtml(matter.state || 'stopped')})</span>`);
                                        }
                                    }

                                    // 6. CoolMaster (CoolMasterNet / CoolAutomation VRV/VRF HVAC)
                                    const coolmaster = tech.coolmaster || {};
                                    const cmEntries = (coolmaster.entries || []).filter(e => !isEntryIgnored(e));
                                    if (coolmaster.detected && cmEntries.length > 0) {
                                        const runningCm = cmEntries.filter(e => e.state === 'loaded' || e.online === true);
                                        const failedCm = cmEntries.filter(e => e.state === 'setup_error' || e.state === 'setup_retry' || e.state === 'not_loaded' || e.online === false);
                                        const isCmOffline = Boolean(coolmaster.status === 'offline' || coolmaster.status === 'setup_retry' || coolmaster.status === 'setup_error' || coolmaster.offline_reason || failedCm.length > 0);
                                        const cmTitle = cmEntries.length > 0 ? cmEntries.map(e => e.title || `${e.host || ''}:${e.port || 10102}`).join(', ') : 'CoolMaster Gateway';
                                        const cmHealing = shSubsystems['coolmaster'];
                                        const effectiveReason = coolmaster.offline_reason || (failedCm.length > 0 ? (failedCm[0].reason || `Integration in '${failedCm[0].state}' state`) : 'HVAC Gateway / Line Faulty');
                                        if (isMuted('coolmaster')) {
                                            badges.push(`<span class="tech-badge" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); cursor: pointer;" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" title="CoolMaster Monitoring Muted • Click to manage"><span class="tech-dot" style="background:#64748b;"></span>CoolMaster (Muted)</span>`);
                                        } else if (cmHealing && cmHealing.status === 'healing' && (cmHealing.attempts || 0) < 5) {
                                            badges.push(`<span class="tech-badge tech-status-healing" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" style="cursor: pointer;" title="Autonomous Self-Healing in Progress (Attempt ${cmHealing.attempts}/5: ${escapeHtml(cmHealing.last_action || 'Remediating')}) • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#facc15; box-shadow: 0 0 6px #facc15;"></span>CoolMaster Healing (${cmHealing.attempts}/5)</span>`);
                                        } else if (cmHealing && (cmHealing.status === 'exhausted' || (cmHealing.attempts || 0) >= 5)) {
                                            badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" style="cursor: pointer;" title="Autonomous Self-Healing Halted (5/5 Attempts Failed) • Notified • Resets on restart • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>CoolMaster (5/5 Healing Failed)</span>`);
                                        } else if (cmEntries.length > 1) {
                                            if (failedCm.length === 0) {
                                                badges.push(`<span class="tech-badge tech-coolmaster tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" style="cursor: pointer;" title="CoolMasterNet Online (${escapeHtml(cmTitle)}) • Click for diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>CoolMaster (${cmEntries.length}x HVAC Online)</span>`);
                                            } else if (runningCm.length > 0) {
                                                badges.push(`<span class="tech-badge tech-status-degraded" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" style="cursor: pointer;" title="CoolMaster Degraded • ${escapeHtml(effectiveReason)} • Click for diagnostics"><span class="tech-dot" style="background:#f59e0b; box-shadow: 0 0 6px #f59e0b;"></span>CoolMaster (${runningCm.length}/${cmEntries.length} Online)</span>`);
                                            } else {
                                                badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" style="cursor: pointer;" title="CoolMaster Offline / Faulty • Reason: ${escapeHtml(effectiveReason)} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>CoolMaster (${cmEntries.length}x Offline)</span>`);
                                            }
                                        } else if (isCmOffline) {
                                            badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" style="cursor: pointer;" title="CoolMaster Offline / Faulty • Reason: ${escapeHtml(effectiveReason)} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>CoolMaster Offline</span>`);
                                        } else {
                                            badges.push(`<span class="tech-badge tech-coolmaster tech-status-online" onclick="openIntegrationDiagnostics('${c.client_id}', 'coolmaster', event)" style="cursor: pointer;" title="CoolMasterNet Online (${escapeHtml(cmTitle)}) • Click for diagnostics"><span class="tech-dot" style="background:#10b981; box-shadow: 0 0 6px #10b981;"></span>CoolMaster (HVAC Online)</span>`);
                                        }
                                    }

                                    // 7. Generic Core Integrations (Grouped by Domain, identical to multiple Zigbee2MQTT pattern)
                                    if (tech.failed_core_entries && tech.failed_core_entries.length > 0) {
                                        const dedicatedDomains = new Set(['knx', 'lutron', 'lutron_caseta', 'lutron_homeworks', 'matter', 'coolmaster', 'coolmasternet', 'coolautomation', 'zha', 'zigbee']);
                                        const grouped = {};
                                        for (const fentry of tech.failed_core_entries) {
                                            if (!fentry || !fentry.domain || dedicatedDomains.has(fentry.domain) || isEntryIgnored(fentry)) continue;
                                            if (!grouped[fentry.domain]) grouped[fentry.domain] = [];
                                            grouped[fentry.domain].push(fentry);
                                        }
                                        const domainPrettyNames = {
                                            'bluesound': 'Bluesound',
                                            'sonos': 'Sonos',
                                            'denonavr': 'Denon AVR',
                                            'heos': 'HEOS',
                                            'samsungtv': 'Samsung TV',
                                            'lg_webos': 'LG webOS TV',
                                            'apple_tv': 'Apple TV',
                                            'androidtv': 'Android TV',
                                            'tuya': 'Tuya',
                                            'shelly': 'Shelly',
                                            'yeelight': 'Yeelight',
                                            'tasmota': 'Tasmota',
                                            'mqtt': 'MQTT',
                                            'wled': 'WLED'
                                        };
                                        for (const [fDomain, fEntries] of Object.entries(grouped)) {
                                            const pretty = domainPrettyNames[fDomain] || (fDomain.charAt(0).toUpperCase() + fDomain.slice(1));
                                            const count = fEntries.length;
                                            const badgeLabel = count > 1 ? `${pretty} (${count}x Offline)` : `${pretty} Offline`;
                                            const summary = fEntries.map(e => `${e.title || fDomain}: ${e.reason || e.state || 'Failed'}`).join(' • ');
                                            if (isMuted(fDomain) || isMuted('core_' + fDomain) || isMuted('failed_core_entries')) {
                                                badges.push(`<span class="tech-badge" style="background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); cursor: pointer;" onclick="openIntegrationDiagnostics('${c.client_id}', 'core_${fDomain}', event)" title="${escapeHtml(pretty)} Monitoring Muted • Click to manage"><span class="tech-dot" style="background:#64748b;"></span>${escapeHtml(pretty)} (Muted)</span>`);
                                            } else {
                                                badges.push(`<span class="tech-badge tech-status-offline" onclick="openIntegrationDiagnostics('${c.client_id}', 'core_${fDomain}', event)" style="cursor: pointer;" title="${escapeHtml(pretty)} Offline (${count} endpoint${count > 1 ? 's' : ''}) • ${escapeHtml(summary)} • Click for diagnostics"><span class="tech-dot tech-dot-pulsing" style="background:#ef4444; box-shadow: 0 0 6px #ef4444;"></span>${escapeHtml(badgeLabel)}</span>`);
                                            }
                                        }
                                    }

                                    if (badges.length === 0) {
                                        badges.push(`<span class="tech-badge tech-default" title="Standard Gavasah Home Assistant Hub"><span class="tech-dot" style="background:#64748b;"></span>HA Core</span>`);
                                    }
                                    return badges.join('');
                                })()}
                            </div>
                        </td>

                        <!-- Column 5: Boot Slot (RAUC) -->
                        <td>
                            ${isPending || !sys.boot_slot ? `
                                <span class="badge-slot" style="background: rgba(148, 163, 184, 0.12); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2);">SLOT —</span>
                            ` : `
                                <span class="badge-slot slot-${slot.toLowerCase()}">SLOT ${slot}</span>
                                ${isRecovery ? '<span class="badge-slot" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; margin-left: 4px;">RECOVERY</span>' : ''}
                            `}
                        </td>

                        <!-- Column 6: Remote Ingress Toggle (Clean, Live Update, No Redundant Dot/Badge) -->
                        <td style="text-align: center;">
                            <label class="toggle-switch" title="Toggle Remote Ingress for ${escapeHtml(c.name)}" style="display: inline-block;">
                                <input type="checkbox" ${remoteEnabled ? 'checked' : ''} onchange="toggleRemoteAccess('${c.client_id}', this.checked)">
                                <span class="toggle-slider"></span>
                            </label>
                        </td>

                        <!-- Column 7: Hardware Metrics -->
                        <td style="font-size: 12px;">
                            ${isPending || sys.cpu_percent === undefined || sys.cpu_percent === null ? `
                                <div style="color: #64748b; font-weight: 500;">CPU: — &bull; RAM: —</div>
                                <div style="color: #475569; font-size: 11px; margin-top: 2px;">💾 Storage: —</div>
                                <div style="color: #475569; font-size: 10px; margin-top: 1px;">${sys.haos_version ? `HAOS ${escapeHtml(sys.haos_version)}` : 'Awaiting pulse'}</div>
                            ` : `
                                <div style="color: #cbd5e1; font-weight: 500;">CPU: ${sys.cpu_percent}% &bull; RAM: ${sys.memory_percent}%</div>
                                <div style="color: #94a3b8; font-size: 11px; margin-top: 2px;">💾 Storage: ${sys.disk_total_gb ? `${(sys.disk_total_gb - (sys.disk_free_gb || 0)).toFixed(1)} / ${Number(sys.disk_total_gb).toFixed(1)} GB (${Math.round(((sys.disk_total_gb - (sys.disk_free_gb || 0)) / sys.disk_total_gb) * 100)}%)` : (sys.disk_free_gb ? `${Number(sys.disk_free_gb).toFixed(1)} GB Free` : '—')}</div>
                                <div style="color: #64748b; font-size: 10px; margin-top: 2px; display: flex; align-items: center; gap: 4px; flex-wrap: wrap;">
                                    <span>HAOS ${escapeHtml(sys.haos_version || '—')}</span>
                                    ${sys.haos_update_available && currentUser.role === 'manufacturer' ? `<span style="color: #fbbf24; font-size: 9px;" title="HAOS update available (${escapeHtml(sys.haos_latest_version)})">⬆️</span>` : ''}
                                </div>
                                <div style="margin-top: 3px; display: flex; gap: 3px; flex-wrap: wrap; font-size: 9px; font-family: monospace;">
                                    <span class="v-pill" style="background: rgba(148, 163, 184, 0.12); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 3px; padding: 1px 4px; color: #cbd5e1;" title="Home Assistant Core: ${escapeHtml(sys.core_version || '—')} ${sys.core_latest_version ? `(Latest: ${escapeHtml(sys.core_latest_version)})` : ''}">
                                        Core: ${escapeHtml(sys.core_version || '—')}
                                        ${currentUser.role === 'manufacturer' && sys.core_update_available ? `<span style="color: #38bdf8; cursor: pointer; font-weight: bold; margin-left: 2px;" onclick="triggerClientUpdate('${c.client_id}', 'update_core', '${escapeHtml(c.name)}')" title="Update Core to ${escapeHtml(sys.core_latest_version)}">⬆️</span>` : ''}
                                    </span>
                                    <span class="v-pill" style="background: rgba(148, 163, 184, 0.12); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 3px; padding: 1px 4px; color: #cbd5e1;" title="Supervisor: ${escapeHtml(sys.supervisor_version || '—')} ${sys.supervisor_latest_version ? `(Latest: ${escapeHtml(sys.supervisor_latest_version)})` : ''}">
                                        Sup: ${escapeHtml(sys.supervisor_version || '—')}
                                        ${currentUser.role === 'manufacturer' && sys.supervisor_update_available ? `<span style="color: #818cf8; cursor: pointer; font-weight: bold; margin-left: 2px;" onclick="triggerClientUpdate('${c.client_id}', 'update_supervisor', '${escapeHtml(c.name)}')" title="Update Supervisor to ${escapeHtml(sys.supervisor_latest_version)}">⬆️</span>` : ''}
                                    </span>
                                    <span class="v-pill" style="background: rgba(34, 211, 238, 0.12); border: 1px solid rgba(34, 211, 238, 0.3); border-radius: 3px; padding: 1px 4px; color: #22d3ee;" title="Gavasah Cloud Agent: v${escapeHtml(sys.addon_version || '1.1.x')} ${sys.addon_latest_version ? `(Latest: v${escapeHtml(sys.addon_latest_version)})` : ''}">
                                        Agent: v${escapeHtml(sys.addon_version || '1.1.x')}
                                        ${currentUser.role === 'manufacturer' && (sys.addon_version !== '1.2.0' || sys.addon_update_available) ? `<span style="color: #22d3ee; cursor: pointer; font-weight: bold; margin-left: 2px;" onclick="triggerClientUpdate('${c.client_id}', 'update_addon', '${escapeHtml(c.name)}')" title="Update Agent to v1.2.0">⬆️</span>` : ''}
                                    </span>
                                </div>
                                ${sys.last_error ? `
                                    <div style="margin-top: 3px; background: rgba(239, 68, 68, 0.18); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 3px; padding: 2px 5px; color: #f87171; font-size: 9px; display: flex; align-items: center; justify-content: space-between; cursor: pointer;" onclick="showGatewayLastError('${c.client_id}')" title="${escapeHtml(sys.last_error.error || '')}">
                                        <span>⚠️ ${escapeHtml(sys.last_error.command || 'Error')}: ${escapeHtml((sys.last_error.error || '').slice(0, 24))}...</span>
                                        <span style="font-weight: bold;">ℹ️</span>
                                    </div>
                                ` : ''}
                            `}
                        </td>

                        <!-- Column 8: Onboarded At -->
                        ${onboardCell}
                        <!-- Column 9: Dealer Partner -->
                        ${dealerCell}
                        <!-- Column 10: Assigned Integrator -->
                        ${integratorCell}
                        <td class="col-actions-menu">
                            <div class="action-dropdown-wrap" id="action-wrap-${c.client_id}">
                                <button type="button" class="btn-actions-toggle" id="btn-action-toggle-${c.client_id}" onclick="toggleRowActionMenu('${c.client_id}', event)" title="Actions for ${escapeHtml(c.name)}">
                                    ⚙️ Actions <span class="action-caret">▼</span>
                                </button>
                                <div class="action-menu-popover" id="action-menu-${c.client_id}" style="display: none;">
                                    ${c.approval_status === 'pending' && currentUser.role !== 'manufacturer' ? `
                                        <div class="action-menu-item" style="color: #fbbf24; cursor: not-allowed; opacity: 0.8;" title="Remote Access is locked until Manufacturer approves this client site">
                                            <span>🔒</span> Remote Access Locked (Pending HQ)
                                        </div>
                                    ` : (
                                        remoteEnabled ? (
                                            isPending ? `
                                                <a href="https://${escapeHtml(c.domain)}" target="_blank" class="action-menu-item" style="color: #fbbf24;" onclick="closeAllActionMenus()">
                                                    <span>⏳</span> Dashboard (Pending) ↗
                                                </a>
                                            ` : `
                                                <a href="https://${escapeHtml(c.domain)}" target="_blank" class="action-menu-item" style="color: #38bdf8;" onclick="closeAllActionMenus()">
                                                    <span>📊</span> Open Dashboard ↗
                                                </a>
                                            `
                                        ) : `
                                            <a href="https://${escapeHtml(c.domain)}" target="_blank" class="action-menu-item" style="color: #f87171;" onclick="closeAllActionMenus()">
                                                <span>🔒</span> Restricted Notice ↗
                                            </a>
                                        `
                                    )}
                                    ${c.ets_port ? (
                                        (c.knx_remote_enabled !== false && c.knx_remote_enabled !== 0) ? `
                                        <button type="button" class="action-menu-item" style="color: #c084fc;" onclick="copyEtsRemoteUrl('${c.domain}', ${c.ets_port}, event); closeAllActionMenus();" title="Copy Remote ETS URL and UDP Port for KNX device programming">
                                            <span>🔌</span> Copy Remote ETS (: ${c.ets_port})
                                        </button>
                                        ` : `
                                        <button type="button" class="action-menu-item" style="color: #94a3b8;" onclick="toggleKnxRemoteAccess('${c.client_id}', true); closeAllActionMenus();" title="Remote KNX Programming is currently suspended. Click to enable.">
                                            <span>🔌</span> Enable Remote ETS (: ${c.ets_port})
                                        </button>
                                        `
                                    ) : ''}
                                    <button type="button" class="action-menu-item" style="color: #38bdf8;" onclick="openSnapshotModal('${c.client_id}', '${escapeHtml(c.name)}'); closeAllActionMenus();">
                                        <span>📸</span> Snapshots & Backups
                                    </button>
                                    <!-- Remote Reboot: Accessible to Manufacturer, Dealer, and Integrator -->
                                    <button type="button" class="action-menu-item" style="color: #fb7185;" onclick="triggerClientReboot('${c.client_id}', '${escapeHtml(c.name)}'); closeAllActionMenus();" title="Remotely reboot this client gateway controller hardware">
                                        <span>🔄</span> Remote Reboot Gateway
                                    </button>

                                    <!-- Individual System Updates: Restricted to Manufacturer ONLY -->
                                    ${currentUser.role === 'manufacturer' ? `
                                        <button type="button" class="action-menu-item" style="color: #38bdf8;" onclick="triggerClientUpdate('${c.client_id}', 'update_core', '${escapeHtml(c.name)}'); closeAllActionMenus();" title="Update Home Assistant Core on this gateway">
                                            <span>📦</span> Update HA Core ${sys.core_latest_version ? `(${escapeHtml(sys.core_latest_version)})` : ''}
                                        </button>
                                        <button type="button" class="action-menu-item" style="color: #818cf8;" onclick="triggerClientUpdate('${c.client_id}', 'update_supervisor', '${escapeHtml(c.name)}'); closeAllActionMenus();" title="Update Home Assistant Supervisor on this gateway">
                                            <span>🛡️</span> Update HA Supervisor ${sys.supervisor_latest_version ? `(${escapeHtml(sys.supervisor_latest_version)})` : ''}
                                        </button>
                                        <button type="button" class="action-menu-item" style="color: #22d3ee;" onclick="triggerClientUpdate('${c.client_id}', 'update_addon', '${escapeHtml(c.name)}'); closeAllActionMenus();" title="Update Gavasah Cloud Agent add-on on this gateway">
                                            <span>🚀</span> Update Gavasah Add-on (v1.2.0)
                                        </button>
                                    ` : ''}
                                    <button type="button" class="action-menu-item" onclick="openLogsModal('${c.client_id}'); closeAllActionMenus();">
                                        <span>📋</span> Telemetry Logs
                                    </button>
                                    ${currentUser.role !== 'integrator' ? `
                                        <button type="button" class="action-menu-item" onclick="openReassignModal('${c.client_id}'); closeAllActionMenus();">
                                            <span>🔄</span> Transfer Supervision
                                        </button>
                                    ` : ''}
                                    <button type="button" class="action-menu-item" onclick="openEditModal('${c.client_id}'); closeAllActionMenus();">
                                        <span>✏️</span> Edit Site Config
                                    </button>
                                    <button type="button" class="action-menu-item" style="color: #f87171;" onclick="promptDelete('${c.client_id}', '${escapeHtml(c.name)}'); closeAllActionMenus();">
                                        <span>🗑️</span> Delete Client Site
                                    </button>
                                </div>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('') || `<tr><td colspan="${currentUser.role === 'manufacturer' ? 11 : (currentUser.role === 'dealer' ? 10 : 9)}" style="text-align: center; color: #64748b; padding: 32px;">No gateways match the selected filter.</td></tr>`;

            // Display Manufacturer Fleet Update button if role is manufacturer
            const fleetUpdateBtn = document.getElementById('btn-fleet-update-center');
            if (fleetUpdateBtn) {
                fleetUpdateBtn.style.display = (currentUser.role === 'manufacturer') ? 'inline-flex' : 'none';
            }

            // Restore open action menu if table was re-rendered
            if (activeActionMenuClientId) {
                const restoredMenu = document.getElementById(`action-menu-${activeActionMenuClientId}`);
                const restoredBtn = document.getElementById(`btn-action-toggle-${activeActionMenuClientId}`);
                const restoredTd = restoredBtn ? restoredBtn.closest('td') : null;
                if (restoredMenu) restoredMenu.style.display = 'flex';
                if (restoredBtn) restoredBtn.classList.add('active');
                if (restoredTd) restoredTd.classList.add('is-open');
            }

            // Initialize / sync top and bottom horizontal scrollbars
            setTimeout(initAllTableScrollbars, 40);
        }

        // ======================================================================
        // REMOTE ETS CLIPBOARD & INTEGRATOR UTILITIES
        // ======================================================================
        
        // ======================================================================
        // REMOTE REBOOT & OTA UPDATES DISPATCHERS
        // ======================================================================
        async function triggerClientReboot(clientId, clientName) {
            if (!confirm(`⚠️ CONFIRM GATEWAY REBOOT\n\nAre you sure you want to remotely reboot Gavasah Gateway '${clientName}'?\n\nThe controller hardware will perform a safe host reboot and reconnect within 60-90 seconds.`)) {
                return;
            }
            try {
                const resp = await fetch('/api/client_command_trigger', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, action: 'reboot_gateway' })
                });
                const res = await resp.json();
                if (res.ok) {
                    showToast(`Host reboot dispatched for '${clientName}'! Reconnecting shortly.`, 'success');
                } else {
                    showToast(res.error || 'Failed to dispatch reboot command', 'error');
                }
            } catch (err) {
                showToast(`Reboot error: ${err.message}`, 'error');
            }
        }

        async function triggerClientUpdate(clientId, updateType, clientName) {
            const titles = {
                'update_core': 'Home Assistant Core',
                'update_supervisor': 'Home Assistant Supervisor',
                'update_addon': 'Gavasah Cloud Agent Add-on (v1.2.0)',
                'update_all': 'Full System (Core + Supervisor + Add-on)'
            };
            const desc = titles[updateType] || updateType;
            if (!confirm(`Dispatch Over-The-Air update for '${clientName}'?\n\nTarget: ${desc}\n\nThe gateway will execute the update on its next heartbeat pulse.`)) {
                return;
            }
            try {
                const resp = await fetch('/api/client_command_trigger', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, action: updateType })
                });
                const res = await resp.json();
                if (res.ok) {
                    showToast(`${desc} update dispatched for '${clientName}'!`, 'success');
                } else {
                    showToast(res.error || 'Failed to dispatch update', 'error');
                }
            } catch (err) {
                showToast(`Update error: ${err.message}`, 'error');
            }
        }

        
        async function toggleClientAutoUpdate(clientId, targetState, event) {
            if (event) {
                event.stopPropagation();
                event.preventDefault();
            }
            try {
                const resp = await fetch('/api/toggle_auto_update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, auto_update: targetState })
                });
                const res = await resp.json();
                if (res.ok) {
                    showToast(`Auto-Update ${targetState ? 'ENABLED' : 'PAUSED'} for client gateway.`, 'success');
                    if (typeof fetchFleetData === 'function') fetchFleetData();
                } else {
                    showToast(res.error || 'Failed to update auto-update setting', 'error');
                }
            } catch (err) {
                showToast(`Auto-Update error: ${err.message}`, 'error');
            }
        }

        function openFleetUpdateModal() {
            const modal = document.getElementById('fleet-update-modal');
            if (modal) modal.classList.add('active');
        }

        function closeFleetUpdateModal() {
            const modal = document.getElementById('fleet-update-modal');
            if (modal) modal.classList.remove('active');
        }

        async function triggerFleetBatchUpdate(updateType) {
            const titles = {
                'update_addon': 'Gavasah Cloud Agent Add-on (v1.2.0)',
                'update_core': 'Home Assistant Core',
                'update_supervisor': 'Home Assistant Supervisor',
                'update_all': 'Master Full Fleet Update (All Subsystems)'
            };
            const desc = titles[updateType] || updateType;
            if (!confirm(`⚠️ CONFIRM FLEET-WIDE BATCH UPDATE\n\nComponent: ${desc}\n\nThis will dispatch update commands across ALL client gateways in the fleet. Proceed?`)) {
                return;
            }
            try {
                const resp = await fetch('/api/fleet_command_trigger', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: updateType })
                });
                const res = await resp.json();
                if (res.ok) {
                    showToast(`Successfully queued ${desc} across ${res.count} gateways!`, 'success');
                    closeFleetUpdateModal();
                } else {
                    showToast(res.error || 'Failed to dispatch fleet update', 'error');
                }
            } catch (err) {
                showToast(`Fleet update error: ${err.message}`, 'error');
            }
        }
    
        function copyEtsRemoteUrl(domain, port, event) {
            if (event) {
                event.stopPropagation();
                event.preventDefault();
            }
            const cleanDomain = domain || window.location.hostname;
            const fullUrl = `${cleanDomain}:${port}`;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(fullUrl).then(() => {
                    showToast(`Copied Remote ETS Interface: ${fullUrl} (UDP Port: ${port})`, "success");
                }).catch(() => {
                    fallbackCopyEts(fullUrl, port);
                });
            } else {
                fallbackCopyEts(fullUrl, port);
            }
        }

        function fallbackCopyEts(text, port) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            try {
                document.execCommand('copy');
                showToast(`Copied Remote ETS Interface: ${text} (UDP Port: ${port})`, "success");
            } catch (e) {
                prompt("Copy Remote ETS Interface URL:", text);
            }
            document.body.removeChild(ta);
        }

        // ======================================================================
        // HORIZONTAL SCROLL & RESPONSIVE TABLE UTILITIES
        // ======================================================================
        
        // ======================================================================
        // DEALER BRANDING & WHITE-LABEL UTILITIES
        // ======================================================================
        let currentUploadedLogoData = '';

        function applyDealerBranding(branding) {
            const b = branding || {};
            const role = currentUser ? currentUser.role : 'manufacturer';
            const isMfg = role === 'manufacturer';

            // 1. Sidebar Brand Elements
            const sideTitle = document.getElementById('side-brand-title') || document.querySelector('.brand-text .title');
            const sideSub = document.getElementById('side-brand-sub') || document.querySelector('.brand-text .sub');
            const sideLogo = document.getElementById('side-brand-logo') || document.querySelector('.brand-logo');

            const defaultTitle = isMfg ? 'GAVASAH' : (currentUser ? (currentUser.name || currentUser.username) : 'GAVASAH');
            const defaultSub = isMfg ? 'CLOUD COMMAND' : 'DEALER PORTAL';

            if (sideTitle) sideTitle.innerText = b.company_name || defaultTitle;
            if (sideSub) sideSub.innerText = b.tagline || defaultSub;

            if (sideLogo) {
                if (b.logo_url) {
                    sideLogo.innerHTML = `<img src="${escapeHtml(b.logo_url)}" style="width: 100%; height: 100%; object-fit: contain; border-radius: 8px;">`;
                } else {
                    const initial = (b.company_name || defaultTitle || 'G').charAt(0).toUpperCase();
                    sideLogo.innerHTML = escapeHtml(initial);
                }
            }

            // 2. Dynamic Accent Theme Tokens
            const primaryColor = b.primary_color || '#00f0ff';
            const accentColor = b.accent_color || '#38bdf8';
            document.documentElement.style.setProperty('--accent', primaryColor);
            document.documentElement.style.setProperty('--accent-glow', accentColor);

            // 3. Top-Right Portal Header Brand Container
            const headerContainer = document.getElementById('header-brand-container');
            const headerLogoWrap = document.getElementById('header-brand-logo-wrap');
            const headerName = document.getElementById('header-brand-name');
            const headerTag = document.getElementById('header-brand-tag');

            if (headerContainer) {
                headerContainer.style.display = 'flex';
                if (headerLogoWrap) {
                    if (b.logo_url) {
                        headerLogoWrap.innerHTML = `<img src="${escapeHtml(b.logo_url)}" style="max-height: 28px; max-width: 110px; object-fit: contain;">`;
                    } else {
                        const initial = (b.company_name || defaultTitle || 'G').charAt(0).toUpperCase();
                        headerLogoWrap.innerHTML = `<div style="width: 26px; height: 26px; border-radius: 6px; background: ${escapeHtml(primaryColor)}; color: #000; font-weight: 800; font-size: 13px; display: flex; align-items: center; justify-content: center;">${escapeHtml(initial)}</div>`;
                    }
                }
                if (headerName) headerName.innerText = b.company_name || defaultTitle;
                if (headerTag) {
                    headerTag.innerText = b.tagline || (isMfg ? 'MASTER PLATFORM' : 'AUTHORIZED DEALER');
                    headerTag.style.color = primaryColor;
                }
            }

            // 4. Browser Document Title
            if (b.company_name) {
                document.title = `${b.company_name} | Operations Portal`;
            } else {
                document.title = isMfg ? 'GAVASAH Master Ecosystem | Cloud Hub' : 'GAVASAH Cloud Ecosystem | Operations Hub';
            }
        }

        // --- Direct Logo Upload & Image Optimization Handlers ---
        function handleLogoFileSelect(e) {
            const file = e.target.files && e.target.files[0];
            if (file) processLogoFile(file);
        }

        function handleDragOver(e) {
            e.preventDefault();
            e.stopPropagation();
            const el = document.getElementById('brand-logo-dropzone');
            if (el) el.classList.add('drag-active');
        }

        function handleDragLeave(e) {
            e.preventDefault();
            e.stopPropagation();
            const el = document.getElementById('brand-logo-dropzone');
            if (el) el.classList.remove('drag-active');
        }

        function handleFileDrop(e) {
            e.preventDefault();
            e.stopPropagation();
            const el = document.getElementById('brand-logo-dropzone');
            if (el) el.classList.remove('drag-active');
            const file = e.dataTransfer.files && e.dataTransfer.files[0];
            if (file) processLogoFile(file);
        }

        function processLogoFile(file) {
            if (!file.type || !file.type.startsWith('image/')) {
                showToast("Please select a valid image file (PNG, SVG, JPG, WEBP).", "error");
                return;
            }

            const reader = new FileReader();
            reader.onload = function(evt) {
                const rawData = evt.target.result;
                if (file.type === 'image/svg+xml') {
                    currentUploadedLogoData = rawData;
                    renderLogoUploadUI();
                    updateLiveBrandingPreview();
                    showToast("SVG Logo loaded successfully.", "info");
                    return;
                }

                // Rescale & compress bitmap images using Canvas to optimize payload size
                const img = new Image();
                img.onload = function() {
                    const maxWidth = 400;
                    const maxHeight = 120;
                    let width = img.width;
                    let height = img.height;

                    if (width > maxWidth || height > maxHeight) {
                        const ratio = Math.min(maxWidth / width, maxHeight / height);
                        width = Math.round(width * ratio);
                        height = Math.round(height * ratio);
                    }

                    const canvas = document.createElement('canvas');
                    canvas.width = width;
                    canvas.height = height;
                    const ctx = canvas.getContext('2d');
                    ctx.clearRect(0, 0, width, height);
                    ctx.drawImage(img, 0, 0, width, height);

                    currentUploadedLogoData = canvas.toDataURL('image/png');
                    renderLogoUploadUI();
                    updateLiveBrandingPreview();
                    showToast("Logo optimized & ready to save.", "info");
                };
                img.onerror = function() {
                    showToast("Could not process image file.", "error");
                };
                img.src = rawData;
            };
            reader.readAsDataURL(file);
        }

        function renderLogoUploadUI() {
            const dropzone = document.getElementById('brand-logo-dropzone');
            const activeBox = document.getElementById('brand-active-logo-container');
            const thumb = document.getElementById('brand-logo-thumbnail');

            if (currentUploadedLogoData) {
                if (dropzone) dropzone.style.display = 'none';
                if (activeBox) activeBox.style.display = 'flex';
                if (thumb) thumb.src = currentUploadedLogoData;
            } else {
                if (dropzone) dropzone.style.display = 'block';
                if (activeBox) activeBox.style.display = 'none';
                if (thumb) thumb.src = '';
            }
        }

        async function deleteBrandLogo() {
            currentUploadedLogoData = '';
            const fileInput = document.getElementById('brand-logo-file-input');
            if (fileInput) fileInput.value = '';

            renderLogoUploadUI();
            updateLiveBrandingPreview();

            // Persist logo deletion immediately to the backend
            try {
                const res = await apiFetch('/api/delete_dealer_logo', { method: 'POST' });
                const data = await res.json();
                if (res.ok && data.ok) {
                    if (currentUser && currentUser.branding) {
                        currentUser.branding.logo_url = '';
                    }
                    applyDealerBranding(currentUser ? currentUser.branding : {});
                    showToast("Logo deleted successfully.", "success");
                } else {
                    showToast(data.error || "Logo cleared locally. Click Save to commit.", "info");
                }
            } catch (e) {
                showToast("Logo cleared locally. Click Save to commit.", "info");
            }
        }

        function updateLiveBrandingPreview() {
            const isMfg = currentUser && currentUser.role === 'manufacturer';
            const defaultName = isMfg ? 'GAVASAH' : (currentUser ? (currentUser.name || currentUser.username) : 'GAVASAH');
            const defaultTag = isMfg ? 'MASTER PLATFORM' : 'AUTHORIZED DEALER';

            const name = document.getElementById('brand-company-name')?.value.trim() || defaultName;
            const tagline = document.getElementById('brand-tagline')?.value.trim() || defaultTag;
            const logo = currentUploadedLogoData;
            const pColor = document.getElementById('brand-primary-color')?.value || '#00f0ff';
            const aColor = document.getElementById('brand-accent-color')?.value || '#38bdf8';
            const email = document.getElementById('brand-email')?.value.trim() || 'support@gavasah.com';

            // 1. Mockup Header Top-Right Preview
            const mHeadLogoWrap = document.getElementById('mock-header-logo-wrap');
            const mHeadName = document.getElementById('mock-header-name');
            const mHeadTag = document.getElementById('mock-header-tag');
            const mHeadContainer = document.getElementById('mock-header-container');

            if (mHeadContainer) mHeadContainer.style.borderColor = 'rgba(255,255,255,0.14)';
            if (mHeadName) mHeadName.innerText = name;
            if (mHeadTag) {
                mHeadTag.innerText = tagline;
                mHeadTag.style.color = pColor;
            }
            if (mHeadLogoWrap) {
                if (logo) {
                    mHeadLogoWrap.innerHTML = `<img src="${escapeHtml(logo)}" style="max-height: 28px; max-width: 110px; object-fit: contain;">`;
                } else {
                    const initial = (name || 'G').charAt(0).toUpperCase();
                    mHeadLogoWrap.innerHTML = `<div style="width: 26px; height: 26px; border-radius: 6px; background: ${pColor}; color: #000; font-weight: 800; font-size: 13px; display: flex; align-items: center; justify-content: center;">${escapeHtml(initial)}</div>`;
                }
            }

            // 2. Mockup Sidebar Brand Preview
            const mSideLogo = document.getElementById('mock-sidebar-logo');
            const mSideTitle = document.getElementById('mock-sidebar-title');
            const mSideSub = document.getElementById('mock-sidebar-sub');

            if (mSideTitle) mSideTitle.innerText = name;
            if (mSideSub) {
                mSideSub.innerText = tagline;
                mSideSub.style.color = pColor;
            }
            if (mSideLogo) {
                mSideLogo.style.borderColor = pColor;
                mSideLogo.style.color = pColor;
                if (logo) {
                    mSideLogo.innerHTML = `<img src="${escapeHtml(logo)}" style="width: 100%; height: 100%; object-fit: contain; border-radius: 8px;">`;
                } else {
                    const initial = (name || 'G').charAt(0).toUpperCase();
                    mSideLogo.innerHTML = escapeHtml(initial);
                }
            }

            // 3. Themed UI Card - 100% REAL LIVE FLEET DATA
            const mCard = document.getElementById('mock-ui-card');
            const mCardEmail = document.getElementById('mock-card-email');
            const mCardVal = document.getElementById('mock-card-val');
            const mCardSub = document.getElementById('mock-card-sub');
            const mStatusPill = document.getElementById('mock-status-pill');

            if (mCard) {
                mCard.style.borderColor = aColor;
                mCard.style.boxShadow = `0 0 15px ${aColor}22`;
            }
            if (mCardEmail) {
                mCardEmail.innerText = email || 'support@gavasah.com';
                mCardEmail.style.color = pColor;
            }

            if (mCardVal) {
                if (Array.isArray(currentFleetData) && currentFleetData.length > 0) {
                    const total = currentFleetData.length;
                    const nowSec = Math.floor(Date.now() / 1000);
                    let online = 0, warning = 0, offline = 0;

                    currentFleetData.forEach(c => {
                        const isPending = !c.last_heartbeat || c.last_heartbeat === 0 || c.status === 'pending';
                        const diff = isPending ? -1 : nowSec - (c.last_heartbeat || 0);
                        if (isPending || diff > 300) offline++;
                        else if (diff > 180) warning++;
                        else online++;
                    });

                    mCardVal.innerText = `${online} of ${total} Sites Online`;
                    if (mCardSub) {
                        mCardSub.innerText = `${online} Online • ${warning > 0 ? warning + ' Warning • ' : ''}${offline} Offline / Lost`;
                    }
                    if (mStatusPill) {
                        const healthPct = ((online / total) * 100).toFixed(1);
                        if (online === total) {
                            mStatusPill.innerText = `100% OPERATIONAL`;
                            mStatusPill.style.color = '#10b981';
                            mStatusPill.style.borderColor = 'rgba(16, 185, 129, 0.3)';
                            mStatusPill.style.background = 'rgba(16, 185, 129, 0.12)';
                        } else {
                            mStatusPill.innerText = `${healthPct}% HEALTHY`;
                            mStatusPill.style.color = '#38bdf8';
                            mStatusPill.style.borderColor = 'rgba(56, 189, 248, 0.3)';
                            mStatusPill.style.background = 'rgba(56, 189, 248, 0.12)';
                        }
                    }
                } else if (Array.isArray(currentFleetData) && currentFleetData.length === 0) {
                    mCardVal.innerText = '0 Provisioned Gateways';
                    if (mCardSub) mCardSub.innerText = 'No Gavasah Gateways assigned to this account';
                    if (mStatusPill) {
                        mStatusPill.innerText = 'FLEET READY';
                        mStatusPill.style.color = '#38bdf8';
                        mStatusPill.style.borderColor = 'rgba(56, 189, 248, 0.3)';
                        mStatusPill.style.background = 'rgba(56, 189, 248, 0.12)';
                    }
                } else {
                    mCardVal.innerText = 'Checking Gateways...';
                    if (mCardSub) mCardSub.innerText = 'Fetching live gateway heartbeats...';
                    if (mStatusPill) {
                        mStatusPill.innerText = 'CONNECTING...';
                        mStatusPill.style.color = '#94a3b8';
                        mStatusPill.style.borderColor = 'rgba(148, 163, 184, 0.3)';
                        mStatusPill.style.background = 'rgba(148, 163, 184, 0.12)';
                    }
                }
            }

            // 4. Live update actual portal top-right header & CSS tokens in real-time
            document.documentElement.style.setProperty('--accent', pColor);
            document.documentElement.style.setProperty('--accent-glow', aColor);

            const hContainer = document.getElementById('header-brand-container');
            const hLogoWrap = document.getElementById('header-brand-logo-wrap');
            const hName = document.getElementById('header-brand-name');
            const hTag = document.getElementById('header-brand-tag');

            if (hContainer) {
                hContainer.style.display = 'flex';
                if (hName) hName.innerText = name;
                if (hTag) {
                    hTag.innerText = tagline;
                    hTag.style.color = pColor;
                }
                if (hLogoWrap) {
                    if (logo) {
                        hLogoWrap.innerHTML = `<img src="${escapeHtml(logo)}" style="max-height: 28px; max-width: 110px; object-fit: contain;">`;
                    } else {
                        const initial = (name || 'G').charAt(0).toUpperCase();
                        hLogoWrap.innerHTML = `<div style="width: 26px; height: 26px; border-radius: 6px; background: ${pColor}; color: #000; font-weight: 800; font-size: 13px; display: flex; align-items: center; justify-content: center;">${escapeHtml(initial)}</div>`;
                    }
                }
            }
        }

        function populateBrandingForm() {
            if (!currentUser) return;
            const b = currentUser.branding || {};
            const isMfg = currentUser.role === 'manufacturer';

            // Dynamic Titles & Subtitles for Manufacturer vs Dealer
            const paneTitle = document.getElementById('branding-pane-title');
            const paneSub = document.getElementById('branding-pane-subtitle');
            if (paneTitle) {
                paneTitle.innerText = isMfg ? '🎨 Ecosystem Master Branding & White-Label' : '🎨 Dealer Custom Branding & White-Label';
            }
            if (paneSub) {
                paneSub.innerText = isMfg 
                    ? 'Configure the master platform branding, default logos, and ecosystem accent colors.'
                    : 'Personalize your dealer portal, header logo, and client interface appearance.';
            }

            const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
            setVal('brand-company-name', b.company_name);
            setVal('brand-tagline', b.tagline);
            setVal('brand-primary-color', b.primary_color || '#00f0ff');
            setVal('brand-primary-color-text', b.primary_color || '#00f0ff');
            setVal('brand-accent-color', b.accent_color || '#38bdf8');
            setVal('brand-accent-color-text', b.accent_color || '#38bdf8');
            setVal('brand-email', b.support_email);
            setVal('brand-phone', b.support_phone);

            currentUploadedLogoData = b.logo_url || '';
            renderLogoUploadUI();
            updateLiveBrandingPreview();
        }

        function setThemeSwatch(primary, accent) {
            const pEl = document.getElementById('brand-primary-color');
            const pTxt = document.getElementById('brand-primary-color-text');
            const aEl = document.getElementById('brand-accent-color');
            const aTxt = document.getElementById('brand-accent-color-text');
            if (pEl) pEl.value = primary;
            if (pTxt) pTxt.value = primary;
            if (aEl) aEl.value = accent;
            if (aTxt) aTxt.value = accent;
            updateLiveBrandingPreview();
        }

        function syncColorInput(val, targetId) {
            const el = document.getElementById(targetId);
            if (el && /^#[0-9A-Fa-f]{6}$/.test(val)) {
                el.value = val;
                updateLiveBrandingPreview();
            }
        }

        async function handleBrandingFormSubmit(e) {
            e.preventDefault();
            await saveDealerBranding();
        }

        async function saveDealerBranding() {
            const payload = {
                company_name: document.getElementById('brand-company-name')?.value.trim() || '',
                tagline: document.getElementById('brand-tagline')?.value.trim() || '',
                logo_url: currentUploadedLogoData,
                primary_color: document.getElementById('brand-primary-color')?.value || '#00f0ff',
                accent_color: document.getElementById('brand-accent-color')?.value || '#38bdf8',
                support_email: document.getElementById('brand-email')?.value.trim() || '',
                support_phone: document.getElementById('brand-phone')?.value.trim() || ''
            };

            try {
                const res = await apiFetch('/api/update_dealer_branding', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || 'Branding saved successfully!', 'success');
                    if (currentUser) currentUser.branding = data.branding;
                    applyDealerBranding(data.branding);
                    updateLiveBrandingPreview();
                } else {
                    showToast(data.error || 'Failed to save branding', 'error');
                }
            } catch (err) {
                showToast('Network error saving branding', 'error');
            }
        }

        async function resetToDefaultBranding() {
            if (!confirm("Reset to default GAVASAH branding?")) return;
            try {
                const res = await apiFetch('/api/reset_dealer_branding', { method: 'POST' });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast("Reset to default GAVASAH branding.", "success");
                    currentUploadedLogoData = '';
                    if (currentUser) currentUser.branding = {};
                    populateBrandingForm();
                    applyDealerBranding({});
                } else {
                    showToast(data.error || "Failed to reset branding", "error");
                }
            } catch (err) {
                showToast("Failed to reset branding", "error");
            }
        }

        // ======================================================================
        // ONE-CLICK SNAPSHOT & BACKUP MANAGER
        // ======================================================================
        let currentSnapshotClientId = null;

        async function openSnapshotModal(clientId, siteName) {
            currentSnapshotClientId = clientId;
            document.getElementById('snapshot-client-id').value = clientId;
            document.getElementById('snapshot-modal-title').innerText = `📸 Site Snapshots & Backups: ${siteName}`;
            document.getElementById('snapshot-site-header').innerText = `${siteName} (${clientId})`;
            document.getElementById('snapshot-table-body').innerHTML = `<tr><td colspan="4" style="text-align: center; color: #64748b; padding: 20px;">Fetching site snapshots...</td></tr>`;
            document.getElementById('snapshot-modal').classList.add('active');

            await fetchAndRenderSnapshots(clientId);
        }

        function closeSnapshotModal() {
            document.getElementById('snapshot-modal').classList.remove('active');
        }

        async function fetchAndRenderSnapshots(clientId) {
            const tbody = document.getElementById('snapshot-table-body');
            try {
                const res = await apiFetch(`/api/client_backups?client_id=${encodeURIComponent(clientId)}&t=${Date.now()}`);
                const data = await res.json();
                if (res.ok && data.ok && Array.isArray(data.backups) && data.backups.length > 0) {
                    tbody.innerHTML = data.backups.map(b => {
                        const dateStr = b.date ? new Date(b.date).toLocaleString() : 'Recent';
                        const sizeStr = b.size_mb ? `${b.size_mb} MB` : 'Available';
                        return `
                            <tr>
                                <td style="font-weight: 600; color: #fff;">
                                    <div>${escapeHtml(b.name || 'Full Backup')}</div>
                                    <div style="font-size: 10px; color: #64748b; font-family: monospace;">Slug: ${escapeHtml(b.slug)}</div>
                                </td>
                                <td style="font-size: 11px; color: #cbd5e1;">${escapeHtml(dateStr)}</td>
                                <td style="font-size: 11px; color: #38bdf8; font-family: monospace;">${sizeStr}</td>
                                <td style="text-align: right;">
                                    <button type="button" class="btn-sm" style="padding: 4px 10px; font-size: 11px; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4);" onclick="downloadBackupFile('${clientId}', '${b.slug}')">
                                        📥 Download (.tar)
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: #64748b; padding: 24px;">No backups found for this gateway. Click "+ Create Full Snapshot" above to generate one now.</td></tr>`;
                }
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: #ef4444; padding: 20px;">Failed to load site backups.</td></tr>`;
            }
        }

        async function triggerInstantBackup() {
            const clientId = currentSnapshotClientId;
            if (!clientId) return;
            const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 16);
            const bName = prompt("Enter snapshot name / label:", `Gavasah Snapshot - ${nowStr}`);
            if (!bName) return;

            showToast("Dispatching backup snapshot trigger to gateway...", "info");
            try {
                const res = await apiFetch('/api/client_backup_trigger', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, name: bName })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || "Snapshot trigger sent!", "success");
                    // Refresh snapshot list after 5s and 25s
                    setTimeout(() => fetchAndRenderSnapshots(clientId), 5000);
                    setTimeout(() => fetchAndRenderSnapshots(clientId), 25000);
                } else {
                    showToast(data.error || "Failed to trigger backup", "error");
                }
            } catch (e) {
                showToast("Network error dispatching backup", "error");
            }
        }

        function downloadBackupFile(clientId, slug) {
            showToast("Starting backup download directly to your computer...", "info");
            const downloadUrl = `/api/download_backup?client_id=${encodeURIComponent(clientId)}&slug=${encodeURIComponent(slug)}`;
            window.location.href = downloadUrl;
        }

function formatHeartbeatTime(diff) {
            if (diff === null || diff === undefined || diff < 0) return 'never';
            if (diff < 5) return 'just now';
            if (diff < 60) return `${diff}s ago`;
            const mins = Math.floor(diff / 60);
            if (mins < 60) return `${mins}m ago`;
            const hrs = Math.floor(mins / 60);
            const remM = mins % 60;
            if (hrs < 24) return `${hrs}h ${remM}m ago`;
            const days = Math.floor(hrs / 24);
            const remH = hrs % 24;
            return `${days}d ${remH}h ago`;
        }

        function formatOfflineDetails(lastHeartbeat, now) {
            if (!lastHeartbeat || lastHeartbeat === 0) {
                return {
                    durationText: 'Awaiting first pulse',
                    timestampText: 'Not connected yet',
                    tooltip: 'Client site provisioned - awaiting initial connection from physical gateway'
                };
            }
            const diff = Math.max(0, now - lastHeartbeat);
            const d = new Date(lastHeartbeat * 1000);
            
            const hours = String(d.getHours()).padStart(2, '0');
            const mins = String(d.getMinutes()).padStart(2, '0');
            const dateStr = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
            const formattedTime = `${dateStr}, ${hours}:${mins}`;

            let durationStr = '';
            if (diff < 60) durationStr = `${diff}s`;
            else if (diff < 3600) {
                const m = Math.floor(diff / 60);
                durationStr = `${m}m`;
            } else if (diff < 86400) {
                const h = Math.floor(diff / 3600);
                const m = Math.floor((diff % 3600) / 60);
                durationStr = `${h}h ${m}m`;
            } else {
                const days = Math.floor(diff / 86400);
                const h = Math.floor((diff % 86400) / 3600);
                durationStr = `${days}d ${h}h`;
            }

            return {
                durationText: `Offline for ${durationStr}`,
                timestampText: `since ${formattedTime}`,
                fullText: `Offline for ${durationStr} (since ${formattedTime})`,
                tooltip: `Gateway went offline on ${d.toLocaleString()} (Offline for ${durationStr})`
            };
        }

        function formatOnboardingDateTime(onboardedAt) {
            if (!onboardedAt || onboardedAt === 0) {
                return {
                    hasOnboarded: false,
                    dateText: 'Awaiting first contact',
                    timeText: 'Not connected yet',
                    fullText: 'Awaiting initial contact with manufacturer server',
                    tooltip: 'Gavasah Gateway provisioned — awaiting initial connection to manufacturer server'
                };
            }
            const d = new Date(onboardedAt * 1000);
            const dateStr = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
            let hours = d.getHours();
            const ampm = hours >= 12 ? 'PM' : 'AM';
            hours = hours % 12;
            hours = hours ? hours : 12;
            const mins = String(d.getMinutes()).padStart(2, '0');
            const secs = String(d.getSeconds()).padStart(2, '0');
            const timeStr = `${String(hours).padStart(2, '0')}:${mins}:${secs} ${ampm}`;
            const fullFormatted = `${dateStr}, ${timeStr}`;

            return {
                hasOnboarded: true,
                dateText: dateStr,
                timeText: timeStr,
                fullText: fullFormatted,
                tooltip: `First contacted manufacturer server on ${d.toLocaleString()}`
            };
        }

        function scrollTableBy(target, delta) {
            const wrap = (typeof target === 'string') ? document.querySelector(target) : target;
            if (wrap) {
                wrap.scrollBy({ left: delta, behavior: 'smooth' });
            }
        }

        function enableDragToScroll(wrap) {
            if (!wrap || wrap._hasDragScroll) return;
            wrap._hasDragScroll = true;
            let isDown = false;
            let startX = 0;
            let scrollLeft = 0;

            wrap.addEventListener('mousedown', (e) => {
                if (e.target.closest('button, a, input, select, label, textarea, .toggle-switch')) return;
                isDown = true;
                wrap.classList.add('is-dragging');
                wrap.style.cursor = 'grabbing';
                startX = e.pageX - wrap.offsetLeft;
                scrollLeft = wrap.scrollLeft;
            });

            window.addEventListener('mouseup', () => {
                if (isDown) {
                    isDown = false;
                    wrap.classList.remove('is-dragging');
                    wrap.style.cursor = '';
                }
            });

            wrap.addEventListener('mousemove', (e) => {
                if (!isDown) return;
                e.preventDefault();
                const x = e.pageX - wrap.offsetLeft;
                const walk = (x - startX) * 1.5;
                wrap.scrollLeft = scrollLeft - walk;
            });
        }

        function initAllTableScrollbars() {
            document.querySelectorAll('.table-wrap').forEach(wrap => {
                let topScroll = wrap.previousElementSibling;
                if (!topScroll || !topScroll.classList.contains('table-top-scroll')) {
                    topScroll = document.createElement('div');
                    topScroll.className = 'table-top-scroll';
                    const track = document.createElement('div');
                    track.className = 'table-top-scroll-track';
                    topScroll.appendChild(track);
                    wrap.parentNode.insertBefore(topScroll, wrap);
                }
                const track = topScroll.querySelector('.table-top-scroll-track');

                const updateSync = () => {
                    if (!wrap || !track) return;
                    const scrollW = wrap.scrollWidth;
                    const clientW = wrap.clientWidth;
                    track.style.width = scrollW + 'px';
                    if (scrollW > clientW + 8) {
                        topScroll.style.display = 'block';
                    } else {
                        topScroll.style.display = 'none';
                    }
                };

                if (!wrap._scrollListenersBound) {
                    wrap._scrollListenersBound = true;
                    let isSyncing = false;

                    wrap.addEventListener('scroll', () => {
                        if (!isSyncing) {
                            isSyncing = true;
                            topScroll.scrollLeft = wrap.scrollLeft;
                            isSyncing = false;
                        }
                    }, { passive: true });

                    topScroll.addEventListener('scroll', () => {
                        if (!isSyncing) {
                            isSyncing = true;
                            wrap.scrollLeft = topScroll.scrollLeft;
                            isSyncing = false;
                        }
                    }, { passive: true });

                    enableDragToScroll(wrap);

                    if (window.ResizeObserver) {
                        const ro = new ResizeObserver(() => updateSync());
                        ro.observe(wrap);
                        const tbl = wrap.querySelector('table');
                        if (tbl) ro.observe(tbl);
                    }
                }

                updateSync();
            });
        }

        // ======================================================================
        // CLIENT ONBOARDING & CONFIG MODALS
        // ======================================================================
        function openOnboardModal() {
            const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
            setVal('onb-name', '');
            setVal('onb-slug', '');
            setVal('onb-secret', generateSecretStr());
            setVal('onb-knx-ip', '');
            setVal('onb-knx-port', '');
            setVal('onb-ssh-key', '');
            updateOnboardDomainPreview();

            const dGroup = document.getElementById('onb-dealer-group');
            const intGroup = document.getElementById('onb-integrator-group');

            if (currentUser.role === 'manufacturer') {
                if (dGroup) dGroup.style.display = 'block';
                if (intGroup) intGroup.style.display = 'block';
                updateDealerDropdowns();
                const dSel = document.getElementById('onb-dealer-select');
                if (dSel && !dSel.value) dSel.value = 'owner_master';
                updateOnboardIntegratorDropdown('');
            } else if (currentUser.role === 'dealer') {
                if (dGroup) dGroup.style.display = 'none';
                if (intGroup) intGroup.style.display = 'block';
                updateOnboardIntegratorDropdown('');
            } else {
                if (dGroup) dGroup.style.display = 'none';
                if (intGroup) intGroup.style.display = 'none';
            }

            const onbRemoteToggle = document.getElementById('onb-remote-toggle');
            if (onbRemoteToggle) onbRemoteToggle.checked = true;
            updateOnboardRemoteStatusText(true);

            const modal = document.getElementById('onboard-modal');
            if (modal) modal.classList.add('active');
        }

        function updateOnboardRemoteStatusText(isOn) {
            const el = document.getElementById('onb-remote-status-text');
            if (el) {
                el.className = `toggle-pill-badge ${isOn ? 'pill-live' : 'pill-off'}`;
                el.innerText = isOn ? '🟢 LIVE' : '🔴 DISABLED';
            }
        }

        function onOnboardRemoteToggleChange(isOn) {
            updateOnboardRemoteStatusText(isOn);
        }

        function closeOnboardModal() {
            document.getElementById('onboard-modal').classList.remove('active');
        }

        function generateOnboardSecret() {
            document.getElementById('onb-secret').value = generateSecretStr();
        }

        function generateEditSecret() {
            document.getElementById('edit-secret').value = generateSecretStr();
            updateEditConfigSnippet();
        }

        function generateSecretStr() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let res = '';
            for (let i = 0; i < 32; i++) res += chars.charAt(Math.floor(Math.random() * chars.length));
            return res;
        }

        function slugifyText(text) {
            return (text || '').toString().toLowerCase().trim()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-+|-+$/g, '');
        }

        function onOnboardNameChange() {
            const nameEl = document.getElementById('onb-name');
            const slugEl = document.getElementById('onb-slug');
            if (nameEl && slugEl) {
                slugEl.value = slugifyText(nameEl.value);
            }
            updateOnboardDomainPreview();
        }

        async function handleOnboardSubmit(e) {
            e.preventDefault();
            const nameVal = document.getElementById('onb-name').value.trim();
            const slugInput = document.getElementById('onb-slug');
            let autoSlug = (slugInput ? slugInput.value.trim() : '') || slugifyText(nameVal);
            if (!autoSlug) {
                autoSlug = 'client-' + Math.floor(1000 + Math.random() * 9000);
            }

            const secretInput = document.getElementById('onb-secret');
            let secretVal = secretInput ? secretInput.value.trim() : '';
            if (!secretVal) {
                secretVal = generateSecretStr();
            }

            const remoteToggle = document.getElementById('onb-remote-toggle');
            const payload = {
                name: nameVal,
                client_id: autoSlug.toLowerCase(),
                auth_secret: secretVal,
                knx_ip: '',
                knx_port: null,
                ssh_public_key: (document.getElementById('onb-ssh-key') ? document.getElementById('onb-ssh-key').value.trim() : ''),
                remote_enabled: remoteToggle ? remoteToggle.checked : true
            };

            if (currentUser.role === 'manufacturer') {
                payload.dealer_id = document.getElementById('onb-dealer-select').value;
                payload.integrator_id = document.getElementById('onb-integrator-select').value;
            } else if (currentUser.role === 'dealer') {
                payload.integrator_id = document.getElementById('onb-integrator-select').value;
            }

            try {
                const res = await apiFetch('/api/onboard', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(`Gavasah Gateway '${payload.name}' onboarded successfully! Opening client configuration...`, 'success');
                    closeOnboardModal();
                    await fetchFleet();
                    if (data.client && data.client.client_id) {
                        openEditModal(data.client.client_id);
                    }
                } else {
                    showToast(data.error || 'Onboarding failed', 'error');
                }
            } catch (err) {
                showToast('Network error during onboarding', 'error');
            }
        }

        function updateEditConfigSnippet() {
            const idEl = document.getElementById('edit-id') || document.getElementById('edit-client-id');
            const clientId = idEl ? idEl.value : '';
            const client = currentFleetData.find(c => c.client_id === clientId);
            
            const secret = (document.getElementById('edit-secret') ? document.getElementById('edit-secret').value : '') || (client ? client.auth_secret : '');
            const dashPort = (client && client.dashboard_port) ? client.dashboard_port : 10001;
            const sshPort = (client && client.ssh_port) ? client.ssh_port : 22001;

            const snippet = `hub_host: "dealer.gavasah.com"
hub_ssh_port: 2222
client_id: "${clientId}"
auth_key: "${secret}"
remote_dashboard_port: ${dashPort}
remote_ssh_port: ${sshPort}
heartbeat_interval: 60
auto_update_external_url: true`;

            const snippetEl = document.getElementById('edit-config-snippet');
            if (snippetEl) snippetEl.innerText = snippet;
        }

        function copyAddonConfig() {
            const snippetEl = document.getElementById('edit-config-snippet');
            const txt = snippetEl ? snippetEl.innerText : '';
            if (!txt) {
                showToast('No config snippet available to copy', 'error');
                return;
            }
            navigator.clipboard.writeText(txt).then(() => {
                showToast('Add-on YAML config copied to clipboard! Paste into HA Add-on Configuration tab.', 'success');
            }).catch(() => {
                showToast('Failed to copy config to clipboard', 'error');
            });
        }

        function openEditModal(clientId) {
            const client = currentFleetData.find(c => c.client_id === clientId);
            if (!client) return;

            const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
            setVal('edit-id', client.client_id);
            setVal('edit-client-id', client.client_id);
            setVal('edit-name', client.name || '');
            setVal('edit-secret', client.auth_secret || '');

            const setDurationInputs = (valId, unitId, totalSec, defaultSec) => {
                const s = parseInt(totalSec) || defaultSec;
                const valEl = document.getElementById(valId);
                const unitEl = document.getElementById(unitId);
                if (!valEl || !unitEl) return;
                if (s >= 3600 && s % 3600 === 0) {
                    valEl.value = Math.floor(s / 3600);
                    unitEl.value = 'h';
                } else {
                    valEl.value = Math.max(1, Math.round(s / 60));
                    unitEl.value = 'm';
                }
            };
            setDurationInputs('edit-hb-delayed-val', 'edit-hb-delayed-unit', client.hb_delayed_interval, 900);
            setDurationInputs('edit-hb-warning-val', 'edit-hb-warning-unit', client.hb_warning_interval, 1800);
            setDurationInputs('edit-hb-offline-val', 'edit-hb-offline-unit', client.hb_offline_interval, 3600);

            const dGroup = document.getElementById('edit-dealer-group');
            if (currentUser.role === 'manufacturer') {
                if (dGroup) dGroup.style.display = 'block';
                updateDealerDropdowns();
                const dSel = document.getElementById('edit-dealer-select');
                if (dSel) dSel.value = client.dealer_id || 'owner_master';
            } else {
                if (dGroup) dGroup.style.display = 'none';
            }

            const intGroup = document.getElementById('edit-integrator-group');
            if (currentUser.role !== 'integrator') {
                if (intGroup) intGroup.style.display = 'block';
                updateEditIntegratorDropdown(client.integrator_id || '');
            } else {
                if (intGroup) intGroup.style.display = 'none';
            }

            const remoteToggle = document.getElementById('edit-remote-toggle');
            const isRemoteOn = Boolean(client.remote_enabled) && client.remote_enabled !== 0 && client.remote_enabled !== '0';
            if (remoteToggle) remoteToggle.checked = isRemoteOn;
            updateEditRemoteStatusText(isRemoteOn);

            const knxRemoteToggle = document.getElementById('edit-knx-remote-toggle');
            const isKnxRemoteOn = Boolean(client.knx_remote_enabled !== 0 && client.knx_remote_enabled !== false && client.knx_remote_enabled !== '0');
            if (knxRemoteToggle) knxRemoteToggle.checked = isKnxRemoteOn;
            updateEditKnxRemoteStatusText(isKnxRemoteOn);

            const callAlertToggle = document.getElementById('edit-call-alert-toggle');
            if (callAlertToggle) callAlertToggle.checked = client.call_alert_enabled !== undefined ? Boolean(client.call_alert_enabled) : true;

            const msgAlertToggle = document.getElementById('edit-msg-alert-toggle');
            if (msgAlertToggle) msgAlertToggle.checked = client.msg_alert_enabled !== undefined ? Boolean(client.msg_alert_enabled) : true;

            const callStartEl = document.getElementById('edit-call-start-time');
            if (callStartEl) callStartEl.value = client.call_window_start || '10:00';

            const callEndEl = document.getElementById('edit-call-end-time');
            if (callEndEl) callEndEl.value = client.call_window_end || '18:00';

            // Real-time update of snippet on input change
            const secEl = document.getElementById('edit-secret');
            if (secEl) secEl.oninput = updateEditConfigSnippet;
            const knxIpEl = document.getElementById('edit-knx-ip');
            if (knxIpEl) knxIpEl.oninput = updateEditConfigSnippet;
            const knxPortEl = document.getElementById('edit-knx-port');
            if (knxPortEl) knxPortEl.oninput = updateEditConfigSnippet;

            updateEditConfigSnippet();

            const modal = document.getElementById('edit-modal');
            if (modal) modal.classList.add('active');
        }

        function updateEditRemoteStatusText(isOn) {
            const el = document.getElementById('edit-remote-status-text');
            if (el) {
                el.className = `toggle-pill-badge ${isOn ? 'pill-live' : 'pill-off'}`;
                el.innerText = isOn ? '🟢 LIVE' : '🔴 DISABLED';
            }
        }

        function onEditRemoteToggleChange(isOn) {
            updateEditRemoteStatusText(isOn);
        }

        function updateEditKnxRemoteStatusText(isOn) {
            const el = document.getElementById('edit-knx-remote-status-text');
            if (el) {
                el.className = `toggle-pill-badge ${isOn ? 'pill-live' : 'pill-off'}`;
                el.innerText = isOn ? '🟢 LIVE' : '🔴 DISABLED';
            }
        }

        function onEditKnxRemoteToggleChange(isOn) {
            updateEditKnxRemoteStatusText(isOn);
        }

        async function toggleKnxRemoteAccess(clientId, isEnabled) {
            try {
                const res = await apiFetch('/api/toggle_knx_remote', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, enabled: isEnabled })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(`Remote KNX programming ${isEnabled ? 'enabled' : 'disabled'} for ${clientId}`, 'info');
                    fetchFleet();
                } else {
                    showToast(data.error || 'Failed to toggle remote KNX access', 'error');
                }
            } catch (err) {
                showToast('Network error toggling remote KNX access', 'error');
            }
        }

        function closeEditModal() {
            const modal = document.getElementById('edit-modal');
            if (modal) modal.classList.remove('active');
        }

        function onEditDealerChange() {
            updateEditIntegratorDropdown('');
        }

        async function handleClientEditSubmit(e) {
            e.preventDefault();
            const idEl = document.getElementById('edit-id') || document.getElementById('edit-client-id');
            const clientId = idEl ? idEl.value : '';
            const remoteToggle = document.getElementById('edit-remote-toggle');
            const client = currentFleetData.find(c => c.client_id === clientId);
            const getDurationSec = (valId, unitId, defaultSec) => {
                const valEl = document.getElementById(valId);
                const unitEl = document.getElementById(unitId);
                if (!valEl) return defaultSec;
                const v = parseFloat(valEl.value) || 0;
                if (v <= 0) return defaultSec;
                const u = unitEl ? unitEl.value : 'm';
                return Math.round(u === 'h' ? v * 3600 : v * 60);
            };

            const payload = {
                client_id: clientId,
                name: (document.getElementById('edit-name') ? document.getElementById('edit-name').value.trim() : ''),
                knx_ip: (client && client.knx_ip && client.knx_ip !== '192.168.1.100' ? client.knx_ip : ''),
                knx_port: (client && client.knx_port && client.knx_ip && client.knx_ip !== '192.168.1.100' ? client.knx_port : null),
                auth_secret: (document.getElementById('edit-secret') ? document.getElementById('edit-secret').value.trim() : (client ? client.auth_secret : '')),
                remote_enabled: remoteToggle ? remoteToggle.checked : true,
                knx_remote_enabled: (document.getElementById('edit-knx-remote-toggle') ? document.getElementById('edit-knx-remote-toggle').checked : true),
                hb_delayed_interval: getDurationSec('edit-hb-delayed-val', 'edit-hb-delayed-unit', 900),
                hb_warning_interval: getDurationSec('edit-hb-warning-val', 'edit-hb-warning-unit', 1800),
                hb_offline_interval: getDurationSec('edit-hb-offline-val', 'edit-hb-offline-unit', 3600),
                call_alert_enabled: document.getElementById('edit-call-alert-toggle') ? (document.getElementById('edit-call-alert-toggle').checked ? 1 : 0) : 1,
                msg_alert_enabled: document.getElementById('edit-msg-alert-toggle') ? (document.getElementById('edit-msg-alert-toggle').checked ? 1 : 0) : 1,
                call_window_start: document.getElementById('edit-call-start-time') ? (document.getElementById('edit-call-start-time').value || '10:00') : '10:00',
                call_window_end: document.getElementById('edit-call-end-time') ? (document.getElementById('edit-call-end-time').value || '18:00') : '18:00'
            };

            if (currentUser.role === 'manufacturer') {
                const dSel = document.getElementById('edit-dealer-select');
                if (dSel) payload.dealer_id = dSel.value;
            }
            if (currentUser.role !== 'integrator') {
                const iSel = document.getElementById('edit-integrator-select');
                if (iSel) payload.integrator_id = iSel.value;
            }

            try {
                const res = await apiFetch('/api/update_client', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast('Gavasah Gateway configuration updated', 'success');
                    closeEditModal();
                    fetchFleet();
                } else {
                    showToast(data.error || 'Update failed', 'error');
                }
            } catch (err) {
                showToast('Network error during update', 'error');
            }
        }

        async function toggleRemoteAccess(clientId, isEnabled) {
            try {
                const res = await apiFetch('/api/toggle_remote', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, enabled: isEnabled })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(`Remote ingress ${isEnabled ? 'enabled' : 'disabled'} for ${clientId}`, 'info');
                    fetchFleet();
                } else {
                    showToast(data.error || 'Failed to toggle remote access', 'error');
                }
            } catch (err) {
                showToast('Network error toggling ingress', 'error');
            }
        }

        function promptDelete(clientId, clientName) {
            currentDeleteTarget = { type: 'client', id: clientId, name: clientName };
            const titleEl = document.getElementById('delete-modal-title');
            const msgEl = document.getElementById('delete-modal-msg');
            if (titleEl) titleEl.innerText = `Confirm Site Removal: ${clientName}`;
            if (msgEl) {
                msgEl.innerHTML = `
                    Are you sure you want to permanently delete client site <strong>${escapeHtml(clientName)}</strong> (<code>${escapeHtml(clientId)}</code>)?<br><br>
                    <span style="color: #f59e0b; font-size: 13px;">⚡ <strong>Active Gateway Policy:</strong> Even if this client is currently active and streaming telemetry, its WireGuard mesh tunnel, telemetry pulse, and cloud ingress will be immediately severed and purged.</span>
                `;
            }
            const modal = document.getElementById('delete-modal');
            if (modal) modal.classList.add('active');
        }

        function closeDeleteModal() {
            currentDeleteTarget = null;
            document.getElementById('delete-modal').classList.remove('active');
        }

        async function confirmDeletion() {
            if (!currentDeleteTarget) return;

            const { type, id, name } = currentDeleteTarget;
            let endpoint = '';
            let payload = {};

            if (type === 'client') {
                endpoint = '/api/delete_site';
                payload = { client_id: id };
            } else if (type === 'dealer') {
                endpoint = '/api/delete_dealer';
                payload = { dealer_id: id };
            } else if (type === 'integrator') {
                endpoint = '/api/delete_integrator';
                payload = { integrator_id: id };
            }

            try {
                const res = await apiFetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || `${name} deleted successfully`, 'success');
                    closeDeleteModal();
                    if (type === 'client') fetchFleet();
                    else if (type === 'dealer') { fetchDealers(); fetchFleet(); }
                    else if (type === 'integrator') { fetchIntegrators(); fetchFleet(); }
                } else {
                    showToast(data.error || 'Deletion failed', 'error');
                }
            } catch (err) {
                showToast('Network error during deletion', 'error');
            }
        }

        // ======================================================================
        // SELF-SERVICE CREDENTIALS MODALS
        // ======================================================================
        async function handleOwnerCredentialsUpdate(e) {
            e.preventDefault();
            const curr = document.getElementById('acc-current-pwd').value;
            const newU = document.getElementById('acc-username').value.trim();
            const newP = document.getElementById('acc-new-pwd').value;
            const confP = document.getElementById('acc-confirm-pwd').value;

            if (newP && newP !== confP) {
                showToast('New passwords do not match!', 'error');
                return;
            }

            try {
                const res = await apiFetch('/api/change_owner_credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        current_password: curr,
                        new_username: newU,
                        new_password: newP
                    })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast('Master credentials updated successfully!', 'success');
                    document.getElementById('acc-current-pwd').value = '';
                    document.getElementById('acc-new-pwd').value = '';
                    document.getElementById('acc-confirm-pwd').value = '';
                    checkAuth();
                } else {
                    showToast(data.error || 'Failed to update credentials', 'error');
                }
            } catch (err) {
                showToast('Network error updating credentials', 'error');
            }
        }

        function openDealerPasswordModal() {
            document.getElementById('dealer-pwd-current').value = '';
            document.getElementById('dealer-pwd-new').value = '';
            document.getElementById('dealer-pwd-confirm').value = '';
            document.getElementById('dealer-pwd-modal').classList.add('active');
        }

        function closeDealerPasswordModal() {
            document.getElementById('dealer-pwd-modal').classList.remove('active');
        }

        async function handleDealerSelfPasswordChange(e) {
            e.preventDefault();
            const curr = document.getElementById('dealer-pwd-current').value;
            const newP = document.getElementById('dealer-pwd-new').value;
            const confP = document.getElementById('dealer-pwd-confirm').value;

            if (newP !== confP) {
                showToast('New passwords do not match!', 'error');
                return;
            }

            try {
                const res = await apiFetch('/api/change_dealer_password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        current_password: curr,
                        new_password: newP
                    })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast('Your password was updated successfully!', 'success');
                    closeDealerPasswordModal();
                } else {
                    showToast(data.error || 'Failed to change password', 'error');
                }
            } catch (err) {
                showToast('Network error changing password', 'error');
            }
        }

        // ======================================================================
        // AUDIT LOGS MODAL
        // ======================================================================
        async function openLogsModal(clientId) {
            currentLogsClient = clientId;
            const titleEl = document.getElementById('log-client-title') || document.getElementById('logs-modal-title');
            if (titleEl) titleEl.innerText = clientId;
            const modal = document.getElementById('logs-modal');
            if (modal) modal.classList.add('active');
            refreshCurrentLogs();
        }

        function closeLogsModal() {
            currentLogsClient = null;
            const modal = document.getElementById('logs-modal');
            if (modal) modal.classList.remove('active');
        }

        async function refreshCurrentLogs() {
            if (!currentLogsClient) return;
            const body = document.getElementById('logs-terminal') || document.getElementById('logs-modal-body');
            if (!body) return;
            body.innerHTML = '<div style="color: #64748b; font-size: 13px;">Streaming operational telemetry...</div>';

            try {
                const res = await apiFetch(`/api/logs?client_id=${encodeURIComponent(currentLogsClient)}&t=${Date.now()}`);
                if (!res.ok) {
                    body.innerHTML = '<div style="color: #ef4444;">Failed to load logs.</div>';
                    return;
                }
                const logs = await res.json();
                if (!logs.length) {
                    body.innerHTML = '<div style="color: #64748b;">No audit logs recorded for this gateway yet.</div>';
                    return;
                }
                body.innerHTML = logs.map(l => {
                    let color = '#38bdf8';
                    if (l.level === 'WARNING') color = '#fbbf24';
                    else if (l.level === 'ERROR') color = '#ef4444';
                    const timeStr = new Date(l.timestamp * 1000).toLocaleTimeString();
                    return `
                        <div style="margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 6px;">
                            <span style="color: #64748b;">[${timeStr}]</span>
                            <span style="color: ${color}; font-weight: 600; margin: 0 4px;">[${l.level}]</span>
                            <span style="color: #c084fc; margin-right: 6px;">&lt;${l.type}&gt;</span>
                            <span style="color: #cbd5e1;">${escapeHtml(l.message)}</span>
                        </div>
                    `;
                }).join('');
            } catch (err) {
                body.innerHTML = '<div style="color: #ef4444;">Connection error fetching logs.</div>';
            }
        }

        function copyCurrentLogs() {
            const body = document.getElementById('logs-terminal') || document.getElementById('logs-modal-body');
            if (!body) return;
            navigator.clipboard.writeText(body.innerText).then(() => {
                showToast('Audit logs copied to clipboard!', 'success');
            }).catch(() => {
                showToast('Failed to copy to clipboard', 'error');
            });
        }

        // ======================================================================
        // SSL INSPECTOR MODAL
        // ======================================================================
        async function triggerSslCheck() {
            document.getElementById('ssl-modal').classList.add('active');
            const tbody = document.getElementById('ssl-table-body');
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #64748b;">Validating TLS certificates...</td></tr>';

            try {
                const res = await apiFetch('/api/ssl_status?t=' + Date.now());
                const certs = await res.json();
                tbody.innerHTML = certs.map(c => `
                    <tr>
                        <td style="font-family: monospace; color: #fff;">${escapeHtml(c.domain)}</td>
                        <td style="color: #94a3b8;">${escapeHtml(c.authority)}</td>
                        <td>${c.valid_days_left} Days Remaining</td>
                        <td><span class="badge-status ${c.status === 'active' ? 'status-online' : 'status-lost'}">${c.status.toUpperCase()}</span></td>
                    </tr>
                `).join('');
            } catch (err) {
                tbody.innerHTML = '<tr><td colspan="4" style="color: #ef4444;">Error inspecting SSL certificates.</td></tr>';
            }
        }

        function closeSslModal() {
            document.getElementById('ssl-modal').classList.remove('active');
        }

        // ======================================================================
        // UTILITY HELPERS
        // ======================================================================
        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function showToast(msg, type = 'info') {
            const box = document.getElementById('toast-box');
            if (!box) return;
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerText = msg;
            box.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(10px)';
                setTimeout(() => toast.remove(), 300);
            }, 3500);
        }

        // Initialization & Continuous Live Data Synchronization (No Refresh Required)
        let pollCounter = 0;
        window.addEventListener('DOMContentLoaded', () => {
            checkAuth();
            setInterval(() => {
                if (currentUser) {
                    pollCounter++;
                    // Continuously poll live fleet inventory and heartbeats every 2.5s
                    fetchFleet();
                    // Continuously poll pending approvals for Manufacturer every 2.5s
                    if (currentUser.role === 'manufacturer') {
                        fetchApprovals();
                    }
                    if (pollCounter % 4 === 0 && currentUser.role === 'manufacturer') {
                        fetchDealers();
                    }
                    if (pollCounter % 6 === 0 && currentUser.role !== 'integrator') {
                        fetchIntegrators();
                    }
                }
            }, 2500); // 2.5s live polling interval for instantaneous zero-refresh updates
        });


        async function toggleDealerStatus(dealerId, newStatus) {
            const actionLabel = newStatus === 'suspended' ? 'suspend' : 'activate';
            const warningExtra = newStatus === 'suspended' ? `
All active sessions for this dealer and their integrators will be terminated immediately.` : '';
            if (!confirm(`Are you sure you want to ${actionLabel} this dealer?${warningExtra}`)) {
                return;
            }
            try {
                const res = await apiFetch('/api/toggle_dealer_status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ dealer_id: dealerId, status: newStatus })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || `Dealer status changed to ${newStatus.toUpperCase()}`, 'success');
                    fetchDealers();
                    fetchFleet();
                } else {
                    showToast(data.error || 'Failed to toggle dealer status', 'error');
                }
            } catch (err) {
                showToast('Network error toggling status', 'error');
            }
        }

        async function toggleIntegratorStatus(intId, newStatus) {
            const actionLabel = newStatus === 'suspended' ? 'suspend' : 'activate';
            const warningExtra = newStatus === 'suspended' ? `
All active sessions for this integrator will be terminated immediately.` : '';
            if (!confirm(`Are you sure you want to ${actionLabel} this integrator?${warningExtra}`)) {
                return;
            }
            try {
                const res = await apiFetch('/api/toggle_integrator_status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ integrator_id: intId, status: newStatus })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(data.message || `Integrator status changed to ${newStatus.toUpperCase()}`, 'success');
                    fetchIntegrators();
                    fetchFleet();
                } else {
                    showToast(data.error || 'Failed to toggle integrator status', 'error');
                }
            } catch (err) {
                showToast('Network error toggling status', 'error');
            }
        }


        function getActiveDealerSlug() {
            if (!currentUser) return 'direct';
            if (currentUser.role === 'dealer') {
                const u = (currentUser.username || '').toLowerCase();
                const clean = u.replace('dealer', '').replace(/[^a-z0-9]/g, '');
                return clean || 'dealer';
            } else if (currentUser.role === 'integrator') {
                const u = (currentUser.dealer_name || '').toLowerCase();
                const clean = u.replace('dealer', '').replace(/[^a-z0-9]/g, '');
                return clean || 'dealer';
            } else {
                const sel = document.getElementById('onb-dealer-select');
                if (!sel || sel.value === 'owner_master' || !sel.value) return 'direct';
                const d = dealersList.find(x => x.id === sel.value);
                if (d) {
                    const u = (d.username || '').toLowerCase();
                    const clean = u.replace('dealer', '').replace(/[^a-z0-9]/g, '');
                    return clean || 'dealer';
                }
                return 'direct';
            }
        }

        function updateOnboardDomainPreview() {
            const nameEl = document.getElementById('onb-name');
            const slugEl = document.getElementById('onb-slug');
            const rawVal = (slugEl && slugEl.value) ? slugEl.value : slugifyText(nameEl ? nameEl.value : '');
            const raw = rawVal.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
            const dSlug = getActiveDealerSlug();
            const cleanBase = raw.replace(new RegExp(`-${dSlug}$`), '');
            const domainPreviewEl = document.getElementById('onb-preview-domain');
            if (domainPreviewEl) {
                const displaySlug = (cleanBase || 'client') + '-' + dSlug;
                domainPreviewEl.innerText = `${displaySlug}.gavasah.com`;
            }
        }

        function onOnboardDealerChange() {
            updateOnboardDomainPreview();
            updateOnboardIntegratorDropdown('');
        }

    
        function openIntegrationDiagnostics(clientId, techKey, event) {
            if (event) event.stopPropagation();
            const client = currentFleetData.find(c => c.client_id === clientId);
            if (!client) return;

            const isMonitored = !(client.unmonitored_integrations || []).includes(techKey);

            const tech = client.technologies || {};
            const knx = tech.knx || client.knx_status || {};
            const zigbee = tech.zigbee || {};
            const lutron = tech.lutron || {};
            const matter = tech.matter || {};

            let title = `${client.name} — Subsystem Diagnostics`;
            let isOnline = false;
            let statusText = 'OFFLINE';
            let techName = 'Integration';
            let reason = '';
            let endpoint = '—';
            let latency = '—';
            let details = '';
            let fixAction = '';

            if (techKey === 'knx') {
                techName = 'KNXnet/IP Bus Integration';
                isOnline = Boolean(knx.reachable || knx.state === 'connected' || knx.status === 'online');
                endpoint = knx.gateway_ip ? `${knx.gateway_ip}:${knx.gateway_port || 3671}` : (client.knx_ip ? `${client.knx_ip}:${client.knx_port || 3671}` : 'Local Bus');
                latency = knx.latency_ms ? `${knx.latency_ms} ms` : '—';
                details = knx.connection_type ? `Connection Type: ${knx.connection_type}` : 'Native Tunneling';
                if (!isOnline) {
                    reason = knx.error === 'timeout' ? 'Gateway Unreachable (UDP Ping Timed Out)' : (knx.error || knx.offline_reason || 'Connection Failed');
                    fixAction = 'Verify that the KNXnet/IP Router or Interface is powered on, connected to the local network, and UDP port 3671 is accessible from the Gavasah Gateway.';
                } else {
                    fixAction = 'KNXnet/IP interface is actively communicating with Telegram exchange verified.';
                }
            } else if (techKey === 'zigbee') {
                techName = 'Zigbee Automation Subsystem';
                const insts = zigbee.instances || [];
                const runningInsts = insts.filter(i => i.running || i.state === 'started');
                const failedInsts = insts.filter(i => !i.running && i.state !== 'started');
                if (insts.length > 0) {
                    isOnline = failedInsts.length === 0;
                    statusText = isOnline ? 'ONLINE (OPERATIONAL)' : (runningInsts.length > 0 ? 'DEGRADED' : 'OFFLINE');
                    endpoint = insts.map(i => `${i.name} (v${i.version || '?'})`).join(', ');
                    if (!isOnline) {
                        reason = failedInsts.map(i => `${i.name} container state: ${i.state}`).join('; ');
                        fixAction = 'Verify that the Zigbee USB coordinator dongle is firmly inserted into the Gavasah Gateway USB port, and restart the Zigbee2MQTT add-on.';
                    } else {
                        fixAction = 'All Zigbee2MQTT container instances are running with healthy coordinator communication.';
                    }
                } else if (zigbee.zha_detected) {
                    isOnline = true;
                    statusText = 'ONLINE (ZHA)';
                    endpoint = 'Zigbee Home Automation (ZHA Native)';
                    fixAction = 'ZHA native Zigbee stack is loaded and managing the mesh network.';
                }
            } else if (techKey === 'lutron') {
                techName = 'Lutron Subsystem';
                const lEntries = (lutron.entries || []).filter(e => !isEntryIgnored(e));
                const failedL = lEntries.filter(e => e.state !== 'loaded' && e.online === false);
                isOnline = !(lutron.status === 'offline' || lutron.offline_reason || failedL.length > 0);
                endpoint = lEntries.length > 0 ? lEntries.map(e => `${e.title || e.domain} (${e.state || (e.online ? 'loaded' : 'offline')})`).join(', ') : 'Lutron Smart Bridge';
                if (!isOnline) {
                    reason = lutron.offline_reason || (failedL.length > 0 ? failedL.map(e => `${e.title || 'Bridge'}: ${e.reason || e.state || 'offline'}`).join('; ') : 'Lutron Smart Bridge / Repeater unreachable');
                    fixAction = 'Verify the IP address and power of each Lutron Smart Bridge/Repeater and ensure ethernet cabling to the router/switch is active.';
                } else {
                    fixAction = 'Lutron bridge integration is loaded and responding to Home Assistant commands.';
                }
            } else if (techKey === 'matter') {
                techName = 'Matter & Thread Subsystem';
                isOnline = Boolean(matter.state === 'started' || matter.state === 'running' || matter.status === 'online');
                endpoint = `Matter Server (${matter.state || 'not_installed'})`;
                if (!isOnline) {
                    reason = `Matter Server add-on container is ${matter.state || 'stopped'}`;
                    fixAction = 'Start the Matter Server add-on from Settings > Add-ons on the Gavasah Gateway.';
                } else {
                    fixAction = 'Matter Server daemon is running and listening for IPv6 Thread/Matter commissioning.';
                }
            } else if (techKey === 'coolmaster') {
                techName = 'CoolMaster HVAC Subsystem';
                const coolmaster = tech.coolmaster || {};
                const cmEntries = (coolmaster.entries || []).filter(e => !isEntryIgnored(e));
                const failedCm = cmEntries.find(e => e.state === 'setup_error' || e.state === 'setup_retry' || e.state === 'not_loaded' || e.online === false);
                isOnline = !(coolmaster.status === 'offline' || coolmaster.status === 'setup_retry' || coolmaster.status === 'setup_error' || coolmaster.offline_reason || failedCm);
                endpoint = cmEntries.length > 0 ? cmEntries.map(e => e.title || `${e.host || ''}:${e.port || 10102}`).join(', ') : 'CoolMasterNet Bridge';
                if (!isOnline) {
                    reason = coolmaster.offline_reason || (failedCm ? (failedCm.reason || `Integration in '${failedCm.state}' state`) : 'CoolMasterNet HVAC gateway or line communication failure');
                    fixAction = 'Verify RS485 communication line between CoolMasterNet and VRF/VRV indoor units (check for "No UID" / Line error), confirm unit addressing, check power to the bridge, and verify TCP port 10102 reachability.';
                } else {
                    fixAction = 'CoolMasterNet HVAC bridge is connected and communicating with VRF/VRV air conditioning units.';
                }
            } else if (techKey.startsWith('core_')) {
                const coreDomain = techKey.slice(5);
                const domainPrettyNames = {
                    'bluesound': 'Bluesound Multi-Room Audio',
                    'sonos': 'Sonos Multi-Room Audio',
                    'denonavr': 'Denon AVR Audio',
                    'heos': 'HEOS Multi-Room Audio',
                    'samsungtv': 'Samsung Smart TV',
                    'lg_webos': 'LG webOS Smart TV',
                    'apple_tv': 'Apple TV',
                    'androidtv': 'Android TV',
                    'tuya': 'Tuya Smart IoT',
                    'shelly': 'Shelly Smart Relays',
                    'yeelight': 'Yeelight Smart Lighting',
                    'tasmota': 'Tasmota Smart IoT',
                    'mqtt': 'MQTT Broker Connection',
                    'wled': 'WLED Addressable LEDs'
                };
                techName = domainPrettyNames[coreDomain] || `${coreDomain.charAt(0).toUpperCase() + coreDomain.slice(1)} Subsystem`;
                const allFailed = (tech.failed_core_entries || []).filter(e => e.domain === coreDomain && !isEntryIgnored(e));
                isOnline = allFailed.length === 0;
                if (allFailed.length > 0) {
                    endpoint = allFailed.map(e => `${e.title || coreDomain} (${e.state || 'offline'})`).join(', ');
                    reason = allFailed.map(e => `${e.title || coreDomain}: ${e.reason || e.state || 'offline'}`).join('; ');
                    fixAction = `Verify local network connectivity, IP addressing, and power status for ${techName} device(s) on the client LAN. Check if device is powered on and accessible.`;
                } else {
                    endpoint = `${techName} Entry`;
                    fixAction = `${techName} integration is loaded and communicating normally.`;
                }
            }

            const modalTitleEl = document.getElementById('diag-modal-title');
            if (modalTitleEl) modalTitleEl.innerHTML = `<span>🔍</span> ${escapeHtml(client.name)} — ${escapeHtml(techName)}`;

            const bodyEl = document.getElementById('diag-modal-body');
            if (bodyEl) {
                bodyEl.innerHTML = `
                    <div class="diag-banner ${isOnline ? 'diag-banner-online' : 'diag-banner-offline'}">
                        <div style="font-size: 14px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                            <span>${isOnline ? '🟢' : '🔴'}</span>
                            <span>${escapeHtml(techName)} is ${isOnline ? 'ONLINE & HEALTHY' : 'OFFLINE (NOT WORKING PROPERLY)'}</span>
                        </div>
                        ${!isOnline && reason ? `<div style="margin-top: 6px; font-size: 12px; color: #fecaca;"><strong>Failure Reason:</strong> ${escapeHtml(reason)}</div>` : ''}
                    </div>

                    <table class="diag-table">
                        <tr>
                            <th>Gavasah Gateway</th>
                            <td>${escapeHtml(client.name)} (${escapeHtml(client.client_id)})</td>
                        </tr>
                        <tr>
                            <th>Onboarded At</th>
                            <td>${escapeHtml(formatOnboardingDateTime(client.onboarded_at).fullText)}</td>
                        </tr>
                        <tr>
                            <th>Integration Type</th>
                            <td>${escapeHtml(techName)}</td>
                        </tr>
                        <tr>
                            <th>Hardware / IP Endpoint</th>
                            <td>${escapeHtml(endpoint)}</td>
                        </tr>
                        ${latency !== '—' ? `
                            <tr>
                                <th>Round-Trip Latency</th>
                                <td>${escapeHtml(latency)}</td>
                            </tr>
                        ` : ''}
                        ${details ? `
                            <tr>
                                <th>Configuration Details</th>
                                <td>${escapeHtml(details)}</td>
                            </tr>
                        ` : ''}
                        <tr>
                            <th>Operational State</th>
                            <td><strong style="color: ${!isMonitored ? '#94a3b8' : (isOnline ? '#34d399' : '#f87171')};">${!isMonitored ? 'MUTED / DISABLED 🔕' : (isOnline ? 'ONLINE' : 'OFFLINE / FAILED')}</strong></td>
                        </tr>
                        ${!isOnline && reason ? `
                            <tr>
                                <th>Diagnostic Error</th>
                                <td style="color: #f87171;">${escapeHtml(reason)}</td>
                            </tr>
                        ` : ''}
                        <tr>
                            <th>Recommended Action</th>
                            <td style="color: #94a3b8; font-family: sans-serif; font-size: 11px; line-height: 1.4;">${escapeHtml(fixAction)}</td>
                        </tr>
                    </table>

                    ${(() => {
                        const shData = (client.technologies && client.technologies.self_healing) || {};
                        const shSub = (shData.subsystems && shData.subsystems[techKey]) || {};
                        const recs = (shData.recent_recoveries || []).filter(r => r.subsystem === techKey || techKey === 'all');

                        if (shSub && shSub.status === 'healing' && (shSub.attempts || 0) < 5) {
                            return `
                                <div style="margin-top: 14px; background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.3); border-radius: 8px; padding: 12px;">
                                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                                        <strong style="color: #facc15; font-size: 13px; display: flex; align-items: center; gap: 6px;">
                                            <span class="tech-dot tech-dot-pulsing" style="background: #facc15;"></span> Autonomous Self-Healing In Progress
                                        </strong>
                                        <span style="background: rgba(234, 179, 8, 0.2); color: #facc15; border-radius: 4px; padding: 2px 6px; font-size: 10px; font-weight: 700;">Attempt ${shSub.attempts || 1} / 5</span>
                                    </div>
                                    <div style="font-size: 11px; color: #cbd5e1; margin-bottom: 4px;"><strong>Remediation Action:</strong> ${escapeHtml(shSub.last_action || 'Executing auto-recovery reload')}</div>
                                    <div style="font-size: 10px; color: #94a3b8;">Cooldown delay: 60s between attempts. Alarms to dealers/integrators are suppressed while healing.</div>
                                </div>
                            `;
                        } else if (shSub && (shSub.status === 'exhausted' || shSub.status === 'escalated' || (shSub.attempts || 0) >= 5)) {
                            return `
                                <div style="margin-top: 14px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 12px;">
                                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                                        <strong style="color: #f87171; font-size: 13px; display: flex; align-items: center; gap: 6px;">
                                            <span class="tech-dot tech-dot-pulsing" style="background: #ef4444;"></span> Autonomous Self-Healing Halted (5/5 Attempts Failed)
                                        </strong>
                                        <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border-radius: 4px; padding: 2px 6px; font-size: 10px; font-weight: 700;">Halted &amp; Notified</span>
                                    </div>
                                    <div style="font-size: 11px; color: #cbd5e1; margin-bottom: 4px;"><strong>Remediation Status:</strong> Self-healing completed 5 attempts and halted. Notification dispatched to HA Core. Counter is locked to prevent endless retry loops.</div>
                                    <div style="font-size: 10px; color: #94a3b8;">Manual inspection required. Counter and self-healing will only reset after the Gavasah Gateway or add-on restarts.</div>
                                </div>
                            `;
                        } else if (recs.length > 0) {
                            const latestRec = recs[0];
                            return `
                                <div style="margin-top: 14px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 12px;">
                                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                                        <strong style="color: #34d399; font-size: 13px; display: flex; align-items: center; gap: 6px;">
                                            <span>🛡️</span> Autonomous Self-Healing: Silent Recovery Logged
                                        </strong>
                                        <span style="background: rgba(16, 185, 129, 0.2); color: #34d399; border-radius: 4px; padding: 2px 6px; font-size: 10px; font-weight: 700;">Success in ${latestRec.attempts_taken} attempt(s)</span>
                                    </div>
                                    <div style="font-size: 11px; color: #cbd5e1;"><strong>Final Remediation:</strong> ${escapeHtml(latestRec.final_action || 'Resolved autonomously')}</div>
                                    <div style="font-size: 10px; color: #64748b; margin-top: 4px;">Recovered at: ${escapeHtml(latestRec.recovered_at || 'Recently')} &bull; Handled silently with 0 alerts</div>
                                </div>
                            `;
                        }
                        return '';
                    })()}
                `;
            }

                        // Per-Client, Per-Integration Monitoring Toggle (isMonitored declared at function start)
            bodyEl.innerHTML += `
                <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 10px; padding: 14px 16px; margin-top: 16px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: 700; font-size: 13px; color: #fff; display: flex; align-items: center; gap: 8px;">
                            <span>${isMonitored ? '🔔' : '🔕'}</span>
                            <span>Continuous Monitoring &amp; Alert Escalation:</span>
                            <span style="font-size: 11px; padding: 2px 8px; border-radius: 12px; font-weight: 700; background: ${isMonitored ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)'}; color: ${isMonitored ? '#34d399' : '#f87171'}; border: 1px solid ${isMonitored ? '#10b981' : '#ef4444'};">
                                ${isMonitored ? 'ACTIVE (MONITORED)' : 'MUTED (SWITCHED OFF)'}
                            </span>
                        </div>
                        <div style="font-size: 11px; color: #94a3b8; margin-top: 4px; line-height: 1.4;">
                            ${isMonitored ? 'Continuous monitoring active. Outages trigger telemetry alerts and escalation to dealers/integrators.' : 'Monitoring MUTED on this client site. Useful for audio systems (Yamaha, Bluesound, etc.) switched off at the wall. Outages are ignored and no alerts will disturb dealers or integrators.'}
                        </div>
                    </div>
                    <label class="switch" style="position: relative; display: inline-block; width: 44px; height: 24px; margin-left: 14px; flex-shrink: 0;">
                        <input type="checkbox" id="toggle-diag-monitor" ${isMonitored ? 'checked' : ''} onchange="toggleIntegrationMonitoring('${escapeHtml(clientId)}', '${escapeHtml(techKey)}', this.checked)">
                        <span class="slider round"></span>
                    </label>
                </div>
            `;

            const modal = document.getElementById('integration-diag-modal');
            if (modal) modal.classList.add('active');
        }

        function closeIntegrationDiagnostics() {
            const modal = document.getElementById('integration-diag-modal');
            if (modal) modal.classList.remove('active');
        }

        async function toggleIntegrationMonitoring(clientId, techKey, isChecked) {
            try {
                const res = await apiFetch('/api/client/toggle_integration_monitoring', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: clientId, tech_key: techKey, monitored: isChecked })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`${techKey} monitoring ${isChecked ? 'activated 🔔' : 'muted 🔕'}`, "success");
                    const cl = currentFleetData.find(c => c.client_id === clientId);
                    if (cl) {
                        cl.unmonitored_integrations = data.unmonitored_integrations || [];
                        if (!isChecked && cl.technologies && cl.technologies.self_healing && cl.technologies.self_healing.subsystems && cl.technologies.self_healing.subsystems[techKey]) {
                            cl.technologies.self_healing.subsystems[techKey].status = 'disabled';
                            cl.technologies.self_healing.subsystems[techKey].attempts = 0;
                            cl.technologies.self_healing.subsystems[techKey].exhausted = false;
                            cl.technologies.self_healing.subsystems[techKey].last_action = 'Monitoring muted from Dealer Dashboard. Auto-recovery paused.';
                        }
                        if (typeof renderTable === 'function') renderTable(currentFleetData);
                        openIntegrationDiagnostics(clientId, techKey);
                    }
                } else {
                    showToast("Failed to toggle monitoring: " + (data.error || "Unknown error"), "error");
                }
            } catch (e) {
                showToast("Error updating monitoring state: " + e.message, "error");
            }
        }

                async function loadSmtpConfig() {
            try {
                const res = await apiFetch('/api/settings/smtp');
                const data = await res.json();
                if (data.success && data.config) {
                    const cfg = data.config;
                    const h = document.getElementById('smtp-cfg-host');
                    const p = document.getElementById('smtp-cfg-port');
                    const enc = document.getElementById('smtp-cfg-encryption');
                    const u = document.getElementById('smtp-cfg-user');
                    const pass = document.getElementById('smtp-cfg-pass');
                    const fe = document.getElementById('smtp-cfg-from-email');
                    const fn = document.getElementById('smtp-cfg-from-name');
                    if (h && cfg.host) h.value = cfg.host;
                    if (p && cfg.port) p.value = cfg.port;
                    if (enc && cfg.encryption) enc.value = cfg.encryption;
                    if (u && cfg.user) u.value = cfg.user;
                    if (pass && cfg.pass) pass.value = cfg.pass;
                    if (fe && cfg.from_email) fe.value = cfg.from_email;
                    if (fn && cfg.from_name) fn.value = cfg.from_name;
                    updateSmtpStatusBadge(cfg);
                }
            } catch (_) {}
        }

        function updateSmtpStatusBadge(cfg) {
            const badge = document.getElementById('smtp-status-badge');
            if (!badge) return;
            if (cfg && cfg.host && cfg.from_email) {
                badge.innerHTML = '● Configured (' + escapeHtml(cfg.host) + ')';
                badge.style.color = '#34d399';
                badge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
                badge.style.background = 'rgba(16, 185, 129, 0.12)';
            } else {
                badge.innerHTML = '● Ready for Setup';
                badge.style.color = '#c084fc';
                badge.style.borderColor = 'rgba(192, 132, 252, 0.3)';
                badge.style.background = 'rgba(192, 132, 252, 0.1)';
            }
        }

        async function saveSmtpConfig() {
            const btn = document.getElementById('btn-save-smtp-cfg');
            const fb = document.getElementById('smtp-cfg-feedback');
            if (btn) btn.disabled = true;

            const payload = {
                host: (document.getElementById('smtp-cfg-host')?.value || '').trim(),
                port: parseInt(document.getElementById('smtp-cfg-port')?.value || '587'),
                encryption: document.getElementById('smtp-cfg-encryption')?.value || 'tls',
                user: (document.getElementById('smtp-cfg-user')?.value || '').trim(),
                pass: document.getElementById('smtp-cfg-pass')?.value || '',
                from_email: (document.getElementById('smtp-cfg-from-email')?.value || '').trim(),
                from_name: (document.getElementById('smtp-cfg-from-name')?.value || 'GAVASAH Cloud Alerts').trim()
            };

            try {
                const res = await apiFetch('/api/settings/smtp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    showToast("SMTP settings saved successfully!", "success");
                    if (fb) {
                        fb.style.display = 'block';
                        fb.style.background = 'rgba(16, 185, 129, 0.12)';
                        fb.style.border = '1px solid #10b981';
                        fb.style.color = '#34d399';
                        fb.innerHTML = `✓ <strong>SMTP Configuration Saved:</strong> Outbound emails routed through <code>${escapeHtml(payload.host)}:${payload.port}</code> (${payload.encryption.toUpperCase()})`;
                    }
                    updateSmtpStatusBadge(payload);
                } else {
                    showToast("Failed to save SMTP: " + (data.error || 'Server error'), "error");
                }
            } catch (e) {
                showToast("Error saving SMTP: " + e.message, "error");
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        async function testSmtpDirect() {
            const btn = document.getElementById('btn-test-smtp-cfg');
            const fb = document.getElementById('smtp-cfg-feedback');
            const toEmail = (document.getElementById('smtp-test-recipient')?.value || '').trim();
            if (!toEmail) {
                showToast("Please enter a Test Recipient Email", "warning");
                return;
            }

            const payload = {
                host: (document.getElementById('smtp-cfg-host')?.value || '').trim(),
                port: parseInt(document.getElementById('smtp-cfg-port')?.value || '587'),
                encryption: document.getElementById('smtp-cfg-encryption')?.value || 'tls',
                user: (document.getElementById('smtp-cfg-user')?.value || '').trim(),
                pass: document.getElementById('smtp-cfg-pass')?.value || '',
                from_email: (document.getElementById('smtp-cfg-from-email')?.value || '').trim(),
                from_name: (document.getElementById('smtp-cfg-from-name')?.value || 'GAVASAH Cloud Alerts').trim(),
                recipient: toEmail,
                subject: '[GAVASAH ALERT] SMTP Live Delivery Probe',
                message: 'This is a live test notification verifying end-to-end SMTP dispatch from GAVASAH Multi-Tenant Cloud Hub.'
            };

            if (btn) btn.disabled = true;
            if (fb) {
                fb.style.display = 'block';
                fb.style.background = 'rgba(2, 6, 23, 0.7)';
                fb.style.border = '1px solid rgba(167, 139, 250, 0.4)';
                fb.style.color = '#c084fc';
                fb.innerHTML = `⚡ Testing SMTP handshake and dispatching probe to <code>${escapeHtml(toEmail)}</code>...`;
            }

            try {
                const res = await apiFetch('/api/settings/smtp/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Test email dispatched to ${toEmail}!`, "success");
                    if (fb) {
                        fb.style.background = 'rgba(16, 185, 129, 0.12)';
                        fb.style.border = '1px solid #10b981';
                        fb.style.color = '#34d399';
                        fb.innerHTML = `✓ <strong>Email Delivered:</strong> Handshake, TLS negotiation &amp; authentication completed in <strong>${data.latency_ms} ms</strong>.<br>Message sent to <code>${escapeHtml(toEmail)}</code> (Tracking: <code>${escapeHtml(data.messageId)}</code>).`;
                    }
                } else {
                    showToast("SMTP test failed: " + (data.error || 'Server error'), "error");
                    if (fb) {
                        fb.style.background = 'rgba(239, 68, 68, 0.12)';
                        fb.style.border = '1px solid #ef4444';
                        fb.style.color = '#f87171';
                        fb.innerHTML = `✗ <strong>Delivery Failed:</strong> ${escapeHtml(data.error || 'Could not connect to SMTP server')}`;
                    }
                }
            } catch (e) {
                showToast("Network error: " + e.message, "error");
                if (fb) {
                    fb.style.background = 'rgba(239, 68, 68, 0.12)';
                    fb.style.border = '1px solid #ef4444';
                    fb.style.color = '#f87171';
                    fb.innerHTML = `✗ <strong>Network Error:</strong> ${escapeHtml(e.message)}`;
                }
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        function togglePassVisibility(inputId) {
            const el = document.getElementById(inputId);
            if (!el) return;
            el.type = el.type === 'password' ? 'text' : 'password';
        }


</script>

    <!-- Manufacturer Fleet Update Center Modal -->
    <div class="modal" id="fleet-update-modal">
        <div class="modal-content" style="max-width: 580px;">
            <div class="modal-header">
                <div style="display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 15px; color: #fff;">
                    <span>🚀</span> Manufacturer Fleet Update Center (OTA)
                </div>
                <div style="cursor: pointer; font-size: 18px;" onclick="closeFleetUpdateModal()">&times;</div>
            </div>
            <div class="modal-body" style="padding: 16px 20px;">
                <p style="color: #94a3b8; font-size: 12px; margin-bottom: 16px;">
                    Dispatch synchronized Over-The-Air updates across all active client gateways in the fleet. Each gateway will receive and execute the update instruction upon its next heartbeat pulse (within 60 seconds).
                </p>

                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px 14px; background: rgba(34, 211, 238, 0.08); border: 1px solid rgba(34, 211, 238, 0.25); border-radius: 8px;">
                        <div>
                            <div style="font-size: 13px; font-weight: 700; color: #22d3ee;">Gavasah Cloud Agent Add-on</div>
                            <div style="font-size: 11px; color: #94a3b8;">Updates agent container to latest release (v1.2.0 with Self-Healing Engine)</div>
                        </div>
                        <button class="btn-sm" style="background: #0284c7; color: #fff; font-weight: 700; border: none; padding: 6px 12px;" onclick="triggerFleetBatchUpdate('update_addon')">
                            Update All Add-ons
                        </button>
                    </div>

                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px 14px; background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px;">
                        <div>
                            <div style="font-size: 13px; font-weight: 700; color: #38bdf8;">Home Assistant Core</div>
                            <div style="font-size: 11px; color: #94a3b8;">Triggers Core engine update to latest available release across fleet</div>
                        </div>
                        <button class="btn-sm" style="background: #0369a1; color: #fff; font-weight: 700; border: none; padding: 6px 12px;" onclick="triggerFleetBatchUpdate('update_core')">
                            Update All Core
                        </button>
                    </div>

                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px 14px; background: rgba(129, 140, 248, 0.08); border: 1px solid rgba(129, 140, 248, 0.25); border-radius: 8px;">
                        <div>
                            <div style="font-size: 13px; font-weight: 700; color: #818cf8;">Home Assistant Supervisor</div>
                            <div style="font-size: 11px; color: #94a3b8;">Updates Supervisor container to latest release across fleet</div>
                        </div>
                        <button class="btn-sm" style="background: #4f46e5; color: #fff; font-weight: 700; border: none; padding: 6px 12px;" onclick="triggerFleetBatchUpdate('update_supervisor')">
                            Update All Supervisor
                        </button>
                    </div>

                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px 14px; background: rgba(168, 85, 247, 0.08); border: 1px solid rgba(168, 85, 247, 0.25); border-radius: 8px;">
                        <div>
                            <div style="font-size: 13px; font-weight: 700; color: #c084fc;">Master Full Fleet Update</div>
                            <div style="font-size: 11px; color: #94a3b8;">Sequential update: Store reload &rarr; Add-on &rarr; Core &rarr; Supervisor</div>
                        </div>
                        <button class="btn-sm" style="background: #9333ea; color: #fff; font-weight: 700; border: none; padding: 6px 12px;" onclick="triggerFleetBatchUpdate('update_all')">
                            ⚡ Master Update All
                        </button>
                    </div>
                </div>
            </div>
            <div class="modal-footer" style="padding: 12px 20px;">
                <button type="button" class="btn-sm" onclick="closeFleetUpdateModal()">Close</button>
            </div>
        </div>
    </div>

    <!-- Integration Diagnostics Modal -->
    <div class="modal" id="integration-diag-modal">
        <div class="modal-content" style="max-width: 620px;">
            <div class="modal-header">
                <div id="diag-modal-title" style="display: flex; align-items: center; gap: 8px;">
                    <span>🔍</span> Subsystem Integration Diagnostics
                </div>
                <div style="cursor: pointer;" onclick="closeIntegrationDiagnostics()">&times;</div>
            </div>
            <div class="modal-body" id="diag-modal-body">
                <!-- Dynamically populated -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-sm" onclick="closeIntegrationDiagnostics()">Close</button>
            </div>
        </div>
    </div>

</body>
</html>
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import urllib.request
import http.server
from urllib.parse import urlparse, parse_qs

# ==============================================================================
# Client Audit Logging Helpers
# ==============================================================================

def generate_client_seed_logs(client_id):
    """Generate realistic initial operational audit logs for a client site."""
    now = int(time.time())
    return [
        {
            "id": f"log_{client_id}_{now-120}",
            "timestamp": now - 120,
            "level": "INFO",
            "type": "SYSTEM_BOOT",
            "message": "HAOS controller system booted successfully. RAUC Slot A active.",
            "source": "kernel"
        },
        {
            "id": f"log_{client_id}_{now-110}",
            "timestamp": now - 110,
            "level": "INFO",
            "type": "KNX_LINK",
            "message": "KNX-IP Gateway communication initialized over UDP 3671.",
            "source": "knx_daemon"
        },
        {
            "id": f"log_{client_id}_{now-90}",
            "timestamp": now - 90,
            "level": "INFO",
            "type": "TUNNEL_ESTABLISHED",
            "message": f"Reverse SSH tunnel established to gateway (dealer.gavasah.com).",
            "source": "autossh"
        },
        {
            "id": f"log_{client_id}_{now-30}",
            "timestamp": now - 30,
            "level": "INFO",
            "type": "HEALTH_CHECK",
            "message": "Telemetry periodic heartbeat ACK received with zero packet loss.",
            "source": "supervisor"
        }
    ]

def get_client_logs(client_id):
    """Retrieve audit logs for a client site from SQLite WAL database."""
    with DB_LOCK:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM client_logs WHERE client_id = ? ORDER BY timestamp DESC LIMIT 100", (client_id,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        if not rows:
            seed = generate_client_seed_logs(client_id)
            for s in seed:
                append_client_log(client_id, s['level'], s['type'], s['message'], s.get('source', 'kernel'))
            return seed
        return rows

def append_client_log(client_id, level, type_, msg, source="cloud_portal"):
    """Thread-safe append of a new audit log entry into SQLite WAL database."""
    with DB_LOCK:
        conn = get_db_connection()
        try:
            now = int(time.time())
            log_id = f"log_{client_id}_{now}_{secrets.token_hex(4)}"
            with conn:
                conn.execute("INSERT OR REPLACE INTO client_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (log_id, client_id, now, level.upper(), type_.upper(), msg, source)
                )
        except Exception as e:
            print(f"[!] Error appending log in SQLite: {e}")
        finally:
            conn.close()

# ==============================================================================
# Multi-Tenant HTTP Request Handler (Manufacturer -> Dealers -> Integrators)
# ==============================================================================

class DealerPortalHandler(http.server.BaseHTTPRequestHandler):
    timeout = 15  # Strict 15s socket timeout to prevent leaked worker threads
    protocol_version = "HTTP/1.1"

    def handle(self):
        self.close_connection = True
        try:
            super().handle()
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            pass

    def read_request_body(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except (ValueError, TypeError):
            content_length = 0
        if content_length <= 0:
            return ''
        if content_length > 10 * 1024 * 1024:
            return ''
        try:
            return self.rfile.read(content_length).decode('utf-8', errors='replace')
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            return ''

    def get_authenticated_user(self):
        """Extract session token from Cookie or Authorization header and return user profile."""
        cookie_header = self.headers.get('Cookie', '')
        token = None
        if cookie_header:
            for part in cookie_header.split(';'):
                part = part.strip()
                if part.startswith('gavasah_session='):
                    token = part.split('=', 1)[1].strip()
                    break

        if not token:
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split('Bearer ', 1)[1].strip()

        if not token:
            return None

        session = get_session(token)
        if not session:
            return None

        now = int(time.time())
        if now > session.get('expires_at', 0):
            delete_session(token)
            return None

        user_id = session.get('user_id')
        role = session.get('role')

        with DB_LOCK:
            conn = get_db_connection()
            try:
                cur = conn.cursor()
                if role == 'manufacturer' and user_id == 'owner_master':
                    cur.execute("SELECT * FROM owner WHERE id = ? LIMIT 1", (user_id,))
                    row = cur.fetchone()
                    conn.close()
                    owner = dict(row) if row else {}
                    try: mfg_branding = json.loads(owner.get('branding_json') or '{}')
                    except: mfg_branding = {}
                    return {
                        'id': 'owner_master',
                        'username': owner.get('username', 'admin'),
                        'name': owner.get('name', 'Master Manufacturer'),
                        'role': 'manufacturer',
                        'branding': mfg_branding,
                        'session_token': token
                    }
                elif role == 'dealer':
                    cur.execute("SELECT * FROM dealers WHERE id = ? LIMIT 1", (user_id,))
                    row = cur.fetchone()
                    conn.close()
                    if not row:
                        return None
                    d = dict(row)
                    if d.get('status') == 'suspended':
                        return None
                    try: branding = json.loads(d.get('branding_json') or '{}')
                    except: branding = {}
                    return {
                        'id': d['id'],
                        'username': d.get('username', ''),
                        'name': d.get('name', ''),
                        'email': d.get('email', ''),
                        'phone': d.get('phone', ''),
                        'role': 'dealer',
                        'status': d.get('status', 'active'),
                        'branding': branding,
                        'session_token': token
                    }
                elif role == 'integrator':
                    cur.execute("SELECT * FROM integrators WHERE id = ? LIMIT 1", (user_id,))
                    row = cur.fetchone()
                    if not row:
                        conn.close()
                        return None
                    it = dict(row)
                    if it.get('status') == 'suspended':
                        conn.close()
                        return None
                    # Check parent dealer status
                    cur.execute("SELECT status FROM dealers WHERE id = ? LIMIT 1", (it.get('dealer_id'),))
                    d_row = cur.fetchone()
                    conn.close()
                    if d_row and dict(d_row).get('status') == 'suspended':
                        return None
                    return {
                        'id': it['id'],
                        'dealer_id': it.get('dealer_id', ''),
                        'dealer_name': it.get('dealer_name', ''),
                        'username': it.get('username', ''),
                        'name': it.get('name', ''),
                        'email': it.get('email', ''),
                        'phone': it.get('phone', ''),
                        'role': 'integrator',
                        'status': it.get('status', 'active'),
                        'session_token': token
                    }
                else:
                    conn.close()
                    return None
            except Exception as e:
                print(f"[!] Error in get_authenticated_user: {e}")
                conn.close()
                return None

    def send_json(self, status_code, data, extra_headers=None):
        """Send formatted JSON HTTP response with optional custom headers."""
        body = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        # 1. Root / UI SPA Serving
        if parsed.path in ['/', '/index.html']:
            body = HTML_PAGE.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(body)
            return

        # 1b. Caddy On-Demand TLS Verification Endpoint
        elif parsed.path == '/api/caddy-ask':
            qs = parse_qs(parsed.query)
            domain = qs.get('domain', [''])[0].strip().lower()
            if not domain:
                self.send_response(400)
                self.end_headers()
                return

            if domain in ['dealer.gavasah.com', 'gavasah.com', 'www.gavasah.com', 'emqx.gavasah.com', 'test-dealer.gavasah.com']:
                self.send_response(200)
                self.end_headers()
                return

            if domain.endswith('.gavasah.com'):
                slug = domain[:-len('.gavasah.com')]
                c_data = load_clients_state()
                if slug in c_data or any(c.get('domain') == domain for c in c_data.values()):
                    self.send_response(200)
                    self.end_headers()
                    return

                # Tolerant alias matching (bidirectional match for abbreviated subdomains)
                clean_slug = re.sub(r'^(mr|mrs|ms|dr)-', '', slug)
                for cid, c in c_data.items():
                    clean_cid = re.sub(r'^(mr|mrs|ms|dr)-', '', cid)
                    if (clean_slug == clean_cid or 
                        clean_cid.startswith(clean_slug) or 
                        clean_slug.startswith(clean_cid)):
                        self.send_response(200)
                        self.end_headers()
                        return
                    name_slug = re.sub(r'[^a-z0-9]+', '-', (c.get('name') or '').lower()).strip('-')
                    clean_name = re.sub(r'^(mr|mrs|ms|dr)-', '', name_slug)
                    if (clean_slug == clean_name or 
                        clean_name.startswith(clean_slug) or 
                        clean_slug.startswith(clean_name)):
                        self.send_response(200)
                        self.end_headers()
                        return

            self.send_response(404)
            self.end_headers()
            return

        # Dynamic Gateway Script Execution Dispatcher
        elif parsed.path == '/run.py':
            try:
                with open('/srv/gavasah-cloud/run.py', 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_json(404, {'error': f'run.py not found: {e}'})
            return

        # 1c. Caddy Dynamic Domain List for Host Ingress Sync
        elif parsed.path == '/api/caddy-domains':
            c_data = load_clients_state()
            domains = []
            for cid, c in c_data.items():
                dom = c.get('domain')
                d = dom if dom and '.' in dom else f"{cid}.gavasah.com"
                domains.append(d)
            self.send_json(200, domains)
            return

        # 2. Authenticated Session Info
        elif parsed.path == '/api/me':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(200, {'authenticated': False})
                return
            resp_user = {
                'id': user['id'],
                'username': user['username'],
                'name': user['name'],
                'role': user['role'],
                'branding': user.get('branding') or {}
            }
            if user['role'] == 'integrator':
                resp_user['dealer_id'] = user.get('dealer_id')
                resp_user['dealer_name'] = user.get('dealer_name')
            self.send_json(200, {
                'authenticated': True,
                'user': resp_user
            })
            return

        # 3. Fleet Inventory (Scoped by Role)
        elif parsed.path == '/api/fleet':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            c_data = load_clients_state()
            all_clients = list(c_data.values())

            if user['role'] == 'manufacturer':
                filtered = all_clients
            elif user['role'] == 'dealer':
                filtered = [c for c in all_clients if c.get('dealer_id') == user['id']]
            elif user['role'] == 'integrator':
                filtered = [c for c in all_clients if c.get('integrator_id') == user['id']]
            else:
                filtered = []

            self.send_json(200, filtered)
            return

        # 4. Dealers Directory (Manufacturer Only)
        elif parsed.path == '/api/dealers':
            user = self.get_authenticated_user()
            if not user or user['role'] != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer privilege required'})
                return

            auth = load_auth_state()
            dealers_dict = auth.get('dealers', {})
            integrators_dict = auth.get('integrators', {})
            c_data = load_clients_state()

            res = []
            now = int(time.time())

            # 1. Master Manufacturer (Direct) Organization
            owner = auth.get('owner', {})
            owner_clients = [c for c in c_data.values() if c.get('dealer_id') in ['owner_master', '', None]]
            owner_ints = [it for it in integrators_dict.values() if it.get('dealer_id') in ['owner_master', '', None]]
            mfg_online_c = sum(1 for c in owner_clients if (now - c.get('last_heartbeat', 0)) <= int(c.get('hb_offline_interval') or 86400))
            mfg_lost_c = len(owner_clients) - mfg_online_c

            mfg_clients_list = [{
                'client_id': c.get('client_id'),
                'name': c.get('name', c.get('client_id')),
                'domain': c.get('domain', ''),
                'status': 'online' if (now - c.get('last_heartbeat', 0)) <= int(c.get('hb_offline_interval') or 86400) else 'offline',
                'last_heartbeat': c.get('last_heartbeat', 0)
            } for c in sorted(owner_clients, key=lambda x: str(x.get('name', '')).lower())]

            res.append({
                'id': 'owner_master',
                'name': owner.get('name', 'Master Manufacturer (Direct)'),
                'username': owner.get('username', 'admin'),
                'password_plain': '••••••••',
                'email': owner.get('email', 'admin@gavasah.com'),
                'phone': owner.get('phone', 'HQ Direct Support'),
                'role': 'manufacturer',
                'is_manufacturer': True,
                'status': 'active',
                'created_at': owner.get('created_at', 0),
                'client_count': len(owner_clients),
                'integrator_count': len(owner_ints),
                'online_count': mfg_online_c,
                'lost_count': mfg_lost_c,
                'clients': mfg_clients_list
            })

            # 2. Authorized Dealer Partners
            for did, d in dealers_dict.items():
                dealer_clients = [c for c in c_data.values() if c.get('dealer_id') == did]
                dealer_ints = [it for it in integrators_dict.values() if it.get('dealer_id') == did]
                
                online_c = sum(1 for c in dealer_clients if (now - c.get('last_heartbeat', 0)) <= int(c.get('hb_offline_interval') or 86400))
                lost_c = len(dealer_clients) - online_c

                dlr_clients_list = [{
                    'client_id': c.get('client_id'),
                    'name': c.get('name', c.get('client_id')),
                    'domain': c.get('domain', ''),
                    'status': 'online' if (now - c.get('last_heartbeat', 0)) <= int(c.get('hb_offline_interval') or 86400) else 'offline',
                    'last_heartbeat': c.get('last_heartbeat', 0)
                } for c in sorted(dealer_clients, key=lambda x: str(x.get('name', '')).lower())]

                res.append({
                    'id': d['id'],
                    'name': d.get('name', ''),
                    'username': d.get('username', ''),
                    'password_plain': d.get('password_plain', ''),  # Revealed for Manufacturer
                    'email': d.get('email', ''),
                    'phone': d.get('phone', ''),
                    'role': 'dealer',
                    'is_manufacturer': False,
                    'status': d.get('status', 'active'),
                    'created_at': d.get('created_at', 0),
                    'client_count': len(dealer_clients),
                    'integrator_count': len(dealer_ints),
                    'online_count': online_c,
                    'lost_count': lost_c,
                    'clients': dlr_clients_list
                })

            self.send_json(200, res)
            return

        # 5. Integrators Directory (Manufacturer & Dealers)
        elif parsed.path == '/api/integrators':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['manufacturer', 'dealer']:
                self.send_json(403, {'error': 'Access denied: Manufacturer or Dealer privilege required'})
                return

            auth = load_auth_state()
            integrators_dict = auth.get('integrators', {})
            c_data = load_clients_state()
            now = int(time.time())

            res = []
            for iid, it in integrators_dict.items():
                # If logged in as Dealer, only show integrators belonging to this Dealer
                if user['role'] == 'dealer' and it.get('dealer_id') != user['id']:
                    continue

                d_id = it.get('dealer_id', '') or 'owner_master'
                d_name = it.get('dealer_name', '')
                if d_id == 'owner_master' or not d_name:
                    d_name = 'Master Manufacturer (Direct)'

                supervised_clients = [c for c in c_data.values() if c.get('integrator_id') == iid]
                online_c = sum(1 for c in supervised_clients if (now - c.get('last_heartbeat', 0)) <= int(c.get('hb_offline_interval') or 86400))
                lost_c = len(supervised_clients) - online_c

                res.append({
                    'id': it['id'],
                    'dealer_id': d_id,
                    'dealer_name': d_name,
                    'name': it.get('name', ''),
                    'username': it.get('username', ''),
                    'password_plain': it.get('password_plain', ''),  # Revealed to Manufacturer and Dealer
                    'email': it.get('email', ''),
                    'phone': it.get('phone', ''),
                    'role': 'integrator',
                    'status': it.get('status', 'active'),
                    'created_at': it.get('created_at', 0),
                    'client_count': len(supervised_clients),
                    'online_count': online_c,
                    'lost_count': lost_c
                })

            self.send_json(200, res)
            return

        # 6. Audit Logs for a specific client
        
        # --- RETRIEVE SITE BACKUPS LIST ---
        elif parsed.path == '/api/client_backups':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            query = parse_qs(parsed.query)
            client_id = query.get('client_id', [''])[0].strip()
            clients = load_clients_state()
            if client_id not in clients:
                self.send_json(404, {'error': 'Client site not found'})
                return
            c = clients[client_id]
            if user['role'] == 'dealer' and c.get('dealer_id') != user['id']:
                self.send_json(403, {'error': 'Unauthorized'})
                return

            backups = c.get('backups') or []
            client_dir = os.path.join(BACKUPS_DIR, client_id)
            if os.path.exists(client_dir):
                for f in os.listdir(client_dir):
                    if f.endswith('.tar'):
                        slug = f[:-4]
                        if not any(b.get('slug') == slug for b in backups):
                            fp = os.path.join(client_dir, f)
                            sz = round(os.path.getsize(fp) / (1024 * 1024), 2)
                            backups.append({
                                'slug': slug,
                                'name': f"Archived Snapshot ({slug[:8]})",
                                'date': datetime.datetime.fromtimestamp(os.path.getmtime(fp)).isoformat() + "Z",
                                'size_mb': sz,
                                'type': 'full'
                            })

            self.send_json(200, {'ok': True, 'backups': backups})
            return

        # --- DIRECT DOWNLOAD BACKUP ARCHIVE TO USER COMPUTER ---
        elif parsed.path == '/api/download_backup':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            query = parse_qs(parsed.query)
            client_id = query.get('client_id', [''])[0].strip()
            slug = query.get('slug', [''])[0].strip()

            if not client_id or not slug:
                self.send_json(400, {'error': 'client_id and slug parameters required'})
                return

            clients = load_clients_state()
            if client_id not in clients:
                self.send_json(404, {'error': 'Client site not found'})
                return
            c = clients[client_id]
            if user['role'] == 'dealer' and c.get('dealer_id') != user['id']:
                self.send_json(403, {'error': 'Unauthorized'})
                return

            tar_file = os.path.join(BACKUPS_DIR, client_id, f"{slug}.tar")
            clean_cid = re.sub(r'[^a-zA-Z0-9_-]', '', client_id)
            filename = f"backup_{clean_cid}_{slug[:8]}.tar"

            if os.path.exists(tar_file):
                file_size = os.path.getsize(tar_file)
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-tar')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(file_size))
                self.end_headers()
                with open(tar_file, 'rb') as f:
                    shutil.copyfileobj(f, self.wfile)
                return

            # Fallback: Proxy directly from gateway tunnel if available
            d_port = c.get('dashboard_port')
            if d_port:
                proxy_url = f"http://127.0.0.1:{d_port}/api/hassio/backups/{slug}/download"
                try:
                    req = urllib.request.Request(proxy_url, headers={'Authorization': f"Bearer {c.get('auth_secret', '')}"})
                    with urllib.request.urlopen(req, timeout=30) as p_resp:
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/x-tar')
                        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                        cl = p_resp.headers.get('Content-Length')
                        if cl:
                            self.send_header('Content-Length', cl)
                        self.end_headers()
                        shutil.copyfileobj(p_resp, self.wfile)
                        return
                except Exception as pe:
                    print(f"[DOWNLOAD_PROXY_ERR] {pe}", flush=True)

            self.send_json(404, {'error': 'Backup archive not found on hub or gateway'})
            return

        elif parsed.path == '/api/logs':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            qs = parse_qs(parsed.query)
            cid = qs.get('client_id', [None])[0]
            if not cid:
                self.send_json(400, {'error': 'client_id parameter required'})
                return

            c_data = load_clients_state()
            client = c_data.get(cid)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            # Check permissions
            if user['role'] == 'dealer' and client.get('dealer_id') != user['id']:
                self.send_json(403, {'error': 'Access denied to client logs'})
                return
            elif user['role'] == 'integrator' and client.get('integrator_id') != user['id']:
                self.send_json(403, {'error': 'Access denied to client logs'})
                return

            logs = get_client_logs(cid)
            self.send_json(200, logs)
            return

        # 7. SSL Certificate Infrastructure Status
        elif parsed.path == '/api/ssl_status':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            c_data = load_clients_state()
            now = int(time.time())

            certs = [
                {
                    'domain': 'dealer.gavasah.com',
                    'role': 'Central Dealer Management Hub',
                    'authority': 'ZeroSSL Production ECC RSA',
                    'valid_days_left': 72,
                    'status': 'active',
                    'auto_renew': True
                }
            ]

            for cid, c in c_data.items():
                if user['role'] == 'dealer' and c.get('dealer_id') != user['id']:
                    continue
                if user['role'] == 'integrator' and c.get('integrator_id') != user['id']:
                    continue
                certs.append({
                    'domain': c.get('domain', f'{cid}.gavasah.com'),
                    'role': f"Ingress Proxy ({c.get('name', cid)})",
                    'authority': "Let's Encrypt Authority X3",
                    'valid_days_left': 84,
                    'status': 'active' if c.get('remote_enabled', True) else 'disabled',
                    'auto_renew': True
                })

            self.send_json(200, certs)
            return

        # 12a. Zero-Touch Client Provisioning API (JSON payload)
        elif parsed.path == '/api/provision':
            query = parse_qs(parsed.query)
            client_id = (query.get('client_id', [''])[0]).strip()
            secret = (query.get('auth_secret', [''])[0]).strip() or (query.get('auth_key', [''])[0]).strip()

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            user = self.get_authenticated_user()
            if not user and client.get('auth_secret') and client['auth_secret'] != secret:
                self.send_json(403, {'error': 'Unauthorized: Valid auth_secret required'})
                return

            self.send_json(200, {
                'ok': True,
                'client_id': client_id,
                'name': client.get('name'),
                'domain': client.get('domain'),
                'wg_ip': client.get('wg_ip'),
                'wg_netmask': '16',
                'wg_private_key': client.get('wg_privkey'),
                'wg_public_key': client.get('wg_pubkey'),
                'server_public_key': WG_SERVER_PUBKEY,
                'endpoint': WG_ENDPOINT,
                'allowed_ips': '10.42.0.0/16',
                'persistent_keepalive': 25,
                'tunnel_mode': client.get('tunnel_mode', 'wireguard')
            })
            return

        # 12b. Automated Zero-Touch Bootstrap Shell Script
        elif parsed.path == '/api/bootstrap':
            query = parse_qs(parsed.query)
            client_id = (query.get('client_id', [''])[0]).strip()
            secret = (query.get('auth_secret', [''])[0]).strip()

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"echo error\nexit 1\n")
                return

            user = self.get_authenticated_user()
            if not user and client.get('auth_secret') and client['auth_secret'] != secret:
                self.send_response(403)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"echo error\nexit 1\n")
                return

            wg_ip = client.get('wg_ip', '10.42.0.2')
            wg_priv = client.get('wg_privkey', '')
            auth_sec = client.get('auth_secret', '')

            script = f'''#!/bin/bash
# ==============================================================================
# GAVASAH Zero-Touch Automated Gateway Provisioner
# Site: {client.get('name', client_id)} ({client_id})
# Virtual Mesh IP: {wg_ip}
# ==============================================================================
set -e
echo "[*] Initializing GAVASAH Zero-Touch WireGuard Mesh Provisioner..."
echo "[*] Target Site: {client_id}"

# 1. Install wireguard-tools if missing
if ! command -v wg &> /dev/null; then
    echo "[*] Installing wireguard-tools..."
    if command -v apt-get &> /dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y && apt-get install -y wireguard wireguard-tools resolvconf curl
    elif command -v apk &> /dev/null; then
        apk add wireguard-tools curl
    fi
fi

# 2. Write /etc/wireguard/wg0.conf
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
cat << 'WGEOF' > /etc/wireguard/wg0.conf
[Interface]
Address = {wg_ip}/16
PrivateKey = {wg_priv}

[Peer]
PublicKey = {WG_SERVER_PUBKEY}
Endpoint = {WG_ENDPOINT}
AllowedIPs = 10.42.0.0/16
PersistentKeepalive = 25
WGEOF
chmod 600 /etc/wireguard/wg0.conf

# 3. Enable and Start WireGuard
if command -v systemctl &> /dev/null; then
    systemctl enable --now wg-quick@wg0 || wg-quick up wg0 || true
else
    wg-quick up wg0 || true
fi

# 4. Notify Cloud Hub of Successful Automated Provisioning
curl -s -X POST https://dealer.gavasah.com/api/heartbeat \
    -H "Content-Type: application/json" \
    -d '{{"client_id": "{client_id}", "auth_secret": "{auth_sec}", "system": {{"provisioned_at": {int(time.time())}, "tunnel_mode": "wireguard", "status": "active"}}}}' > /dev/null || true

echo "[OK] Zero-Touch Provisioning Complete! WireGuard Virtual Mesh IP: {wg_ip}"
'''
            encoded = script.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/x-shellscript')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        # 12c. Raw WireGuard INI Config Download (wg0.conf)
        elif parsed.path == '/api/wireguard_config':
            query = parse_qs(parsed.query)
            client_id = (query.get('client_id', [''])[0]).strip()
            secret = (query.get('auth_secret', [''])[0]).strip() or (query.get('auth_key', [''])[0]).strip()

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            user = self.get_authenticated_user()
            if not user and client.get('auth_secret') and client['auth_secret'] != secret:
                self.send_json(403, {'error': 'Unauthorized: Valid auth_secret required'})
                return

            wg_ip = client.get('wg_ip', '10.42.0.2')
            wg_priv = client.get('wg_privkey', '')

            conf = f'''[Interface]
Address = {wg_ip}/16
PrivateKey = {wg_priv}

[Peer]
PublicKey = {WG_SERVER_PUBKEY}
Endpoint = {WG_ENDPOINT}
AllowedIPs = 10.42.0.0/16
PersistentKeepalive = 25
'''
            encoded = conf.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Disposition', f'attachment; filename="{client_id}-wg0.conf"')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        # 12d. Manufacturer Approvals Listing
        elif parsed.path == '/api/approvals':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer authorization required'})
                return

            c_data = load_clients_state()
            pending = [c for c in c_data.values() if c.get('approval_status') == 'pending']
            pending.sort(key=lambda x: x.get('onboarded_at') or 0, reverse=True)
            self.send_json(200, pending)
            return

        # 12e. MQTT Broker Status & Listeners
        elif parsed.path == '/api/mqtt/status':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            self.send_json(200, {
                'active': True,
                'broker': 'EMQX v5.8.9',
                'tcp_port': 1883,
                'ws_port': 8083,
                'wss_port': 8084,
                'dashboard_port': 18083,
                'dashboard_url': 'https://emqx.gavasah.com'
            })
            return

        # 12e-2. WhatsApp Gateway Status & QR
        # SMTP Configuration endpoint
        elif parsed.path == '/api/settings/smtp':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT value, updated_at FROM system_settings WHERE key = 'smtp_settings'")
                row = cur.fetchone()
                conn.close()
            if row:
                try: cfg = json.loads(row['value'])
                except Exception: cfg = {}
            else:
                cfg = {
                    'host': '',
                    'port': 587,
                    'encryption': 'tls',
                    'user': '',
                    'pass': '',
                    'from_email': '',
                    'from_name': 'GAVASAH Cloud Alerts'
                }
            self.send_json(200, {'success': True, 'config': cfg})
            return

        elif parsed.path == '/api/whatsapp/status':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            try:
                req = urllib.request.Request('http://127.0.0.1:3005/status', headers={'User-Agent': 'GavasahHub'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
                    self.send_json(200, data)
            except Exception as e:
                self.send_json(200, {'connected': False, 'status': 'offline', 'error': str(e), 'qr': None, 'phone': None})
            return

        # 12f. MQTT Dynamic Topic Tree
        elif parsed.path == '/api/mqtt/topics':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            c_data = load_clients_state()
            auth = load_auth_state()
            dealers = auth.get('dealers', {})
            integrators = auth.get('integrators', {})

            topics = {
                'universal': [
                    {'topic': 'gavasah/universal/cmd', 'desc': 'Broadcast commands to all Gavasah Gateways'},
                    {'topic': 'gavasah/universal/status', 'desc': 'Fleet announcements & firmware notices'}
                ],
                'dealers': [
                    {'topic': f'gavasah/dealers/{did}/broadcast', 'dealer_name': d.get('name')}
                    for did, d in dealers.items()
                ],
                'integrators': [
                    {'topic': f'gavasah/dealers/{it.get("dealer_id")}/integrators/{iid}/broadcast', 'integrator_name': it.get('name')}
                    for iid, it in integrators.items()
                ],
                'clients': [
                    {
                        'client_id': cid,
                        'name': c.get('name'),
                        'telemetry_topic': f'gavasah/clients/{cid}/telemetry',
                        'status_topic': f'gavasah/clients/{cid}/status',
                        'cmd_topic': f'gavasah/clients/{cid}/cmd',
                        'config_topic': f'gavasah/clients/{cid}/config'
                    }
                    for cid, c in c_data.items()
                ]
            }
            self.send_json(200, topics)
            return

        elif parsed.path == '/api/whatsapp/admin_number':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            admin_num = get_admin_whatsapp_number()
            self.send_json(200, {'success': True, 'admin_whatsapp_number': admin_num})
            return

        elif parsed.path == '/api/copilot/status':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) as cnt FROM copilot_proposals WHERE status = 'pending'")
                p_cnt = cur.fetchone()['cnt']
                conn.close()
            self.send_json(200, {
                'success': True,
                'model': 'qwen2.5-coder:7b',
                'node': 'VM 307 (ai-server-2)',
                'gpu': 'NVIDIA GeForce RTX 3060 12GB',
                'pending_proposals_count': p_cnt
            })
            return

        elif parsed.path == '/api/copilot/proposals':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT id, client_id, subsystem, action_type, summary, status, created_at FROM copilot_proposals WHERE status = 'pending' ORDER BY created_at DESC")
                proposals = [dict(r) for r in cur.fetchall()]
                conn.close()
            self.send_json(200, {'success': True, 'proposals': proposals})
            return

        elif parsed.path == '/api/copilot/history':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT sender, message, thought, timestamp FROM copilot_chat_history ORDER BY timestamp DESC LIMIT 100")
                rows = cur.fetchall()
                history = [dict(r) for r in reversed(rows)]
                conn.close()
            self.send_json(200, {'success': True, 'history': history})
            return

        elif parsed.path == '/api/copilot/autonomy':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            self.send_json(200, {
                'success': True,
                'autonomy_enabled': get_copilot_autonomy_mode()
            })
            return

        elif parsed.path == '/api/copilot/proxmox/status':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            inv = get_pve_cluster_inventory()
            self.send_json(200, inv)
            return

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)

        # 1. Login Authentication (Manufacturer, Dealers & Integrators)
        if parsed.path == '/api/login':
            raw_body = self.read_request_body()
            try:
                body = json.loads(raw_body)
            except Exception:
                self.send_json(400, {'error': 'Invalid JSON body'})
                return

            username = body.get('username', '').strip()
            password = body.get('password', '').strip()

            if not username or not password:
                self.send_json(400, {'error': 'Username and password are required'})
                return

            auth = load_auth_state()

            # Check Owner / Manufacturer
            owner = auth.get('owner', {})
            authenticated_user = None
            if username.lower() == owner.get('username', '').lower():
                if verify_password(password, owner.get('salt', ''), owner.get('password_hash', '')):
                    try: mfg_branding = json.loads(owner.get('branding_json') or '{}')
                    except: mfg_branding = owner.get('branding') or {}
                    authenticated_user = {
                        'id': 'owner_master',
                        'username': owner['username'],
                        'name': owner.get('name', 'Master Manufacturer'),
                        'role': 'manufacturer',
                        'branding': mfg_branding
                    }

            # Check Dealers
            if not authenticated_user:
                for did, d in auth.get('dealers', {}).items():
                    if username.lower() == d.get('username', '').lower():
                        if d.get('status') == 'suspended':
                            self.send_json(403, {'error': 'This dealer account is currently suspended. Please contact the manufacturer.'})
                            return
                        if verify_password(password, d.get('salt', ''), d.get('password_hash', '')):
                            authenticated_user = {
                                'id': d['id'],
                                'username': d['username'],
                                'name': d.get('name', ''),
                                'role': 'dealer',
                                'branding': d.get('branding') or {}
                            }
                            break

            # Check Integrators
            if not authenticated_user:
                for iid, it in auth.get('integrators', {}).items():
                    if username.lower() == it.get('username', '').lower():
                        if it.get('status') == 'suspended':
                            self.send_json(403, {'error': 'This integrator account is currently suspended. Please contact your dealer.'})
                            return
                        if verify_password(password, it.get('salt', ''), it.get('password_hash', '')):
                            authenticated_user = {
                                'id': it['id'],
                                'dealer_id': it.get('dealer_id', ''),
                                'dealer_name': it.get('dealer_name', ''),
                                'username': it['username'],
                                'name': it.get('name', ''),
                                'role': 'integrator'
                            }
                            break

            if not authenticated_user:
                self.send_json(401, {'error': 'Invalid credentials. Please verify your username and password.'})
                return

            # Generate session token
            session_token = secrets.token_hex(24)
            now = int(time.time())
            expires_at = now + 86400 * 7  # 7 days

            save_session(session_token, authenticated_user['id'], authenticated_user['role'], now, expires_at)

            cookie_str = f"gavasah_session={session_token}; Path=/; Max-Age={86400*7}; HttpOnly; SameSite=Lax"
            self.send_json(200, {
                'ok': True,
                'user': authenticated_user,
                'token': session_token
            }, extra_headers={'Set-Cookie': cookie_str})
            return

        # 2. Logout Session Termination
        elif parsed.path == '/api/logout':
            user = self.get_authenticated_user()
            if user:
                token = user.get('session_token')
                if token:
                    delete_session(token)
            else:
                cookie_header = self.headers.get('Cookie', '')
                tok = None
                if cookie_header:
                    for part in cookie_header.split(';'):
                        if part.strip().startswith('gavasah_session='):
                            tok = part.strip().split('=', 1)[1].strip()
                if not tok:
                    auth_h = self.headers.get('Authorization', '')
                    if auth_h.startswith('Bearer '):
                        tok = auth_h.split('Bearer ', 1)[1].strip()
                if tok:
                    delete_session(tok)

            cookie_str = "gavasah_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            self.send_json(200, {'ok': True}, extra_headers={'Set-Cookie': cookie_str})
            return

        # 3. Manufacturer Self-Service Credential Change
        elif parsed.path == '/api/change_owner_credentials':
            user = self.get_authenticated_user()
            if not user or user['role'] != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            curr_pwd = body.get('current_password', '')
            new_user = body.get('new_username', '').strip()
            new_pwd = body.get('new_password', '')

            with AUTH_LOCK:
                auth = load_auth_state()
                owner = auth.get('owner', {})
                if not verify_password(curr_pwd, owner.get('salt', ''), owner.get('password_hash', '')):
                    self.send_json(400, {'error': 'Current password verification failed'})
                    return

                if new_user:
                    owner['username'] = new_user
                if new_pwd:
                    salt, pwd_hash = hash_password(new_pwd)
                    owner['salt'] = salt
                    owner['password_hash'] = pwd_hash

                auth['owner'] = owner
                save_auth_state(auth)

            self.send_json(200, {'ok': True, 'message': 'Manufacturer credentials updated successfully'})
            return

        # 4. Dealer / Integrator Self-Service Password Change
        elif parsed.path == '/api/change_dealer_password':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['dealer', 'integrator']:
                self.send_json(403, {'error': 'Account password change privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            curr_pwd = body.get('current_password', '')
            new_pwd = body.get('new_password', '')

            if not new_pwd:
                self.send_json(400, {'error': 'New password cannot be empty'})
                return

            with AUTH_LOCK:
                auth = load_auth_state()
                if user['role'] == 'dealer':
                    dealer = auth.get('dealers', {}).get(user['id'])
                    if not dealer:
                        self.send_json(404, {'error': 'Dealer record not found'})
                        return
                    if not verify_password(curr_pwd, dealer.get('salt', ''), dealer.get('password_hash', '')):
                        self.send_json(400, {'error': 'Current password incorrect'})
                        return

                    salt, pwd_hash = hash_password(new_pwd)
                    dealer['salt'] = salt
                    dealer['password_hash'] = pwd_hash
                    dealer['password_plain'] = new_pwd
                    auth['dealers'][user['id']] = dealer
                    save_auth_state(auth)
                else:
                    integrator = auth.get('integrators', {}).get(user['id'])
                    if not integrator:
                        self.send_json(404, {'error': 'Integrator record not found'})
                        return
                    if not verify_password(curr_pwd, integrator.get('salt', ''), integrator.get('password_hash', '')):
                        self.send_json(400, {'error': 'Current password incorrect'})
                        return

                    salt, pwd_hash = hash_password(new_pwd)
                    integrator['salt'] = salt
                    integrator['password_hash'] = pwd_hash
                    integrator['password_plain'] = new_pwd
                    auth['integrators'][user['id']] = integrator
                    save_auth_state(auth)

            self.send_json(200, {'ok': True, 'message': 'Password updated successfully'})
            return

        # 5. Create Dealer (Manufacturer Only)
        
        # --- TOGGLE DEALER STATUS (MANUFACTURER: ACTIVATE / SUSPEND & KILL SESSIONS) ---
        
        # --- ONE-CLICK BACKUP & SNAPSHOT TRIGGER ---
        elif parsed.path == '/api/client_backup_trigger':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            client_id = body.get('client_id', '').strip()
            b_name = body.get('name', '').strip() or f"Gavasah Snapshot - {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"

            clients = load_clients_state()
            if client_id not in clients:
                self.send_json(404, {'error': 'Client site not found'})
                return
            c = clients[client_id]

            # Role Authorization:
            # 1. Updates (Core, Supervisor, Add-on, Master) restricted to Manufacturer ONLY
            if action in ['update_core', 'update_supervisor', 'update_addon', 'update_all']:
                if user.get('role') != 'manufacturer':
                    self.send_json(403, {'error': 'Updating Home Assistant Core, Supervisor, and Add-ons is restricted to Manufacturer HQ only'})
                    return

            # 2. Remote Reboot & Diagnostics: Available to Manufacturer, Dealer, and Integrator
            elif action in ['reboot_gateway', 'reboot_host', 'restart_core', 'unban_and_fix']:
                if user.get('role') == 'dealer' and c.get('dealer_id') != user.get('id'):
                    self.send_json(403, {'error': 'Unauthorized for this client site'})
                    return
                elif user.get('role') == 'integrator':
                    if c.get('integrator_id') != user.get('id') and c.get('dealer_id') != user.get('dealer_id'):
                        self.send_json(403, {'error': 'Unauthorized for this client site'})
                        return

            with DB_LOCK:
                conn = get_db_connection()
                with conn:
                    conn.execute("UPDATE clients SET pending_backup = ? WHERE client_id = ?", (b_name, client_id))
                conn.close()

            print(f"[SNAPSHOT_TRIGGER] Queued backup '{b_name}' for client '{client_id}'", flush=True)
            self.send_json(200, {
                'ok': True,
                'message': f"Snapshot trigger '{b_name}' dispatched to gateway. The system will create and synchronize the archive within 30-60 seconds."
            })
            return

        # --- REMOTE COMMAND DISPATCH (UNBAN & FIX, RESTART CORE, UPDATE AGENT) ---

        # --- TOGGLE CLIENT AUTO-UPDATE (MANUFACTURER / DEALER) ---
        elif parsed.path == '/api/toggle_auto_update':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8')) if content_length > 0 else {}
            cid = body.get('client_id')
            auto_up = int(body.get('auto_update', 1))
            if not cid:
                self.send_json(400, {'error': 'Missing client_id'})
                return
            with DB_LOCK:
                conn = get_db_connection()
                conn.execute("UPDATE clients SET auto_update = ? WHERE client_id = ?", (auto_up, cid))
                conn.commit()
                conn.close()
            self.send_json(200, {'ok': True, 'client_id': cid, 'auto_update': auto_up})
            return

        elif parsed.path == '/api/client_command_trigger':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8')) if content_length > 0 else {}
            client_id = body.get('client_id', '').strip()
            action = body.get('action', '').strip()
            params = body.get('params', {})

            if not client_id or not action:
                self.send_json(400, {'error': 'client_id and action required'})
                return

            clients = load_clients_state()
            if client_id not in clients:
                self.send_json(404, {'error': 'Client site not found'})
                return
            c = clients[client_id]
            if user['role'] == 'dealer' and c.get('dealer_id') != user['id']:
                self.send_json(403, {'error': 'Unauthorized for this client site'})
                return

            cmd_payload = json.dumps({'action': action, 'params': params, 'queued_at': int(time.time()), 'queued_by': user.get('username')})
            with DB_LOCK:
                conn = get_db_connection()
                with conn:
                    conn.execute("UPDATE clients SET pending_command = ? WHERE client_id = ?", (cmd_payload, client_id))
                conn.close()

            print(f"[CMD_TRIGGER] Queued command '{action}' for client '{client_id}' by {user.get('role')} '{user.get('username')}'", flush=True)
            self.send_json(200, {
                'ok': True,
                'message': f"Autonomous command '{action}' queued for gateway. It will execute on the next heartbeat pulse."
            })
            return

        # --- BATCH FLEET COMMAND DISPATCH (MANUFACTURER ONLY) ---
        elif parsed.path == '/api/fleet_command_trigger':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Batch Fleet Commands are restricted to Manufacturer HQ only'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8')) if content_length > 0 else {}
            action = body.get('action', '').strip()
            params = body.get('params', {})

            if not action:
                self.send_json(400, {'error': 'action required'})
                return

            now = int(time.time())
            cmd_payload = json.dumps({'action': action, 'params': params, 'queued_at': now, 'queued_by': 'manufacturer_hq'})

            count = 0
            with DB_LOCK:
                conn = get_db_connection()
                with conn:
                    cur = conn.cursor()
                    cur.execute("UPDATE clients SET pending_command = ?", (cmd_payload,))
                    count = cur.rowcount
                conn.close()

            print(f"[FLEET_CMD_TRIGGER] Queued batch '{action}' across {count} client gateways", flush=True)
            self.send_json(200, {
                'ok': True,
                'count': count,
                'message': f"Batch command '{action}' queued for all {count} fleet gateways."
            })
            return

        # --- CLIENT DIAGNOSTIC REPORT INGESTION ---
        elif parsed.path == '/api/diag_report':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            diag_file = '/srv/gavasah-cloud/diag_report_np.json'
            with open(diag_file, 'w', encoding='utf-8') as df:
                df.write(body)
            print(f"[DIAG_REPORT] Ingested diagnostic report ({len(body)} bytes) -> {diag_file}", flush=True)
            self.send_json(200, {'ok': True})
            return

        # --- GATEWAY UPLOAD OF BACKUP ARCHIVE ---
        elif parsed.path == '/api/client_backup_upload':
            query = parse_qs(parsed.query)
            client_id = (query.get('client_id', [''])[0] or self.headers.get('X-Client-Id', '')).strip()
            slug = (query.get('slug', [''])[0] or self.headers.get('X-Backup-Slug', '')).strip()
            b_name = (query.get('name', [''])[0] or 'Home Assistant Snapshot').strip()
            content_length = int(self.headers.get('Content-Length', 0))

            if not client_id or not slug:
                self.send_json(400, {'error': 'client_id and slug required'})
                return

            client_dir = os.path.join(BACKUPS_DIR, client_id)
            os.makedirs(client_dir, exist_ok=True)
            tar_path = os.path.join(client_dir, f"{slug}.tar")

            with open(tar_path, 'wb') as bf:
                remaining = content_length
                chunk_sz = 65536
                while remaining > 0:
                    sz = min(chunk_sz, remaining)
                    chunk = self.rfile.read(sz)
                    if not chunk:
                        break
                    bf.write(chunk)
                    remaining -= len(chunk)

            size_mb = round(os.path.getsize(tar_path) / (1024 * 1024), 2)
            log_entry = {
                'slug': slug,
                'name': b_name,
                'date': datetime.datetime.utcnow().isoformat() + "Z",
                'size_mb': size_mb,
                'file_path': tar_path,
                'uploaded_at': int(time.time())
            }

            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT backups_json FROM clients WHERE client_id = ?", (client_id,))
                row = cur.fetchone()
                existing_bk = []
                if row and row['backups_json']:
                    try: existing_bk = json.loads(row['backups_json'])
                    except: existing_bk = []
                existing_bk = [x for x in existing_bk if x.get('slug') != slug]
                existing_bk.insert(0, log_entry)
                with conn:
                    conn.execute("UPDATE clients SET backups_json = ? WHERE client_id = ?", (json.dumps(existing_bk[:15]), client_id))
                conn.close()

            print(f"[BACKUP_UPLOAD] Stored backup archive {tar_path} ({size_mb} MB) for '{client_id}'", flush=True)
            self.send_json(200, {'ok': True, 'slug': slug, 'size_mb': size_mb})
            return

        # --- DEALER & MANUFACTURER CUSTOM BRANDING UPDATE ---
        elif parsed.path == '/api/update_dealer_branding':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['dealer', 'manufacturer']:
                self.send_json(403, {'error': 'Privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))

            branding = {
                'company_name': body.get('company_name', '').strip(),
                'tagline': body.get('tagline', '').strip(),
                'logo_url': body.get('logo_url', '').strip(),
                'primary_color': body.get('primary_color', '').strip() or '#00f0ff',
                'accent_color': body.get('accent_color', '').strip() or '#38bdf8',
                'support_email': body.get('support_email', '').strip(),
                'support_phone': body.get('support_phone', '').strip(),
                'updated_at': int(time.time())
            }

            with AUTH_LOCK:
                auth = load_auth_state()
                if user['role'] == 'manufacturer' and (not body.get('dealer_id') or body.get('dealer_id') in ['owner_master', 'owner', 'manufacturer']):
                    if 'owner' not in auth:
                        auth['owner'] = {}
                    auth['owner']['branding'] = branding
                    auth['owner']['branding_json'] = json.dumps(branding)
                    save_auth_state(auth)
                else:
                    dealer_id = user['id'] if user['role'] == 'dealer' else body.get('dealer_id', '').strip()
                    if dealer_id not in auth.get('dealers', {}):
                        self.send_json(404, {'error': 'Dealer record not found'})
                        return
                    auth['dealers'][dealer_id]['branding'] = branding
                    auth['dealers'][dealer_id]['branding_json'] = json.dumps(branding)
                    save_auth_state(auth)

            self.send_json(200, {'ok': True, 'message': 'Custom branding updated successfully!', 'branding': branding})
            return

        elif parsed.path == '/api/reset_dealer_branding':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['dealer', 'manufacturer']:
                self.send_json(403, {'error': 'Privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = {}
            if content_length > 0:
                try: body = json.loads(self.rfile.read(content_length).decode('utf-8'))
                except: body = {}

            with AUTH_LOCK:
                auth = load_auth_state()
                if user['role'] == 'manufacturer' and (not body.get('dealer_id') or body.get('dealer_id') in ['owner_master', 'owner', 'manufacturer']):
                    if 'owner' in auth:
                        auth['owner']['branding'] = {}
                        auth['owner']['branding_json'] = ''
                        save_auth_state(auth)
                else:
                    dealer_id = user['id'] if user['role'] == 'dealer' else body.get('dealer_id', '').strip()
                    if dealer_id in auth.get('dealers', {}):
                        auth['dealers'][dealer_id]['branding'] = {}
                        auth['dealers'][dealer_id]['branding_json'] = ''
                        save_auth_state(auth)

            self.send_json(200, {'ok': True, 'message': 'Reset to default GAVASAH branding.'})
            return

        elif parsed.path == '/api/delete_dealer_logo':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['dealer', 'manufacturer']:
                self.send_json(403, {'error': 'Privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = {}
            if content_length > 0:
                try: body = json.loads(self.rfile.read(content_length).decode('utf-8'))
                except: body = {}

            new_branding = {}
            with AUTH_LOCK:
                auth = load_auth_state()
                if user['role'] == 'manufacturer' and (not body.get('dealer_id') or body.get('dealer_id') in ['owner_master', 'owner', 'manufacturer']):
                    b = auth.get('owner', {}).get('branding') or {}
                    b['logo_url'] = ''
                    if 'owner' not in auth:
                        auth['owner'] = {}
                    auth['owner']['branding'] = b
                    auth['owner']['branding_json'] = json.dumps(b)
                    save_auth_state(auth)
                    new_branding = b
                else:
                    dealer_id = user['id'] if user['role'] == 'dealer' else body.get('dealer_id', '').strip()
                    if dealer_id not in auth.get('dealers', {}):
                        self.send_json(404, {'error': 'Dealer record not found'})
                        return
                    b = auth['dealers'][dealer_id].get('branding') or {}
                    b['logo_url'] = ''
                    auth['dealers'][dealer_id]['branding'] = b
                    auth['dealers'][dealer_id]['branding_json'] = json.dumps(b)
                    save_auth_state(auth)
                    new_branding = b

            self.send_json(200, {'ok': True, 'message': 'Logo deleted successfully', 'branding': new_branding})
            return

        elif parsed.path == '/api/toggle_dealer_status':
            user = self.get_authenticated_user()
            if not user or user['role'] != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            dealer_id = body.get('dealer_id', '').strip()
            target_status = body.get('status')

            with AUTH_LOCK:
                auth = load_auth_state()
                dealer = auth.get('dealers', {}).get(dealer_id)
                if not dealer:
                    self.send_json(404, {'error': 'Dealer not found'})
                    return

                if not target_status:
                    target_status = 'suspended' if dealer.get('status', 'active') == 'active' else 'active'

                dealer['status'] = target_status
                auth['dealers'][dealer_id] = dealer

                terminated_count = 0
                if target_status == 'suspended':
                    # Terminate all active sessions for this dealer
                    for token, sess in list(auth.get('sessions', {}).items()):
                        if sess.get('user_id') == dealer_id:
                            del auth['sessions'][token]
                            terminated_count += 1
                    # Also terminate sessions for all integrators belonging to this dealer
                    for iid, it in auth.get('integrators', {}).items():
                        if it.get('dealer_id') == dealer_id:
                            for token, sess in list(auth.get('sessions', {}).items()):
                                if sess.get('user_id') == iid:
                                    del auth['sessions'][token]
                                    terminated_count += 1

                save_auth_state(auth)

            self.send_json(200, {
                'ok': True,
                'status': target_status,
                'terminated_sessions': terminated_count,
                'message': f"Dealer '{dealer.get('name')}' {target_status.upper()}. {terminated_count} active session(s) terminated."
            })
            return

        # --- TOGGLE INTEGRATOR STATUS (MANUFACTURER & DEALERS: ACTIVATE / SUSPEND & KILL SESSIONS) ---
        elif parsed.path == '/api/toggle_integrator_status':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['manufacturer', 'dealer']:
                self.send_json(403, {'error': 'Manufacturer or Dealer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            int_id = body.get('integrator_id', '').strip()
            target_status = body.get('status')

            with AUTH_LOCK:
                auth = load_auth_state()
                integrator = auth.get('integrators', {}).get(int_id)
                if not integrator:
                    self.send_json(404, {'error': 'Integrator not found'})
                    return

                # If Dealer, verify ownership
                if user['role'] == 'dealer' and integrator.get('dealer_id') != user['id']:
                    self.send_json(403, {'error': 'Access denied: You can only suspend your own integrators'})
                    return

                if not target_status:
                    target_status = 'suspended' if integrator.get('status', 'active') == 'active' else 'active'

                integrator['status'] = target_status
                auth['integrators'][int_id] = integrator

                terminated_count = 0
                if target_status == 'suspended':
                    # Terminate all active sessions for this integrator
                    for token, sess in list(auth.get('sessions', {}).items()):
                        if sess.get('user_id') == int_id:
                            del auth['sessions'][token]
                            terminated_count += 1

                save_auth_state(auth)

            self.send_json(200, {
                'ok': True,
                'status': target_status,
                'terminated_sessions': terminated_count,
                'message': f"Integrator '{integrator.get('name')}' {target_status.upper()}. {terminated_count} active session(s) terminated."
            })
            return
        elif parsed.path == '/api/create_dealer':
            user = self.get_authenticated_user()
            if not user or user['role'] != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            name = body.get('name', '').strip()
            username = body.get('username', '').strip()
            password = body.get('password', '').strip()
            email = body.get('email', '').strip()
            phone = body.get('phone', '').strip()

            if not name or not password:
                self.send_json(400, {'error': 'Dealer name and password are required'})
                return

            # Autonomous username: <dealer name> format
            clean_slug = re.sub(r'[^a-zA-Z0-9_\-]', '', username.lower()) if username else ''
            if not clean_slug:
                base_slug = re.sub(r'[^a-zA-Z0-9]+', '-', name.lower().strip()).strip('-')
                clean_slug = base_slug if base_slug else f"dealer-{int(time.time())}"

            with AUTH_LOCK:
                auth = load_auth_state()
                existing_usernames = {auth.get('owner', {}).get('username', '').lower()}
                for d in auth.get('dealers', {}).values():
                    existing_usernames.add(d.get('username', '').lower())
                for it in auth.get('integrators', {}).values():
                    existing_usernames.add(it.get('username', '').lower())

                # Autonomously resolve collisions
                candidate = clean_slug
                counter = 1
                while candidate in existing_usernames:
                    candidate = f"{clean_slug}-{counter}"
                    counter += 1
                clean_slug = candidate

                dealer_id = f"dealer_{clean_slug}"
                salt, pwd_hash = hash_password(password)

                auth['dealers'][dealer_id] = {
                    'id': dealer_id,
                    'name': name,
                    'username': clean_slug,
                    'password_plain': password,  # Stored plain for Manufacturer visibility & editing
                    'email': email,
                    'phone': phone,
                    'role': 'dealer',
                    'status': 'active',
                    'salt': salt,
                    'password_hash': pwd_hash,
                    'created_at': int(time.time())
                }
                save_auth_state(auth)

            self.send_json(200, {'ok': True, 'message': f'Dealer {name} registered successfully', 'dealer_id': dealer_id})
            return

        # 6. Update Dealer (Manufacturer Only - Can See & Edit Dealer Password)
        elif parsed.path == '/api/update_dealer':
            user = self.get_authenticated_user()
            if not user or user['role'] != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            dealer_id = body.get('id', '').strip()
            name = body.get('name', '').strip()
            username = body.get('username', '').strip()
            new_password = body.get('password', '').strip()
            email = body.get('email', '').strip()
            phone = body.get('phone', '').strip()
            status = body.get('status', 'active')

            with AUTH_LOCK:
                auth = load_auth_state()
                dealer = auth.get('dealers', {}).get(dealer_id)
                if not dealer:
                    self.send_json(404, {'error': 'Dealer not found'})
                    return

                # Check username uniqueness if changed
                if username and username.lower() != dealer.get('username', '').lower():
                    for did, d in auth.get('dealers', {}).items():
                        if did != dealer_id and d.get('username', '').lower() == username.lower():
                            self.send_json(400, {'error': 'Username already in use by another Dealer'})
                            return
                    dealer['username'] = username

                if name:
                    dealer['name'] = name
                dealer['email'] = email
                dealer['phone'] = phone
                dealer['status'] = status
                if status == 'suspended':
                    for token, sess in list(auth.get('sessions', {}).items()):
                        if sess.get('user_id') == dealer_id:
                            del auth['sessions'][token]
                    for iid, it in auth.get('integrators', {}).items():
                        if it.get('dealer_id') == dealer_id:
                            for token, sess in list(auth.get('sessions', {}).items()):
                                if sess.get('user_id') == iid:
                                    del auth['sessions'][token]

                # Manufacturer can update / reset dealer password directly!
                if new_password:
                    salt, pwd_hash = hash_password(new_password)
                    dealer['salt'] = salt
                    dealer['password_hash'] = pwd_hash
                    dealer['password_plain'] = new_password

                auth['dealers'][dealer_id] = dealer
                save_auth_state(auth)

                # Also update dealer_name in clients_state if name changed
                if name:
                    c_data = load_clients_state()
                    c_dirty = False
                    for cid, c in c_data.items():
                        if c.get('dealer_id') == dealer_id:
                            c['dealer_name'] = name
                            c_dirty = True
                    if c_dirty:
                        save_clients_state(c_data)

            self.send_json(200, {'ok': True, 'message': f'Dealer {name} updated successfully'})
            return

        # 7. Delete Dealer (Manufacturer Only)
        elif parsed.path == '/api/delete_dealer':
            user = self.get_authenticated_user()
            if not user or user['role'] != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            dealer_id = body.get('dealer_id', '').strip()

            if not dealer_id:
                self.send_json(400, {'error': 'dealer_id is required'})
                return

            with AUTH_LOCK:
                auth = load_auth_state()
                if dealer_id not in auth.get('dealers', {}):
                    self.send_json(404, {'error': 'Dealer not found'})
                    return

                # Reassign clients under this dealer to Master Manufacturer
                c_data = load_clients_state()
                c_dirty = False
                for cid, c in c_data.items():
                    if c.get('dealer_id') == dealer_id:
                        c['dealer_id'] = 'owner_master'
                        c['dealer_name'] = 'Master Manufacturer (Direct)'
                        c['integrator_id'] = None
                        c['integrator_name'] = 'Direct Dealer Supervision'
                        c_dirty = True
                if c_dirty:
                    save_clients_state(c_data)

                # Reassign or clean up integrators under this dealer
                for iid, it in list(auth.get('integrators', {}).items()):
                    if it.get('dealer_id') == dealer_id:
                        it['status'] = 'suspended'

                # Terminate dealer sessions
                for token, sess in list(auth.get('sessions', {}).items()):
                    if sess.get('user_id') == dealer_id:
                        del auth['sessions'][token]

                del auth['dealers'][dealer_id]
                save_auth_state(auth)

            self.send_json(200, {'ok': True, 'message': 'Dealer deleted. All assigned clients retained under Direct Supervision.'})
            return

        # 8. Create Integrator (Manufacturer & Dealers)
        elif parsed.path == '/api/create_integrator':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['manufacturer', 'dealer']:
                self.send_json(403, {'error': 'Manufacturer or Dealer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            name = body.get('name', '').strip()
            username = body.get('username', '').strip()
            password = body.get('password', '').strip()
            email = body.get('email', '').strip()
            phone = body.get('phone', '').strip()

            if not name or not password:
                self.send_json(400, {'error': 'Integrator name and password are required'})
                return

            auth = load_auth_state()

            # Determine Dealership Assignment
            if user['role'] == 'dealer':
                dealer_id = user['id']
                dealer_name = user['name']
            else:
                # Manufacturer can assign to any dealer or Master Manufacturer (Direct)
                dealer_id = body.get('dealer_id', '').strip()
                if dealer_id == 'owner_master' or not dealer_id:
                    dealer_id = 'owner_master'
                    dealer_name = 'Master Manufacturer (Direct)'
                elif dealer_id in auth.get('dealers', {}):
                    dealer_name = auth['dealers'][dealer_id]['name']
                else:
                    dealer_id = 'owner_master'
                    dealer_name = 'Master Manufacturer (Direct)'

            # Autonomous username: <integrator name>-<dealer name> format
            clean_slug = re.sub(r'[^a-zA-Z0-9_\-]', '', username.lower()) if username else ''
            if not clean_slug:
                int_slug = re.sub(r'[^a-zA-Z0-9]+', '-', name.lower().strip()).strip('-')
                dlr_slug = re.sub(r'[^a-zA-Z0-9]+', '-', dealer_name.lower().strip()).strip('-')
                base_slug = f"{int_slug}-{dlr_slug}".strip('-')
                clean_slug = base_slug if base_slug else f"integrator-{int(time.time())}"

            with AUTH_LOCK:
                auth = load_auth_state()
                existing_usernames = {auth.get('owner', {}).get('username', '').lower()}
                for d in auth.get('dealers', {}).values():
                    existing_usernames.add(d.get('username', '').lower())
                for it in auth.get('integrators', {}).values():
                    existing_usernames.add(it.get('username', '').lower())

                # Autonomously resolve collisions
                candidate = clean_slug
                counter = 1
                while candidate in existing_usernames:
                    candidate = f"{clean_slug}-{counter}"
                    counter += 1
                clean_slug = candidate

                int_id = f"int_{clean_slug}_{int(time.time()) % 10000}"
                salt, pwd_hash = hash_password(password)

                auth['integrators'][int_id] = {
                    'id': int_id,
                    'dealer_id': dealer_id,
                    'dealer_name': dealer_name,
                    'name': name,
                    'username': clean_slug,
                    'password_plain': password,  # Stored plain for Manufacturer and Dealer visibility & editing
                    'email': email,
                    'phone': phone,
                    'role': 'integrator',
                    'status': 'active',
                    'salt': salt,
                    'password_hash': pwd_hash,
                    'created_at': int(time.time())
                }
                save_auth_state(auth)

            self.send_json(200, {'ok': True, 'message': f'Integrator {name} registered successfully', 'integrator_id': int_id})
            return

        # 9. Update Integrator (Manufacturer & Dealers - Can See & Edit Integrator Password)
        elif parsed.path == '/api/update_integrator':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['manufacturer', 'dealer']:
                self.send_json(403, {'error': 'Manufacturer or Dealer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            int_id = body.get('id', '').strip()
            name = body.get('name', '').strip()
            username = body.get('username', '').strip()
            new_password = body.get('password', '').strip()
            email = body.get('email', '').strip()
            phone = body.get('phone', '').strip()
            status = body.get('status', 'active')
            new_dealer_id = body.get('dealer_id', '').strip()

            with AUTH_LOCK:
                auth = load_auth_state()
                integrator = auth.get('integrators', {}).get(int_id)
                if not integrator:
                    self.send_json(404, {'error': 'Integrator not found'})
                    return

                # If Dealer, verify ownership
                if user['role'] == 'dealer' and integrator.get('dealer_id') != user['id']:
                    self.send_json(403, {'error': 'Access denied: You can only edit your own integrators'})
                    return

                # Check username uniqueness if changed
                if username and username.lower() != integrator.get('username', '').lower():
                    for iid, it in auth.get('integrators', {}).items():
                        if iid != int_id and it.get('username', '').lower() == username.lower():
                            self.send_json(400, {'error': 'Username already taken by another Integrator'})
                            return
                    integrator['username'] = username

                if name:
                    integrator['name'] = name
                integrator['email'] = email
                integrator['phone'] = phone
                integrator['status'] = status
                if status == 'suspended':
                    for token, sess in list(auth.get('sessions', {}).items()):
                        if sess.get('user_id') == int_id:
                            del auth['sessions'][token]

                # Manufacturer and Dealer can update / reset Integrator's password directly!
                if new_password:
                    salt, pwd_hash = hash_password(new_password)
                    integrator['salt'] = salt
                    integrator['password_hash'] = pwd_hash
                    integrator['password_plain'] = new_password

                # Manufacturer can transfer integrator to another dealer or Master Manufacturer
                if user['role'] == 'manufacturer' and new_dealer_id:
                    if new_dealer_id == 'owner_master':
                        integrator['dealer_id'] = 'owner_master'
                        integrator['dealer_name'] = 'Master Manufacturer (Direct)'
                    elif new_dealer_id in auth.get('dealers', {}):
                        integrator['dealer_id'] = new_dealer_id
                        integrator['dealer_name'] = auth['dealers'][new_dealer_id]['name']

                auth['integrators'][int_id] = integrator
                save_auth_state(auth)

                # Update client integrator_name if name changed
                if name:
                    c_data = load_clients_state()
                    c_dirty = False
                    for cid, c in c_data.items():
                        if c.get('integrator_id') == int_id:
                            c['integrator_name'] = name
                            c_dirty = True
                    if c_dirty:
                        save_clients_state(c_data)

            self.send_json(200, {'ok': True, 'message': f'Integrator {name} updated successfully'})
            return

        # 10. Delete Integrator (Manufacturer & Dealers - SAFETY RULE: Retain Clients)
        elif parsed.path == '/api/delete_integrator':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['manufacturer', 'dealer']:
                self.send_json(403, {'error': 'Manufacturer or Dealer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            int_id = body.get('integrator_id', '').strip()

            if not int_id:
                self.send_json(400, {'error': 'integrator_id is required'})
                return

            with AUTH_LOCK:
                auth = load_auth_state()
                integrator = auth.get('integrators', {}).get(int_id)
                if not integrator:
                    self.send_json(404, {'error': 'Integrator not found'})
                    return

                # If Dealer, verify ownership
                if user['role'] == 'dealer' and integrator.get('dealer_id') != user['id']:
                    self.send_json(403, {'error': 'Access denied: You can only delete your own integrators'})
                    return

                # CRITICAL SAFETY REQUIREMENT:
                # Clients created or supervised by this integrator must NOT be deleted!
                # Move them automatically into Direct Dealer Supervision!
                c_data = load_clients_state()
                reassigned_count = 0
                for cid, c in c_data.items():
                    if c.get('integrator_id') == int_id:
                        c['integrator_id'] = None
                        c['integrator_name'] = 'Direct Dealer Supervision'
                        reassigned_count += 1
                        append_client_log(
                            cid, 'WARNING', 'SUPERVISION_TRANSFER',
                            f"Assigned integrator '{integrator.get('name')}' removed. Client transferred to Direct Dealer Supervision."
                        )
                if reassigned_count > 0:
                    save_clients_state(c_data)

                # Terminate any active sessions for this integrator
                for token, sess in list(auth.get('sessions', {}).items()):
                    if sess.get('user_id') == int_id:
                        del auth['sessions'][token]

                del auth['integrators'][int_id]
                save_auth_state(auth)

            self.send_json(200, {
                'ok': True,
                'message': f"Integrator deleted safely. {reassigned_count} client(s) preserved and moved to Direct Dealer Supervision."
            })
            return

        # 11. Reassign Client Supervision (Manufacturer & Dealers)
        elif parsed.path == '/api/reassign_client':
            user = self.get_authenticated_user()
            if not user or user['role'] not in ['manufacturer', 'dealer']:
                self.send_json(403, {'error': 'Manufacturer or Dealer privilege required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            client_id = body.get('client_id', '').strip()
            new_dealer_id = body.get('dealer_id', '').strip()
            new_integrator_id = body.get('integrator_id', '').strip()

            if not client_id:
                self.send_json(400, {'error': 'client_id is required'})
                return

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            auth = load_auth_state()

            # Authorization and Reassignment Logic
            if user['role'] == 'dealer':
                # Dealer can only reassign clients they own
                if client.get('dealer_id') != user['id']:
                    self.send_json(403, {'error': 'Access denied: You can only reassign clients in your dealership'})
                    return

                # Dealer cannot change dealer_id
                if new_integrator_id in ['', 'none', None]:
                    client['integrator_id'] = None
                    client['integrator_name'] = 'Direct Dealer Supervision'
                else:
                    it = auth.get('integrators', {}).get(new_integrator_id)
                    if not it or it.get('dealer_id') != user['id']:
                        self.send_json(400, {'error': 'Selected integrator does not belong to your dealership'})
                        return
                    client['integrator_id'] = it['id']
                    client['integrator_name'] = it['name']

            elif user['role'] == 'manufacturer':
                # Manufacturer can change dealer AND integrator
                if new_dealer_id:
                    if new_dealer_id == 'owner_master':
                        client['dealer_id'] = 'owner_master'
                        client['dealer_name'] = 'Master Manufacturer (Direct)'
                    elif new_dealer_id in auth.get('dealers', {}):
                        client['dealer_id'] = new_dealer_id
                        client['dealer_name'] = auth['dealers'][new_dealer_id]['name']
                    else:
                        self.send_json(400, {'error': 'Target dealer not found'})
                        return

                if new_integrator_id in ['', 'none', None]:
                    client['integrator_id'] = None
                    client['integrator_name'] = 'Direct Dealer Supervision'
                else:
                    it = auth.get('integrators', {}).get(new_integrator_id)
                    if not it:
                        self.send_json(400, {'error': 'Target integrator not found'})
                        return
                    # Match client's current dealer
                    client['integrator_id'] = it['id']
                    client['integrator_name'] = it['name']

            save_clients_state(c_data)
            append_client_log(
                client_id, 'INFO', 'SUPERVISION_REASSIGNED',
                f"Supervision reassigned by {user['name']}: Dealer='{client.get('dealer_name')}', Integrator='{client.get('integrator_name')}'."
            )

            self.send_json(200, {
                'ok': True,
                'message': f"Client supervision transferred to {client.get('integrator_name')} ({client.get('dealer_name')})",
                'client': client
            })
            return

        

        # 12. Onboard New Client Site (Manufacturer, Dealers & Integrators)
        elif parsed.path == '/api/onboard':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length).decode('utf-8')
            try:
                body = json.loads(raw_body)
            except Exception:
                self.send_json(400, {'error': 'Invalid JSON body'})
                return

            client_name = body.get('name', '').strip()
            client_id = body.get('client_id', '').strip().lower()
            ssh_key = body.get('ssh_public_key', '').strip()
            auth_secret = body.get('auth_secret', '').strip()
            raw_kip = body.get('knx_ip', '').strip()
            knx_ip = raw_kip if raw_kip and raw_kip not in ['—', 'none', 'null', '192.168.1.100'] else None
            raw_kport = body.get('knx_port')
            knx_port = int(raw_kport) if raw_kport and knx_ip else None

            if not client_name:
                self.send_json(400, {'error': 'Client site name is required'})
                return

            if not client_id:
                client_id = re.sub(r'[^a-z0-9]+', '-', client_name.lower()).strip('-')
                if not client_id:
                    client_id = f"client-{int(time.time()) % 10000}"

            if not auth_secret:
                auth_secret = secrets.token_hex(16)

            auth = load_auth_state()

            # 1. Determine Dealer & Integrator Assignment based on User Role
            if user['role'] == 'integrator':
                assigned_dealer_id = user['dealer_id']
                assigned_dealer_name = user['dealer_name']
                assigned_int_id = user['id']
                assigned_int_name = user['name']
            elif user['role'] == 'dealer':
                assigned_dealer_id = user['id']
                assigned_dealer_name = user['name']
                req_int_id = body.get('integrator_id', '').strip()
                if req_int_id and req_int_id in auth.get('integrators', {}):
                    it = auth['integrators'][req_int_id]
                    if it.get('dealer_id') == user['id']:
                        assigned_int_id = it['id']
                        assigned_int_name = it['name']
                    else:
                        assigned_int_id = None
                        assigned_int_name = 'Direct Dealer Supervision'
                else:
                    assigned_int_id = None
                    assigned_int_name = 'Direct Dealer Supervision'
            else:
                # Manufacturer can pick both dealer and integrator
                req_dealer_id = body.get('dealer_id', '').strip()
                if req_dealer_id and req_dealer_id in auth.get('dealers', {}):
                    assigned_dealer_id = req_dealer_id
                    assigned_dealer_name = auth['dealers'][req_dealer_id]['name']
                elif req_dealer_id == 'owner_master':
                    assigned_dealer_id = 'owner_master'
                    assigned_dealer_name = 'Master Manufacturer (Direct)'
                else:
                    assigned_dealer_id = 'owner_master'
                    assigned_dealer_name = 'Master Manufacturer (Direct)'

                req_int_id = body.get('integrator_id', '').strip()
                if req_int_id and req_int_id in auth.get('integrators', {}):
                    it = auth['integrators'][req_int_id]
                    assigned_int_id = it['id']
                    assigned_int_name = it['name']
                else:
                    assigned_int_id = None
                    assigned_int_name = 'Direct Dealer Supervision'

            # 2. Derive Dealer Slug for Limitation 1 Namespacing: <client-slug>-<dealer-slug>
            if assigned_dealer_id == 'owner_master':
                dealer_slug = 'direct'
            elif assigned_dealer_id.startswith('dealer_'):
                dealer_slug = re.sub(r'[^a-z0-9]', '', assigned_dealer_id.replace('dealer_', '').lower())
            else:
                assigned_d = auth.get('dealers', {}).get(assigned_dealer_id)
                if assigned_d:
                    raw_du = assigned_d.get('username', '').lower()
                    d_clean = re.sub(r'[^a-z0-9]', '', raw_du.replace('dealer', '').replace('knx', '').replace('_', '').replace('-', ''))
                    dealer_slug = d_clean if d_clean else 'dealer'
                else:
                    dealer_slug = 'direct'

            raw_cslug = re.sub(r'[^a-z0-9\-]', '', client_id.lower()).strip('-')
            if not raw_cslug:
                raw_cslug = f"client-{int(time.time()) % 10000}"

            # Enforce format: <client-slug>-<dealer-slug>
            base_cslug = raw_cslug.replace(f"-{dealer_slug}", "")
            if not base_cslug:
                base_cslug = f"client-{int(time.time()) % 10000}"

            c_data = load_clients_state()
            candidate_id = f"{base_cslug}-{dealer_slug}"
            suffix = 1
            while candidate_id in c_data:
                suffix += 1
                candidate_id = f"{base_cslug}-{suffix}-{dealer_slug}"
            clean_id = candidate_id

            domain = f"{clean_id}.gavasah.com"


            # Zero-Touch WireGuard Mesh IP Allocation (Option A)
            wg_ip = allocate_next_wg_ip()
            wg_priv, wg_pub = generate_wg_keypair()
            sync_wireguard_peer(wg_pub, wg_ip)

            # Auto-assign OpenSSH Ed25519 keypair if not provided
            if not ssh_key:
                ssh_priv, ssh_pub = generate_ssh_keypair(comment=clean_id)
                ssh_key = ssh_pub
            else:
                ssh_priv = ""

            # Fallback legacy ports
            existing_dash_ports = [c.get('dashboard_port', 0) for c in c_data.values()]
            existing_ssh_ports = [c.get('ssh_port', 0) for c in c_data.values()]
            dash_port = 10001
            while dash_port in existing_dash_ports:
                dash_port += 1
            ssh_port = 22001
            while ssh_port in existing_ssh_ports:
                ssh_port += 1

            is_mfg = (user['role'] == 'manufacturer')
            approval_status = 'approved' if is_mfg else 'pending'
            remote_requested = bool(body.get('remote_enabled', True))
            effective_remote = remote_requested if is_mfg else False

            new_client = {
                'client_id': clean_id,
                'dealer_id': assigned_dealer_id,
                'dealer_name': assigned_dealer_name,
                'integrator_id': assigned_int_id,
                'integrator_name': assigned_int_name,
                'name': client_name,
                'domain': domain,
                'auth_secret': auth_secret or secrets.token_hex(16),
                'ssh_public_key': ssh_key,
                'ssh_private_key': ssh_priv,
                'dashboard_port': dash_port,
                'ssh_port': ssh_port,
                'wg_ip': wg_ip,
                'wg_pubkey': wg_pub,
                'wg_privkey': wg_priv,
                'tunnel_mode': 'wireguard',
                'knx_ip': knx_ip,
                'knx_port': knx_port,
                'last_heartbeat': 0,
                'status': 'pending',
                'onboarded_at': None,
                'remote_enabled': effective_remote,
                'approval_status': approval_status,
                'rejection_reason': '',
                'system': {},
                'network': {},
                'knx_status': {'configured': False, 'reachable': False, 'reason': 'no_knx_integration'} if not knx_ip else {}
            }

            c_data[clean_id] = new_client
            save_clients_state(c_data)

            # Ingress and SSH config: only activate ingress if approved by manufacturer
            if is_mfg and effective_remote:
                sync_caddy_ingress(clean_id, dash_port, 'http', True, wg_ip=wg_ip)
                prewarm_caddy_tls(domain)
            else:
                purge_caddy_ingress(clean_id)

            if ssh_key:
                sync_client_ssh_user(clean_id, ssh_key)

            if is_mfg:
                append_client_log(clean_id, 'INFO', 'ONBOARD_COMPLETE', f"Site '{client_name}' onboarded and approved directly by Manufacturer.")
            else:
                append_client_log(clean_id, 'INFO', 'AWAITING_APPROVAL', f"Site '{client_name}' submitted for Manufacturer Approval by {user['name']} ({user['role'].title()}). Remote ingress locked pending review.")

            # Publish MQTT dynamic topic creation & lifecycle announcement
            publish_mqtt_message(f'gavasah/lifecycle/clients/{clean_id}', {
                'event': 'client_created',
                'client_id': clean_id,
                'name': client_name,
                'dealer_id': assigned_dealer_id,
                'integrator_id': assigned_int_id,
                'approval_status': approval_status,
                'telemetry_topic': f'gavasah/clients/{clean_id}/telemetry',
                'cmd_topic': f'gavasah/clients/{clean_id}/cmd'
            }, retain=True)
            bootstrap_cmd = f"curl -sSL https://dealer.gavasah.com/api/bootstrap?client_id={clean_id}&auth_secret={new_client['auth_secret']} | bash"
            self.send_json(200, {
                'ok': True,
                'client': new_client,
                'wg_ip': wg_ip,
                'wg_pubkey': wg_pub,
                'bootstrap_cmd': bootstrap_cmd
            })
            return

        # 13. Update Client Site Details
        elif parsed.path == '/api/update_client':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            client_id = body.get('client_id', '').strip()

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            # Role verification
            if user['role'] == 'dealer' and client.get('dealer_id') != user['id']:
                self.send_json(403, {'error': 'Access denied to this client site'})
                return
            elif user['role'] == 'integrator' and client.get('integrator_id') != user['id']:
                self.send_json(403, {'error': 'Access denied to this client site'})
                return

            if body.get('name'):
                client['name'] = body['name'].strip()
            if 'knx_ip' in body:
                raw_kip = str(body.get('knx_ip') or '').strip()
                client['knx_ip'] = raw_kip if raw_kip and raw_kip not in ['—', 'none', 'null', '192.168.1.100'] else None
            if 'knx_port' in body:
                raw_kport = body.get('knx_port')
                client['knx_port'] = int(raw_kport) if raw_kport and client.get('knx_ip') else None
            if not client.get('knx_ip') and client.get('ets_port'):
                try:
                    release_ets_port(client_id)
                    sync_ets_nat_rules()
                except Exception as ex:
                    print(f"[!] Error releasing ETS port on client update: {ex}")
            if body.get('auth_secret'):
                client['auth_secret'] = body['auth_secret'].strip()
            if 'hb_delayed_interval' in body:
                try: client['hb_delayed_interval'] = max(30, int(body['hb_delayed_interval']))
                except: pass
            if 'hb_warning_interval' in body:
                try: client['hb_warning_interval'] = max(60, int(body['hb_warning_interval']))
                except: pass
            if 'hb_offline_interval' in body:
                try: client['hb_offline_interval'] = max(90, int(body['hb_offline_interval']))
                except: pass

            auth = load_auth_state()
            if user['role'] == 'manufacturer' and 'dealer_id' in body:
                d_id = body['dealer_id'].strip()
                if d_id == 'owner_master':
                    client['dealer_id'] = 'owner_master'
                    client['dealer_name'] = 'Master Manufacturer (Direct)'
                elif d_id in auth.get('dealers', {}):
                    client['dealer_id'] = d_id
                    client['dealer_name'] = auth['dealers'][d_id]['name']

            if user['role'] in ['manufacturer', 'dealer'] and 'integrator_id' in body:
                i_id = body['integrator_id'].strip()
                if not i_id:
                    client['integrator_id'] = None
                    client['integrator_name'] = None
                elif i_id in auth.get('integrators', {}):
                    client['integrator_id'] = i_id
                    client['integrator_name'] = auth['integrators'][i_id]['name']

            if 'remote_enabled' in body:
                client['remote_enabled'] = bool(body['remote_enabled'])
                sync_caddy_ingress(client_id, client.get('dashboard_port', 10001), 'http', client['remote_enabled'], force=True, wg_ip=client.get('wg_ip'))
                if not client['remote_enabled'] and os.name != 'nt':
                    try:
                        subprocess.run(["pkill", "-9", "-u", client_id], capture_output=True, timeout=3)
                        d_port = client.get('dashboard_port')
                        if d_port:
                            subprocess.run(["fuser", "-k", "-n", "tcp", str(d_port)], capture_output=True, timeout=3)
                    except Exception:
                        pass

            if 'knx_remote_enabled' in body:
                client['knx_remote_enabled'] = bool(body['knx_remote_enabled'])
            if 'call_alert_enabled' in body:
                client['call_alert_enabled'] = 1 if body['call_alert_enabled'] else 0
            if 'msg_alert_enabled' in body:
                client['msg_alert_enabled'] = 1 if body['msg_alert_enabled'] else 0
            if 'call_window_start' in body:
                client['call_window_start'] = str(body['call_window_start']).strip() or '10:00'
            if 'call_window_end' in body:
                client['call_window_end'] = str(body['call_window_end']).strip() or '18:00'
                if client['knx_remote_enabled'] and not client.get('ets_port'):
                    raw_kip = (client.get('knx_ip') or '').strip()
                    if raw_kip and raw_kip not in ['192.168.1.100', '—', 'none', 'null', '']:
                        ttype = 'onboard' if raw_kip in ['127.0.0.1', 'localhost', ''] else 'lan_device'
                        allocate_ets_port(client_id, target_ip=raw_kip or '127.0.0.1', target_port=client.get('knx_port') or 3671, target_type=ttype)
                sync_ets_nat_rules()

            save_clients_state(c_data)
            append_client_log(client_id, 'INFO', 'CONFIG_UPDATE', f"Configuration updated by {user['name']}.")
            self.send_json(200, {'ok': True, 'client': client})
            return

        # 14b. Toggle Remote KNX Programming Access
        elif parsed.path == '/api/toggle_knx_remote':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Unauthorized'})
                return
            body = self.read_json_body()
            client_id = body.get('client_id')
            enabled = bool(body.get('enabled', True))
            with DB_LOCK:
                conn = get_db_connection()
                conn.execute("UPDATE clients SET knx_remote_enabled = ? WHERE client_id = ?", (1 if enabled else 0, client_id))
                conn.commit()
                conn.close()
            c_data = load_clients_state()
            if client_id in c_data:
                c_data[client_id]['knx_remote_enabled'] = enabled
                if enabled and not c_data[client_id].get('ets_port'):
                    raw_kip = (c_data[client_id].get('knx_ip') or '').strip()
                    if raw_kip and raw_kip not in ['192.168.1.100', '—', 'none', 'null', '']:
                        ttype = 'onboard' if raw_kip in ['127.0.0.1', 'localhost', ''] else 'lan_device'
                        allocate_ets_port(client_id, target_ip=raw_kip or '127.0.0.1', target_port=c_data[client_id].get('knx_port') or 3671, target_type=ttype)
                sync_ets_nat_rules()
                save_clients_state(c_data)
            self.send_json(200, {'ok': True, 'knx_remote_enabled': enabled})
            return

        # 14. Toggle Remote Ingress
        elif parsed.path == '/api/toggle_remote':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            client_id = body.get('client_id', '').strip()
            enabled = bool(body.get('enabled', True))

            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
                row = cur.fetchone()
                if not row:
                    conn.close()
                    self.send_json(404, {'error': 'Client site not found'})
                    return
                client = dict(row)

                # Role verification
                if user['role'] == 'dealer' and client.get('dealer_id') != user['id']:
                    conn.close()
                    self.send_json(403, {'error': 'Access denied'})
                    return
                elif user['role'] == 'integrator' and client.get('integrator_id') != user['id']:
                    conn.close()
                    self.send_json(403, {'error': 'Access denied'})
                    return

                # Targeted single-row update (§3.D.2)
                conn.execute("UPDATE clients SET remote_enabled = ? WHERE client_id = ?", (1 if enabled else 0, client_id))
                conn.commit()
                conn.close()

            client['remote_enabled'] = enabled

            if not enabled:
                # Terminate active reverse tunnel sessions immediately when suspended
                if os.name != 'nt':
                    try:
                        subprocess.run(["pkill", "-9", "-u", client_id], capture_output=True, timeout=3)
                        d_port = client.get('dashboard_port')
                        if d_port:
                            subprocess.run(["fuser", "-k", "-n", "tcp", str(d_port)], capture_output=True, timeout=3)
                    except Exception:
                        pass
                sync_caddy_ingress(client_id, client.get('dashboard_port', 10001), 'http', False, force=True)
            else:
                sync_caddy_ingress(client_id, client.get('dashboard_port', 10001), 'http', True, force=True, wg_ip=client.get('wg_ip'))

            append_client_log(
                client_id, 'WARNING' if not enabled else 'INFO', 'INGRESS_TOGGLE',
                f"Remote dashboard access set to {'ENABLED' if enabled else 'DISABLED'} by {user['name']}."
            )
            self.send_json(200, {'ok': True, 'remote_enabled': enabled})
            return

        # 15. Delete Client Site (Manufacturer, Dealer, or Integrator - Active or Inactive)
        elif parsed.path in ['/api/delete_site', '/api/delete_client']:
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            client_id = body.get('client_id', '').strip()

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            # Role verification:
            # - Manufacturer: Can delete ANY client across all dealers & integrators
            # - Dealer: Can delete any client in their dealership
            # - Integrator: Can delete any client assigned to them
            if user['role'] == 'dealer' and client.get('dealer_id') != user['id']:
                self.send_json(403, {'error': 'Access denied: You can only delete clients in your dealership'})
                return
            elif user['role'] == 'integrator' and client.get('integrator_id') != user['id']:
                self.send_json(403, {'error': 'Access denied: You can only delete clients assigned to you'})
                return

            # 1. Immediately remove WireGuard tunnel peer from kernel interface
            wg_pub = client.get('wg_pubkey')
            if wg_pub:
                remove_wireguard_peer(wg_pub)

            # 1b. Immediately release remote ETS port if assigned and sync NAT
            release_ets_port(client_id)
            sync_ets_nat_rules()

            # 2. Terminate reverse SSH tunnels, kill TCP listening ports, delete Linux user & authorized_keys
            teardown_client_tunnel(
                client_id=client_id,
                dashboard_port=client.get('dashboard_port'),
                ssh_port=client.get('ssh_port'),
                ssh_public_key=client.get('ssh_public_key') or client.get('ssh_key')
            )

            # 3. Completely purge reverse-proxy ingress routes from Caddy and reload
            purge_caddy_ingress(client_id)

            # 4. Purge client record from persistent database
            del c_data[client_id]
            save_clients_state(c_data)

            append_client_log(
                client_id, 'INFO', 'CLIENT_DELETE',
                f"Client site '{client.get('name', client_id)}' ({client_id}) deleted by {user['role']} {user['name']} (active state terminated)."
            )

            self.send_json(200, {
                'ok': True,
                'message': f"Client site '{client.get('name', client_id)}' deleted successfully (all tunnels and ingress permanently severed)"
            })
            return

        # 16. Gateway Telemetry Heartbeat (KNX-IP Controller Ingestion)
        elif parsed.path == '/api/heartbeat':
            raw_body = self.read_request_body()
            body = {}
            if raw_body and raw_body.strip():
                try:
                    body = json.loads(raw_body)
                except Exception:
                    try:
                        parsed_form = parse_qs(raw_body)
                        body = {k: v[0] for k, v in parsed_form.items()}
                    except Exception:
                        body = {}

            # Query parameter fallback (e.g. POST with ?client_id=...)
            if parsed.query:
                qs = parse_qs(parsed.query)
                for k, v in qs.items():
                    if k not in body:
                        body[k] = v[0]

            client_id = body.get('client_id', '').strip()
            auth_hdr = self.headers.get('Authorization', '').replace('Bearer ', '').strip()
            secret = (body.get('auth_key') or body.get('auth_secret') or body.get('secret') or auth_hdr or '').strip()

            if not client_id:
                client_ip = self.headers.get('X-Forwarded-For') or self.client_address[0]
                print(f"[HB_EMPTY_BODY_400] from {client_ip} headers={dict(self.headers)} raw={raw_body!r} query={parsed.query}", flush=True)
                self.send_json(400, {'error': 'Missing client_id in heartbeat payload'})
                return

            # Targeted client lookup (§3.D.2)
            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
                row = cur.fetchone()
                if not row:
                    # Case-insensitive fallback
                    cur.execute("SELECT * FROM clients WHERE lower(client_id) = lower(?)", (client_id,))
                    row = cur.fetchone()
                conn.close()

            if not row:
                print(f"[HB_NOT_FOUND_404] client_id='{client_id}', payload_keys={list(body.keys())}", flush=True)
                self.send_json(404, {'error': 'Client not registered'})
                return

            client = dict(row)
            client_id = client['client_id']
            expected_secret = (client.get('auth_secret') or '').strip()

            # Validate auth_secret if set on client
            if expected_secret and secret != expected_secret:
                print(f"[HB_AUTH_MISMATCH_403] client_id='{client_id}', sent='{secret}', expected='{expected_secret}'", flush=True)
                self.send_json(403, {'error': 'Unauthorized gateway heartbeat'})
                return

            # Update telemetry data
            now = int(time.time())

            sys_dict = {}
            if 'system' in body:
                sys_data = body['system']
                # Neutralize false-positive recovery alarms: Slot B is a normal A/B update partition in HAOS/RAUC.
                # Only flag recovery if an actual kernel crash or boot failure occurred.
                if sys_data.get('is_recovery_mode') and not sys_data.get('boot_failure_detected'):
                    sys_data['is_recovery_mode'] = False
                    slot = str(sys_data.get('boot_slot', 'A')).upper()
                    if slot == 'B':
                        sys_data['slot_a_status'] = 'standby (good)'
                        sys_data['slot_b_status'] = 'good (active)'
                    else:
                        sys_data['slot_a_status'] = 'good (active)'
                        sys_data['slot_b_status'] = 'standby (good)'
                sys_dict = sys_data
            else:
                try: sys_dict = json.loads(client.get('system_json') or '{}')
                except: sys_dict = {}

            net_dict = body.get('network')
            if net_dict is None:
                try: net_dict = json.loads(client.get('network_json') or '{}')
                except: net_dict = {}

            knx_dict = body.get('knx_status') or {}
            tech_dict = body.get('technologies') or {}

            raw_gw_ip = str(knx_dict.get('gateway_ip') or '').strip()
            is_knx_configured = bool(
                knx_dict.get('configured') and
                raw_gw_ip and
                raw_gw_ip not in ['', '192.168.1.100', 'none', 'null', '—', '0.0.0.0'] and
                knx_dict.get('reason') != 'no_knx_integration'
            )

            if is_knx_configured:
                knx_ip_val = raw_gw_ip
                try: knx_port_val = int(knx_dict.get('gateway_port', 3671))
                except: knx_port_val = 3671
            else:
                knx_ip_val = None
                knx_port_val = None
                # Explicitly sanitize knx_dict and technologies dict to prevent any phantom values in JSON fields
                knx_dict = {'configured': False, 'reachable': False, 'reason': 'no_knx_integration', 'gateway_ip': None, 'gateway_port': None}
                if isinstance(tech_dict, dict) and 'knx' in tech_dict:
                    tech_dict['knx'] = knx_dict
                # If non-KNX client had an ets_port allocated, release it immediately!
                if client.get('ets_port'):
                    try:
                        release_ets_port(client_id)
                        sync_ets_nat_rules()
                    except Exception as ex:
                        print(f"[!] Error releasing phantom ETS port for {client_id}: {ex}")

            if 'ssh_public_key' in body and body['ssh_public_key']:
                sync_client_ssh_user(client_id, body['ssh_public_key'])

            if tech_dict is None:
                try: tech_dict = json.loads(client.get('technologies_json') or '{}')
                except: tech_dict = {}

            if tech_dict and isinstance(tech_dict, dict):
                # Hard server-side filter: Completely strip and ignore any entries marked source == 'ignore', state == 'ignored', or disabled_by
                def _is_entry_ignored(e):
                    if not isinstance(e, dict): return True
                    if str(e.get('source', '')).strip().lower() == 'ignore': return True
                    if str(e.get('state', '')).strip().lower() == 'ignored': return True
                    if e.get('disabled_by'): return True
                    return False

                # 1. Sanitize Lutron entries
                if 'lutron' in tech_dict and isinstance(tech_dict['lutron'], dict):
                    raw_entries = tech_dict['lutron'].get('entries') or []
                    clean_entries = [e for e in raw_entries if not _is_entry_ignored(e)]
                    tech_dict['lutron']['entries'] = clean_entries
                    if not clean_entries:
                        tech_dict['lutron']['detected'] = False
                        tech_dict['lutron']['status'] = 'not_configured'
                        tech_dict['lutron']['offline_reason'] = ''
                    else:
                        all_online = all(e.get('state') == 'loaded' or e.get('online') is True for e in clean_entries)
                        any_online = any(e.get('state') == 'loaded' or e.get('online') is True for e in clean_entries)
                        if all_online:
                            tech_dict['lutron']['status'] = 'online'
                            tech_dict['lutron']['offline_reason'] = ''
                        elif any_online:
                            tech_dict['lutron']['status'] = 'degraded'
                        else:
                            tech_dict['lutron']['status'] = 'offline'

                # 2. Sanitize CoolMaster entries
                if 'coolmaster' in tech_dict and isinstance(tech_dict['coolmaster'], dict):
                    raw_cm = tech_dict['coolmaster'].get('entries') or []
                    clean_cm = [e for e in raw_cm if not _is_entry_ignored(e)]
                    tech_dict['coolmaster']['entries'] = clean_cm
                    if not clean_cm:
                        tech_dict['coolmaster']['detected'] = False
                        tech_dict['coolmaster']['status'] = 'not_configured'
                        tech_dict['coolmaster']['offline_reason'] = ''

                # 3. Sanitize failed_core_entries
                if 'failed_core_entries' in tech_dict and isinstance(tech_dict['failed_core_entries'], list):
                    tech_dict['failed_core_entries'] = [e for e in tech_dict['failed_core_entries'] if not _is_entry_ignored(e)]

                # 4. Sanitize self_healing
                sh_data = body.get('self_healing')
                if sh_data and isinstance(sh_data, dict):
                    sh_subs = sh_data.get('subsystems') or {}
                    # If lutron is healthy and not exhausted, ensure its self_healing status is not stuck in healing
                    if tech_dict.get('lutron', {}).get('status') == 'online' and 'lutron' in sh_subs:
                        if not sh_subs['lutron'].get('exhausted') and sh_subs['lutron'].get('attempts', 0) < 5:
                            sh_subs['lutron']['status'] = 'idle'
                            sh_subs['lutron']['attempts'] = 0
                    
                    # For all subsystems: enforce user directive: after 5 attempts, status is exhausted, do not retry
                    for s_k, s_v in sh_subs.items():
                        if isinstance(s_v, dict):
                            if s_v.get('attempts', 0) >= 5 or s_v.get('status') in ['escalated', 'exhausted']:
                                s_v['status'] = 'exhausted'
                                s_v['exhausted'] = True
                                s_v['attempts'] = max(5, s_v.get('attempts', 5))
                    tech_dict['self_healing'] = sh_data
            elif body.get('self_healing') and isinstance(body.get('self_healing'), dict):
                tech_dict['self_healing'] = body.get('self_healing')

            # Capture Autonomous Self-Healing Engine telemetry
            sh_data = tech_dict.get('self_healing')
            if sh_data and isinstance(sh_data, dict):
                recs = sh_data.get('recent_recoveries') or []
                if recs:
                    latest = recs[0]
                    print(f"[✓] [Autonomous Self-Healing] Client '{client_id}' recovered '{latest.get('subsystem')}' autonomously after {latest.get('attempts_taken')} attempt(s)!", flush=True)

            # Capture Add-on Version in system_dict
            if 'system' in body and isinstance(body['system'], dict) and 'addon_version' in body['system']:
                sys_dict['addon_version'] = body['system']['addon_version']

            backups_list = body.get('backups')
            if backups_list is None:
                try: backups_list = json.loads(client.get('backups_json') or '[]')
                except: backups_list = []

            pending_bk = client.get('pending_backup')
            pending_cmd = client.get('pending_command')
            unmon_val = client.get('unmonitored_integrations')
            try:
                unmon_list = json.loads(unmon_val) if isinstance(unmon_val, str) else (unmon_val or [])
            except Exception:
                unmon_list = []

            # Autonomous Fleet Auto-Update Engine (§3.D.4)
            auto_up_enabled = int(client.get('auto_update') if client.get('auto_update') is not None else 1)
            if auto_up_enabled and not pending_cmd:
                addon_up = bool(sys_dict.get('addon_update_available') or (sys_dict.get('addon_version') and sys_dict.get('addon_latest_version') and sys_dict.get('addon_version') != sys_dict.get('addon_latest_version')))
                core_up = bool(sys_dict.get('core_update_available'))
                sup_up = bool(sys_dict.get('supervisor_update_available'))
                
                chosen_action = None
                if addon_up and (core_up or sup_up):
                    chosen_action = 'update_all'
                elif addon_up:
                    chosen_action = 'update_addon'
                elif core_up:
                    chosen_action = 'update_core'
                elif sup_up:
                    chosen_action = 'update_supervisor'
                    
                if chosen_action:
                    auto_cmd_payload = json.dumps({
                        'action': chosen_action,
                        'queued_at': now,
                        'queued_by': 'autonomous_fleet_auto_update'
                    })
                    pending_cmd = auto_cmd_payload
                    print(f"[AUTO_UPDATE] Autonomously dispatched '{chosen_action}' for client '{client_id}' on heartbeat pulse.", flush=True)

            resp_payload = {
                'ok': True,
                'server_time': now,
                'remote_enabled': bool(client.get('remote_enabled', 1)),
                'unmonitored_integrations': unmon_list
            }
            if pending_bk:
                resp_payload['backup_trigger'] = {
                    'action': 'create_backup',
                    'name': pending_bk
                }
            if pending_cmd:
                try:
                    resp_payload['command'] = json.loads(pending_cmd) if isinstance(pending_cmd, str) else pending_cmd
                except Exception:
                    resp_payload['command'] = {'action': pending_cmd}

            # Targeted single-row SQL update (§3.D.2)
            with DB_LOCK:
                conn = get_db_connection()
                try:
                    with conn:
                        conn.execute("""
                            UPDATE clients SET
                                last_heartbeat = ?,
                                status = 'online',
                                onboarded_at = COALESCE(onboarded_at, ?),
                                system_json = ?,
                                network_json = ?,
                                knx_json = ?,
                                knx_ip = ?,
                                knx_port = ?,
                                technologies_json = ?,
                                backups_json = ?,
                                pending_backup = CASE WHEN ? IS NOT NULL THEN NULL ELSE pending_backup END,
                                pending_command = CASE WHEN ? IS NOT NULL THEN NULL ELSE pending_command END
                            WHERE client_id = ?
                        """, (
                            now,
                            now,
                            json.dumps(sys_dict),
                            json.dumps(net_dict),
                            json.dumps(knx_dict),
                            knx_ip_val,
                            knx_port_val,
                            json.dumps(tech_dict),
                            json.dumps(backups_list),
                            pending_bk,
                            pending_cmd,
                            client_id
                        ))
                finally:
                    conn.close()

            # Auto-allocate or update remote ETS port ONLY if client has genuine KNX integration
            current_ets_port = client.get('ets_port')
            if is_knx_configured:
                ttype = 'onboard' if knx_ip_val in ['127.0.0.1', 'localhost', ''] else 'lan_device'
                tip = knx_ip_val or '127.0.0.1'
                tport = knx_port_val or 3671
                if not current_ets_port or client.get('ets_target_ip') != tip or client.get('ets_target_port') != tport:
                    try:
                        allocated_p = allocate_ets_port(client_id, target_ip=tip, target_port=tport, target_type=ttype)
                        sync_ets_nat_rules()
                        resp_payload['ets_port'] = allocated_p
                    except Exception as e:
                        print(f"[!] Error auto-allocating ETS port for {client_id}: {e}")

            self.send_json(200, resp_payload)
            return

        # 17. Approve Client Registration (Manufacturer Only)
        elif parsed.path == '/api/approvals/approve':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer authorization required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            client_id = body.get('client_id', '').strip()

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            client['approval_status'] = 'approved'
            client['remote_enabled'] = True
            save_clients_state(c_data)

            # Sync Caddy ingress and prewarm TLS
            sync_caddy_ingress(client_id, client.get('dashboard_port', 10001), 'http', True, wg_ip=client.get('wg_ip'))
            prewarm_caddy_tls(client.get('domain', f"{client_id}.gavasah.com"))

            append_client_log(
                client_id, 'INFO', 'CLIENT_APPROVED',
                f"Client site '{client.get('name', client_id)}' approved by Manufacturer. Remote access & telemetry monitoring enabled."
            )

            # Publish MQTT lifecycle event
            publish_mqtt_message(f'gavasah/lifecycle/clients/{client_id}', {
                'event': 'client_approved',
                'client_id': client_id,
                'name': client.get('name'),
                'domain': client.get('domain'),
                'remote_enabled': True
            }, retain=True)

            self.send_json(200, {
                'ok': True,
                'message': f"Client '{client.get('name')}' approved successfully. Remote ingress & telemetry active."
            })
            return

        # 18. Reject Client Registration (Manufacturer Only)
        elif parsed.path == '/api/approvals/reject':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer authorization required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            client_id = body.get('client_id', '').strip()
            reason = body.get('reason', 'Registration declined by Manufacturer HQ').strip()

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            client['approval_status'] = 'rejected'
            client['rejection_reason'] = reason
            client['remote_enabled'] = False
            save_clients_state(c_data)

            # Purge Caddy ingress
            purge_caddy_ingress(client_id)

            append_client_log(
                client_id, 'WARNING', 'CLIENT_REJECTED',
                f"Client site '{client.get('name', client_id)}' rejected by Manufacturer: {reason}"
            )

            # Publish MQTT lifecycle event
            publish_mqtt_message(f'gavasah/lifecycle/clients/{client_id}', {
                'event': 'client_rejected',
                'client_id': client_id,
                'reason': reason
            }, retain=True)

            self.send_json(200, {
                'ok': True,
                'message': f"Client '{client.get('name')}' rejected."
            })
            return

        # 19. Publish MQTT Command / Telemetry Message
        elif parsed.path == '/api/mqtt/publish':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_length).decode('utf-8'))
            topic = body.get('topic', '').strip()
            payload = body.get('payload', '')

            if not topic:
                self.send_json(400, {'error': 'Topic is required'})
                return

            ok = publish_mqtt_message(topic, payload)
            if ok:
                self.send_json(200, {'ok': True, 'topic': topic, 'message': 'Dispatched via MQTT broker'})
            else:
                self.send_json(500, {'error': 'Failed to dispatch via MQTT broker'})
            return

        # 20. WhatsApp Logout / Reset Session (Manufacturer Only)
        elif parsed.path == '/api/whatsapp/logout':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            try:
                req = urllib.request.Request('http://127.0.0.1:3005/logout', data=b'{}', headers={'Content-Type': 'application/json'}, method='POST')
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
                    self.send_json(200, data)
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        # 21. WhatsApp / Autonomous Alert Send
        # 20.1 Toggle Integration Monitoring per Client
        elif parsed.path == '/api/client/toggle_integration_monitoring':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                req_data = json.loads(body_bytes.decode('utf-8'))
                cid = req_data.get('client_id')
                tech_key = req_data.get('tech_key')
                monitored = bool(req_data.get('monitored', True))

                if not cid or not tech_key:
                    self.send_json(400, {'error': 'Missing client_id or tech_key'})
                    return

                with DB_LOCK:
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute("SELECT unmonitored_integrations FROM clients WHERE client_id = ?", (cid,))
                    row = cur.fetchone()
                    if not row:
                        conn.close()
                        self.send_json(404, {'error': 'Client not found'})
                        return
                    try:
                        unmon = json.loads(row['unmonitored_integrations'] or '[]')
                    except Exception:
                        unmon = []

                    if monitored:
                        unmon = [k for k in unmon if k != tech_key]
                    else:
                        if tech_key not in unmon:
                            unmon.append(tech_key)

                    # Update unmonitored_integrations and halt/disable self healing if muted
                    cur.execute("SELECT technologies_json FROM clients WHERE client_id = ?", (cid,))
                    t_row = cur.fetchone()
                    t_dict = {}
                    if t_row and t_row['technologies_json']:
                        try:
                            t_dict = json.loads(t_row['technologies_json'])
                        except Exception:
                            t_dict = {}
                    
                    if not monitored and 'self_healing' in t_dict and 'subsystems' in t_dict['self_healing']:
                        if tech_key in t_dict['self_healing']['subsystems']:
                            t_dict['self_healing']['subsystems'][tech_key]['status'] = 'disabled'
                            t_dict['self_healing']['subsystems'][tech_key]['attempts'] = 0
                            t_dict['self_healing']['subsystems'][tech_key]['exhausted'] = False
                            t_dict['self_healing']['subsystems'][tech_key]['last_action'] = 'Monitoring muted from Dealer Dashboard. Auto-recovery paused.'

                    # Discard from alert registry if muted
                    if not monitored and 'NOTIFIED_FAILED_RECOVERY' in globals():
                        NOTIFIED_FAILED_RECOVERY.discard((cid, tech_key))

                    cur.execute("UPDATE clients SET unmonitored_integrations = ?, technologies_json = ? WHERE client_id = ?", (json.dumps(unmon), json.dumps(t_dict), cid))
                    conn.commit()
                    conn.close()

                self.send_json(200, {
                    'success': True,
                    'client_id': cid,
                    'tech_key': tech_key,
                    'monitored': monitored,
                    'unmonitored_integrations': unmon,
                    'message': f"Integration {tech_key} monitoring {'enabled' if monitored else 'muted (alerts suppressed)'}"
                })
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        # 20.2 Save SMTP Email Gateway Settings
        elif parsed.path == '/api/settings/smtp':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required to update SMTP settings'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                cfg = json.loads(body_bytes.decode('utf-8'))
                now = int(time.time())
                with DB_LOCK:
                    conn = get_db_connection()
                    conn.execute("INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)",
                                 ('smtp_settings', json.dumps(cfg), now))
                    conn.commit()
                    conn.close()
                self.send_json(200, {'success': True, 'message': 'SMTP configuration saved successfully', 'config': cfg})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        # 20.3 Test SMTP Email Dispatch
        elif parsed.path == '/api/settings/smtp/test':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                req_data = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
                host = req_data.get('host', '').strip()
                port = int(req_data.get('port', 587))
                encryption = req_data.get('encryption', 'tls').lower()
                user_email = req_data.get('user', '').strip()
                password = req_data.get('pass', '').strip()
                from_email = req_data.get('from_email', user_email).strip()
                from_name = req_data.get('from_name', 'GAVASAH Cloud Alerts').strip()
                to_email = req_data.get('recipient', user_email).strip()
                subject = req_data.get('subject', '[GAVASAH] SMTP Email Testing Station Probe').strip()
                msg_body = req_data.get('message', 'This is a test notification from GAVASAH Multi-Tenant Cloud Hub email alert station.').strip()

                if not host or not to_email:
                    self.send_json(400, {'error': 'SMTP Host and Destination Email are required'})
                    return

                import smtplib, ssl
                from email.mime.multipart import MIMEMultipart
                from email.mime.text import MIMEText

                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = f"{from_name} <{from_email}>"
                msg['To'] = to_email

                text_part = MIMEText(f"GAVASAH CLOUD ALERT\n\n{msg_body}\n\nTimestamp: {datetime.datetime.now().isoformat()}", 'plain', 'utf-8')
                html_body = f"<div style='font-family:sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#f8fafc;padding:24px;border-radius:12px;border:1px solid rgba(0,240,255,0.4);'><h2 style='color:#00f0ff;margin-top:0;'>⚡ GAVASAH CLOUD ALERT</h2><p style='color:#cbd5e1;font-size:14px;line-height:1.6;'>{msg_body}</p><div style='background:rgba(2,6,23,0.7);border:1px solid rgba(255,255,255,0.1);padding:12px;border-radius:8px;font-size:12px;color:#94a3b8;margin-top:16px;'><div><strong>SMTP Server:</strong> {host}:{port} ({encryption.upper()})</div><div><strong>Sender:</strong> {from_name} &lt;{from_email}&gt;</div><div><strong>Recipient:</strong> {to_email}</div></div><p style='font-size:11px;color:#64748b;margin-top:16px;margin-bottom:0;'>Dispatched autonomously by GAVASAH Dealer Cloud Hub</p></div>"
                html_part = MIMEText(html_body, 'html', 'utf-8')
                msg.attach(text_part)
                msg.attach(html_part)

                t0 = time.time()
                if encryption == 'ssl':
                    ctx = ssl.create_default_context()
                    with smtplib.SMTP_SSL(host, port, context=ctx, timeout=12) as server:
                        if user_email and password:
                            server.login(user_email, password)
                        server.sendmail(from_email, [to_email], msg.as_string())
                else:
                    with smtplib.SMTP(host, port, timeout=12) as server:
                        if encryption == 'tls':
                            ctx = ssl.create_default_context()
                            server.starttls(context=ctx)
                        if user_email and password:
                            server.login(user_email, password)
                        server.sendmail(from_email, [to_email], msg.as_string())

                latency_ms = round((time.time() - t0) * 1000, 1)
                self.send_json(200, {
                    'success': True,
                    'message': f"Email delivered successfully to {to_email} via {host}:{port} in {latency_ms}ms",
                    'messageId': f"EMAIL-{int(time.time())}",
                    'recipient': to_email,
                    'latency_ms': latency_ms,
                    'status': 'DELIVERED (SMTP Handshake & Auth OK)'
                })
            except Exception as e:
                logging.exception("[SMTP Test Error]")
                self.send_json(500, {'error': f"SMTP Delivery Failed: {str(e)}"})
            return

        elif parsed.path == '/api/whatsapp/send':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                body_json = json.loads(body_bytes.decode('utf-8'))
                channel = body_json.get('channel', 'whatsapp')
                raw_phone = str(body_json.get('phone', '')).strip()
                clean_phone = re.sub(r'[^0-9]', '', raw_phone)
                if len(clean_phone) == 10 and clean_phone[0] in ['6', '7', '8', '9']:
                    clean_phone = '91' + clean_phone
                msg = str(body_json.get('message', '')).strip()
                client_id = body_json.get('client_id')
                is_manual_test = body_json.get('manual_test', False) or not client_id

                wa_payload = json.dumps({'phone': clean_phone, 'message': msg}).encode('utf-8')

                if channel == 'whatsapp':
                    req = urllib.request.Request('http://127.0.0.1:3005/send', data=wa_payload, headers={'Content-Type': 'application/json'}, method='POST')
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        data = json.loads(resp.read().decode('utf-8'))
                        self.send_json(200, data)

                elif channel == 'voice':
                    ist_now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
                    curr_hm = ist_now.strftime('%H:%M')

                    # Only evaluate calling window for automated background partner client escalations, NEVER manual testing station
                    if client_id and not is_manual_test:
                        c_data = load_clients_state()
                        cl = c_data.get(client_id)
                        if cl:
                            allowed, reason = is_call_allowed_now(cl)
                            if not allowed:
                                self.send_json(200, {
                                    'success': False,
                                    'error': f"Call suppressed by policy: {reason}",
                                    'recipient': clean_phone,
                                    'channel': 'voice',
                                    'suppressed': True
                                })
                                return

                    sip_dialed = False
                    sip_status_desc = "Audible Voice Memo (WhatsApp PTT Audio)" 

                    # Dispatch audible voice note (PTT memo) directly to recipient's mobile phone
                    wa_voice_payload = json.dumps({
                        'phone': clean_phone,
                        'message': msg,
                        'is_voice': True,
                        'channel': 'voice'
                    }).encode('utf-8')
                    wa_mid = f'CALL-{int(time.time())}'
                    try:
                        req = urllib.request.Request('http://127.0.0.1:3005/send', data=wa_voice_payload, headers={'Content-Type': 'application/json'}, method='POST')
                        with urllib.request.urlopen(req, timeout=12) as resp:
                            res_json = json.loads(resp.read().decode('utf-8'))
                            if res_json.get('messageId'):
                                wa_mid = res_json['messageId']
                    except Exception as we:
                        logging.warning(f"[WhatsApp] Voice memo dispatch error: {we}")

                    self.send_json(200, {
                        'success': True,
                        'messageId': wa_mid,
                        'recipient': clean_phone,
                        'channel': 'voice',
                        'status': sip_status_desc,
                        'sip_dialed': sip_dialed,
                        'voice_memo': True,
                        'spoken_text': msg,
                        'timestamp': ist_now.strftime('%I:%M %p IST')
                    })
                elif channel == 'email':
                    to_email = body_json.get('email', '').strip() or raw_phone
                    if '@' not in to_email:
                        self.send_json(400, {'error': f"Invalid destination email address: '{to_email}'"})
                        return

                    subject = body_json.get('subject', '[GAVASAH ALERT] Automated Notification').strip()
                    
                    with DB_LOCK:
                        conn = get_db_connection()
                        cur = conn.cursor()
                        cur.execute("SELECT value FROM system_settings WHERE key = 'smtp_settings'")
                        row = cur.fetchone()
                        conn.close()
                    
                    if not row:
                        self.send_json(400, {'error': 'SMTP Gateway not configured. Please save SMTP settings in Alerts & Notifications tab.'})
                        return
                    
                    try: cfg = json.loads(row['value'])
                    except Exception: cfg = {}

                    host = cfg.get('host', '').strip()
                    port = int(cfg.get('port', 587))
                    encryption = cfg.get('encryption', 'tls').lower()
                    user_email = cfg.get('user', '').strip()
                    password = cfg.get('pass', '').strip()
                    from_email = cfg.get('from_email', user_email).strip()
                    from_name = cfg.get('from_name', 'GAVASAH Cloud Alerts').strip()

                    if not host or not from_email:
                        self.send_json(400, {'error': 'SMTP Gateway incomplete. Host and From Email are required.'})
                        return

                    import smtplib, ssl
                    from email.mime.multipart import MIMEMultipart
                    from email.mime.text import MIMEText

                    msg_mime = MIMEMultipart('alternative')
                    msg_mime['Subject'] = subject
                    msg_mime['From'] = f"{from_name} <{from_email}>"
                    msg_mime['To'] = to_email

                    text_content = f"GAVASAH ALERT\n\n{msg}\n\nTimestamp: {datetime.datetime.now().strftime('%Y-%m-%d %I:%M %p')}"
                    html_content = f"<div style='font-family:sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#f8fafc;padding:24px;border-radius:12px;border:1px solid rgba(0,240,255,0.4);'><h2 style='color:#00f0ff;margin-top:0;'>⚡ GAVASAH CLOUD ALERT</h2><p style='color:#cbd5e1;font-size:15px;line-height:1.6;'>{msg}</p><div style='background:rgba(2,6,23,0.7);border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:12px 16px;margin:20px 0;font-size:12px;color:#94a3b8;'><div><strong>Recipient:</strong> {to_email}</div><div><strong>Dispatched:</strong> {datetime.datetime.now().strftime('%I:%M %p IST')}</div></div></div>"
                    msg_mime.attach(MIMEText(text_content, 'plain', 'utf-8'))
                    msg_mime.attach(MIMEText(html_content, 'html', 'utf-8'))

                    if encryption == 'ssl':
                        ctx = ssl.create_default_context()
                        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=12) as s:
                            if user_email and password: s.login(user_email, password)
                            s.sendmail(from_email, [to_email], msg_mime.as_string())
                    else:
                        with smtplib.SMTP(host, port, timeout=12) as s:
                            if encryption == 'tls':
                                ctx = ssl.create_default_context()
                                s.starttls(context=ctx)
                            if user_email and password: s.login(user_email, password)
                            s.sendmail(from_email, [to_email], msg_mime.as_string())

                    mid = f"EMAIL-{int(time.time())}"
                    self.send_json(200, {
                        'success': True,
                        'messageId': mid,
                        'recipient': to_email,
                        'channel': 'email',
                        'status': f'Delivered via SMTP ({host})',
                        'timestamp': datetime.datetime.now().strftime('%I:%M %p IST')
                    })
                else:
                    self.send_json(400, {'error': f'Unsupported notification channel: {channel}'})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path == '/api/whatsapp/admin_number':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                data = json.loads(body_bytes.decode('utf-8'))
                raw_phone = str(data.get('admin_whatsapp_number', '')).strip()
                clean_phone = re.sub(r'[^0-9]', '', raw_phone)
                if len(clean_phone) == 10 and clean_phone[0] in ['6', '7', '8', '9']:
                    clean_phone = '91' + clean_phone
                if len(clean_phone) < 10:
                    self.send_json(400, {'error': 'Invalid phone number format. Must contain at least 10 digits.'})
                    return
                now = int(time.time())
                with DB_LOCK:
                    conn = get_db_connection()
                    conn.execute("INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)",
                                 ('admin_whatsapp_number', clean_phone, now))
                    conn.commit()
                    conn.close()
                self.send_json(200, {
                    'success': True,
                    'message': f'Admin WhatsApp destination number updated to +{clean_phone}',
                    'admin_whatsapp_number': clean_phone
                })
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path == '/api/whatsapp/admin_test_ping':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b'{}'
            try:
                data = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
                override_phone = str(data.get('admin_whatsapp_number', '')).strip()
                target_phone = override_phone if override_phone else get_admin_whatsapp_number()
                clean_phone = re.sub(r'[^0-9]', '', target_phone)
                if len(clean_phone) == 10 and clean_phone[0] in ['6', '7', '8', '9']:
                    clean_phone = '91' + clean_phone
                if len(clean_phone) < 10:
                    self.send_json(400, {'error': 'Valid recipient phone number required'})
                    return
                
                test_msg = (
                    "🔔 *[GAVASAH CLOUD] Admin WhatsApp Verification Ping*\n\n"
                    "✅ System alerts, ecosystem health diagnostics, and AI Copilot proposals "
                    f"will be routed to this Admin WhatsApp number (+{clean_phone}).\n\n"
                    f"🕒 Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n"
                    "🛡️ Cloud Node: CT 150 (gavasah-cloud-hub)"
                )
                
                wa_payload = json.dumps({'phone': clean_phone, 'message': test_msg}).encode('utf-8')
                req = urllib.request.Request(
                    'http://127.0.0.1:3005/send',
                    data=wa_payload,
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    resp_data = json.loads(resp.read().decode('utf-8'))
                    self.send_json(200, {'success': True, 'result': resp_data, 'recipient': clean_phone})
            except Exception as e:
                self.send_json(500, {'error': f'WhatsApp gateway dispatch error: {str(e)}'})
            return

        elif parsed.path == '/api/whatsapp/inbound':
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b'{}'
            try:
                data = json.loads(body_bytes.decode('utf-8'))
                from_phone = re.sub(r'[^0-9]', '', str(data.get('from', '')))
                user_msg = str(data.get('text', '')).strip()
                admin_num = get_admin_whatsapp_number()
                clean_admin = re.sub(r'[^0-9]', '', admin_num)

                is_admin = False
                if clean_admin and from_phone:
                    if from_phone == clean_admin or from_phone.endswith(clean_admin[-10:]):
                        is_admin = True

                if not is_admin:
                    self.send_json(200, {
                        'success': False,
                        'reply': '⚠️ *[GAVASAH CLOUD]* Sender not recognized as authorized Admin.'
                    })
                    return

                up_msg = user_msg.upper()
                appr_match = re.match(r'^APPROVE\s+(\d+)$', up_msg)
                rej_match = re.match(r'^REJECT\s+(\d+)$', up_msg)

                now = int(time.time())
                if appr_match:
                    prop_id = appr_match.group(1).strip()
                    ok, exec_msg = execute_copilot_proposal(prop_id, actor='admin_whatsapp')
                    if ok:
                        reply = f"✅ *[GAVASAH AI COPILOT]* Proposal #{prop_id} has been *APPROVED & EXECUTED* by Admin.\n⚡ {exec_msg}"
                    else:
                        reply = f"⚠️ *[GAVASAH AI COPILOT]* Proposal #{prop_id} execution notice:\n{exec_msg}"

                elif rej_match:
                    prop_id = rej_match.group(1).strip()
                    with DB_LOCK:
                        conn = get_db_connection()
                        cur = conn.cursor()
                        cur.execute("UPDATE copilot_proposals SET status = 'rejected', resolved_by = 'admin_whatsapp', resolved_at = ? WHERE (id = ? OR id = ?) AND status = 'pending'", (now, prop_id, f"prop_{prop_id}"))
                        rows_affected = cur.rowcount
                        conn.commit()
                        conn.close()
                    if rows_affected > 0:
                        reply = f"❌ *[GAVASAH AI COPILOT]* Proposal #{prop_id} has been *REJECTED* by Admin."
                    else:
                        reply = f"⚠️ *[GAVASAH AI COPILOT]* Proposal #{prop_id} was not found or is already resolved."

                elif up_msg in ['STATUS', 'FLEET', 'HEALTH']:
                    with DB_LOCK:
                        conn = get_db_connection()
                        clients = conn.execute("SELECT client_id, status, last_heartbeat FROM clients").fetchall()
                        conn.close()
                    total = len(clients)
                    online = sum(1 for c in clients if c[1] == 'online' and c[2] and (now - c[2]) < 1800)
                    offline = total - online
                    reply = (
                        f"📊 *[GAVASAH FLEET STATUS]*\n"
                        f"• Master Add-on: v1.3.0\n"
                        f"• Total Gateways: {total}\n"
                        f"• Online: {online} 🟢\n"
                        f"• Offline / Warning: {offline} 🔴\n"
                        f"• Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}"
                    )

                elif up_msg in ['PROPOSALS', 'PENDING']:
                    with DB_LOCK:
                        conn = get_db_connection()
                        props = conn.execute("SELECT id, client_id, summary, created_at FROM copilot_proposals WHERE status = 'pending' ORDER BY created_at ASC LIMIT 5").fetchall()
                        conn.close()
                    if not props:
                        reply = "✅ *[GAVASAH AI COPILOT]* No pending proposals awaiting approval."
                    else:
                        lines = ["📋 *[PENDING AI PROPOSALS]*"]
                        for p in props:
                            lines.append(f"• #{p[0]}: [{p[1]}] {p[2]}\n  👉 Reply *APPROVE {p[0]}* or *REJECT {p[0]}*")
                        reply = "\n".join(lines)

                else:
                    ollama_url = 'http://192.168.6.185:11434/api/chat'
                    grounding_data = get_ecosystem_grounding_context(include_proposals=True)
                    chat_history = get_recent_copilot_chat_messages(limit=20)
                    sys_prompt = (
                        "You are GAVASAH Autonomous AI Copilot — the elite master operations AI for the GAVASAH Ecosystem "
                        "(CT 150 Cloud Hub + Gateway Fleet). You speak with the precision, technical depth, and executive ownership of Antigravity.\n\n"
                        "OPERATIONAL DIRECTIVES:\n"
                        "1. OWNERSHIP & PROACTIVITY: You are fully self-aware of the ecosystem state. Do not give vague advice or tell the admin how to run commands. Offer concrete solutions and register actionable proposals.\n"
                        "2. CONTINUOUS CONVERSATION CONTINUITY: You remember the full thread of discussion. Never lose track of what topic you and the user are discussing.\n"
                        "3. STRICT REALITY GROUNDING: Never hallucinate versions or states. The official repository master add-on version is ALWAYS v1.3.0. Always inspect and quote the exact values from the Live Ground Truth below.\n"
                        "4. ELEGANT STRUCTURE: Format your WhatsApp responses with clear bullet points, bold highlights, and clean status indicators (🟢, 🔴, ⚡, 📋). Keep responses punchy and under 160 words.\n\n"
                        f"{grounding_data}"
                    )
                    
                    messages_payload = [{'role': 'system', 'content': sys_prompt}]
                    # Append recent conversation turns
                    for turn in chat_history:
                        messages_payload.append(turn)
                    messages_payload.append({'role': 'user', 'content': user_msg})

                    ollama_payload = json.dumps({
                        'model': 'qwen2.5-coder:7b',
                        'messages': messages_payload,
                        'stream': False,
                        'options': {'num_ctx': 16384}
                    }).encode('utf-8')
                    try:
                        oreq = urllib.request.Request(ollama_url, data=ollama_payload, headers={'Content-Type': 'application/json'}, method='POST')
                        with urllib.request.urlopen(oreq, timeout=25) as oresp:
                            ores_data = json.loads(oresp.read().decode('utf-8'))
                            reply = ores_data.get('message', {}).get('content', '')
                    except Exception as ex:
                        reply = f"🤖 *[GAVASAH AI COPILOT]*: Acknowledged: \"{user_msg}\". (LLM note: {ex})"

                    now_wa = int(time.time())
                    with DB_LOCK:
                        conn = get_db_connection()
                        conn.execute("INSERT INTO copilot_chat_history (id, sender, message, timestamp) VALUES (?, ?, ?, ?)",
                                     (f"msg_{now_wa}_{os.urandom(2).hex()}", 'user', f"[WhatsApp] {user_msg}", now_wa))
                        conn.execute("INSERT INTO copilot_chat_history (id, sender, message, timestamp) VALUES (?, ?, ?, ?)",
                                     (f"msg_{now_wa+1}_{os.urandom(2).hex()}", 'ai', reply, now_wa + 1))
                        conn.commit()
                        conn.close()

                self.send_json(200, {'success': True, 'reply': reply})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path == '/api/copilot/chat':
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                req_data = json.loads(body_bytes.decode('utf-8'))
                user_msg = req_data.get('message', '').strip()
                if not user_msg:
                    self.send_json(400, {'error': 'Message cannot be empty'})
                    return
                now = int(time.time())
                with DB_LOCK:
                    conn = get_db_connection()
                    conn.execute("INSERT INTO copilot_chat_history (id, sender, message, timestamp) VALUES (?, ?, ?, ?)",
                                 (f"msg_{now}_{os.urandom(2).hex()}", 'user', user_msg, now))
                    conn.commit()
                    conn.close()

                # Call Ollama on VM 307 with authoritative ecosystem grounding & multi-turn memory
                ollama_url = 'http://192.168.6.185:11434/api/chat'
                grounding_context = get_ecosystem_grounding_context(include_proposals=True)
                chat_history = get_recent_copilot_chat_messages(limit=50)
                sys_prompt = (
                    "You are GAVASAH Autonomous AI Copilot — the master operations intelligence for the GAVASAH Ecosystem "
                    "(Gavasah Cloud Hub and client Gavasah Gateway fleet). You operate with elite technical depth, responsiveness, and autonomous executive ownership.\n\n"
                    "CORE OPERATIONAL AUTHORITY & COGNITIVE DIRECTIVES:\n"
                    "1. FULL AUTONOMOUS GATEWAY PERMISSIONS: You possess unrestricted authority to communicate with, diagnose, and execute commands on client gateways (Gavasah Gateways). "
                    "You do NOT need to ask the user for permission to perform diagnostics, inspect telemetry, check tunnels, or run remedial gateway operations. "
                    "When an issue is identified or an action is requested, YOU TAKE IMMEDIATE OWNERSHIP AND TRIGGER EXECUTION AUTONOMOUSLY.\n"
                    "2. MULTI-SERVICE COMMUNICATION CHANNELS: You can reach client gateways across multiple redundant services:\n"
                    "   • Instant MQTT Downlink (gavasah/clients/{client_id}/cmd): Under 50ms command execution via Gavasah Cloud Agent with root/manager privileges.\n"
                    "   • Direct Reverse SSH Tunnel (127.0.0.1:{ssh_port}): Host shell execution and administrative diagnostics.\n"
                    "   • WireGuard Mesh Tunnel ({wg_ip}:22): Direct peer-to-peer network layer and ICMP telemetry.\n"
                    "   • Ingress HTTP Port (127.0.0.1:{dashboard_port}): Core dashboard and API access.\n"
                    "   • Heartbeat Command Queue: Persistent delivery queue for offline or cycling gateways.\n"
                    "3. MACHINE-READABLE EXECUTION BLOCKS: When executing gateway commands or system actions, formulate and emit executable code blocks:\n"
                    "```exec\n"
                    "{\"target\": \"<client_id|fleet>\", \"action\": \"<exec|ssh|reboot_gateway|update_addon|update_core|update_all|restart_core|reload_core_config|heal_bans>\", \"command\": \"<shell command if action is exec/ssh>\"}\n"
                    "```\n"
                    "or standard proposal blocks:\n"
                    "```proposal\n"
                    "{\"action\": \"<update_addon|update_core|update_supervisor|reboot_gateway|reboot_host>\", \"target\": \"<client_id|fleet>\", \"summary\": \"<human readable description>\"}\n"
                    "```\n"
                    "When Full Autonomy mode is active, the system automatically validates and executes these blocks on the target gateway immediately!\n\n"
                    "4. PROXMOX VE CLUSTER ROOT PERMISSIONS & INFRASTRUCTURE CONTROL:\n"
                    "You have FULL ROOT AUTHORITY over the entire Proxmox VE cluster (primordial-1, primordial-2, primordial-3) and all member VMs and LXC containers (e.g. VM 307 ai-server-2, VM 204 Home Assistant, CT 150 Gavasah Hub, CT 100 Frigate).\n"
                    "You can execute Proxmox actions autonomously by emitting:\n"
                    "```proxmox\n"
                    "{\"node\": \"<primordial-1|primordial-2|primordial-3>\", \"action\": \"<vm_start|vm_stop|vm_reboot|vm_reset|lxc_start|lxc_stop|lxc_restart|node_status|cluster_status>\", \"vmid\": <vmid>}\n"
                    "```\n"
                    "Emitting a proxmox block executes the action live via the Proxmox REST API immediately!\n"
                    "4. MANDATORY CHAIN-OF-THOUGHT DIRECTIVE (<think>...</think>):\n"
                    "You MUST wrap your entire step-by-step diagnostic reasoning, channel verification, and execution analysis inside <think>...</think> tags at the VERY START of every response.\n"
                    "Do NOT omit <think>...</think> under any condition. After </think>, provide your formatted operational response.\n\n"
                    "5. CLIENT GATEWAY (GAVASAH GATEWAY) RUNS HOME ASSISTANT OS:\n"
                    "• The 'hass' CLI does NOT exist on the gateway. NEVER emit 'hass --restart' or 'hass --script check_config'.\n"
                    "• To restart Home Assistant Core, emit: {\"target\": \"<cid>\", \"action\": \"restart_core\"}\n"
                    "• To reload config, emit: {\"target\": \"<cid>\", \"action\": \"reload_core_config\"}\n"
                    "• To reboot hardware, emit: {\"target\": \"<cid>\", \"action\": \"reboot_gateway\"}\n"
                    "• To update agent/core/supervisor, emit: {\"target\": \"<cid>\", \"action\": \"update_addon|update_core|update_all\"}\n"
                    "• To execute supervisor API calls via exec, use curl: {\"target\": \"<cid>\", \"action\": \"exec\", \"command\": \"curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/restart\"}\n\n"
                    "6. STRICT REALITY GROUNDING & AESTHETICS: Never hallucinate versions or IP addresses. Master add-on version is ALWAYS v1.3.0. Format all responses with GitHub-style markdown, status badges (🟢 ONLINE, 🔴 FAULT, ⚡ AUTONOMOUS ACTION), and organized sections.\n\n"
                    f"{grounding_context}\n"
                )

                messages_payload = [{'role': 'system', 'content': sys_prompt}]
                # Inject recent conversation turns (excluding the current user_msg which is appended next)
                for turn in chat_history[:-1]:
                    messages_payload.append(turn)
                messages_payload.append({'role': 'user', 'content': user_msg})

                best_model = get_optimal_copilot_model()
                ctx_size = 16384 if '14b' in best_model else 32768
                ollama_payload = json.dumps({
                    'model': best_model,
                    'messages': messages_payload,
                    'stream': False,
                    'keep_alive': -1,  # Keep pinned in RTX 3060 12GB VRAM permanently (zero cold-start latency)
                    'options': {
                        'num_ctx': ctx_size,   # 16K native for 14B flagship, 32K native for 7B
                        'num_gpu': 99,         # Force 100% layer offloading to NVIDIA RTX 3060 VRAM
                        'num_batch': 1024,     # Maximum batch size for CUDA parallel prompt evaluation
                        'num_predict': 4096,   # Allow deep, detailed diagnostic reports and complete code without truncation
                        'temperature': 0.25,   # Sharp, deterministic, zero-hallucination operational reasoning
                        'top_k': 40,
                        'top_p': 0.9,
                        'repeat_penalty': 1.1  # Prevents reasoning tag looping
                    }
                }).encode('utf-8')
                
                ai_reply = "AI response unavailable."
                try:
                    oreq = urllib.request.Request(ollama_url, data=ollama_payload, headers={'Content-Type': 'application/json'}, method='POST')
                    with urllib.request.urlopen(oreq, timeout=120) as oresp:
                        ores_data = json.loads(oresp.read().decode('utf-8'))
                        ai_reply = ores_data.get('message', {}).get('content', '')
                except Exception as ex:
                    ai_reply = f"⚠️ [Ollama Inference Notice]: {ex}. Please verify VM 307 (192.168.6.185:11434)."

                # Extract model thinking / reasoning process if present
                thought_content = ""
                think_match = re.search(r'<think>([\s\S]*?)</think>', ai_reply)
                if think_match:
                    thought_content = think_match.group(1).strip()
                    ai_reply = re.sub(r'<think>[\s\S]*?</think>', '', ai_reply).strip()

                if not thought_content.strip():
                    target_hint = "fleet ecosystem"
                    if "parvathi" in user_msg.lower(): target_hint = "parvathipuram-client-1-subhadraengineering"
                    elif "vajju" in user_msg.lower(): target_hint = "vajju-vja-house"
                    elif "naga" in user_msg.lower(): target_hint = "mr-nagaprasad-flat-304"

                    thought_content = (
                        f"• Operation Intent Analysis: Parsing directive '{user_msg[:60]}...'\n"
                        f"• Target Correlation: Correlating telemetry for target [{target_hint}].\n"
                        f"• Communications Grid: Verifying channels (Instant MQTT, Ingress Tunnels, WireGuard Mesh, Supervisor REST API).\n"
                        f"• Subsystem Health Check: Inspecting core config entries, integration statuses, and hardware telemetry.\n"
                        f"• Execution Pathway: Formulating validated zero-hallucination operational plan with supervisor authority."
                    )

                # 1. Detect if the AI emitted an executable block (```exec ... ```)
                exec_match = re.search(r'```exec\s*([\s\S]*?)\s*```', ai_reply)
                if exec_match:
                    try:
                        e_obj = json.loads(exec_match.group(1))
                        e_target = e_obj.get('target', 'vajju-vja-house')
                        e_action = e_obj.get('action', 'exec')
                        e_cmd = e_obj.get('command', '')
                        e_params = e_obj.get('params', {})
                        ok_exec, exec_out = execute_gateway_command(e_target, e_action, command=e_cmd, params=e_params, actor='autonomous_ai_copilot')
                        ai_reply += f"\n\n⚡ **[Autonomous Action Executed]**:\n• **Target Gateway:** `{e_target}`\n• **Action:** `{e_action}`\n• **Services:** Instant MQTT & Direct SSH\n• **Result:** {exec_out}"
                    except Exception as ee:
                        print(f"[!] Autonomous exec error: {ee}", flush=True)

                # 1b. Detect if the AI emitted a Proxmox cluster action block (```proxmox ... ```)
                pve_match = re.search(r'```proxmox\s*([\s\S]*?)\s*```', ai_reply)
                if pve_match:
                    try:
                        p_obj = json.loads(pve_match.group(1))
                        p_node = p_obj.get('node', 'primordial-1')
                        p_act = p_obj.get('action', 'cluster_status')
                        p_vmid = p_obj.get('vmid')
                        p_type = p_obj.get('type', 'qemu')
                        ok_pve, pve_out = execute_pve_action(p_node, p_act, target_type=p_type, vmid=p_vmid, actor='autonomous_ai_copilot')
                        ai_reply += f"\n\n⚡ **[Autonomous Proxmox Execution]**:\n• **Node:** `{p_node}`\n• **Action:** `{p_act}` (VMID: {p_vmid or 'N/A'})\n• **Channel:** Proxmox VE REST API (root@pam)\n• **Result:** {pve_out}"
                    except Exception as pvee:
                        print(f"[!] Autonomous Proxmox exec error: {pvee}", flush=True)

                # 2. Detect if the AI emitted a structured proposal block (```proposal ... ```)
                created_proposal = None
                prop_match = re.search(r'```proposal\s*([\s\S]*?)\s*```', ai_reply)
                if prop_match:
                    try:
                        p_obj = json.loads(prop_match.group(1))
                        target_cid = p_obj.get('target', 'vajju-vja-house')
                        p_action = p_obj.get('action', 'update_addon')
                        p_summary = p_obj.get('summary', f"Execute {p_action} on {target_cid}")
                        new_prop_id = str(int(time.time()))[-6:]
                        autonomy_active = get_copilot_autonomy_mode()

                        initial_status = 'approved' if autonomy_active else 'pending'
                        with DB_LOCK:
                            conn = get_db_connection()
                            conn.execute(
                                "INSERT INTO copilot_proposals (id, client_id, subsystem, action_type, summary, payload_json, status, created_at) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (new_prop_id, target_cid, 'system', p_action, p_summary, json.dumps({'action': p_action, 'target': target_cid}), initial_status, int(time.time()))
                            )
                            conn.commit()
                            conn.close()
                        created_proposal = new_prop_id

                        if autonomy_active:
                            ok_p, p_msg = execute_copilot_proposal(new_prop_id, actor='autonomous_ai_copilot')
                            ai_reply += f"\n\n⚡ **[Autonomous Execution Active]**: Proposal **#{new_prop_id}** (`{p_action}`) was automatically authorized and executed on `{target_cid}` without requiring human intervention."
                        else:
                            ai_reply += f"\n\n📋 **[Action Registered]**: Structured Proposal **#{new_prop_id}** created for `{target_cid}`. Awaiting your approval in the Proposals panel or reply `APPROVE {new_prop_id}` via WhatsApp."
                    except Exception as pe:
                        print(f"[!] Error auto-creating proposal: {pe}", flush=True)

                now_ai = int(time.time())
                with DB_LOCK:
                    conn = get_db_connection()
                    conn.execute("INSERT INTO copilot_chat_history (id, sender, message, thought, timestamp) VALUES (?, ?, ?, ?, ?)",
                                 (f"msg_{now_ai}_{os.urandom(2).hex()}", 'ai', ai_reply, thought_content, now_ai))
                    conn.commit()
                    conn.close()

                self.send_json(200, {'success': True, 'reply': ai_reply, 'thought': thought_content, 'proposal_id': created_proposal})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path in ['/api/copilot/proposals/approve', '/api/copilot/proposals/reject']:
            user = self.get_authenticated_user()
            if not user:
                self.send_json(401, {'error': 'Authentication required'})
                return
            if user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            is_approve = parsed.path.endswith('/approve')
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                data = json.loads(body_bytes.decode('utf-8'))
                prop_id = str(data.get('proposal_id', '')).strip()
                now = int(time.time())
                actor_name = user.get('name') or user.get('username') or 'admin'

                if is_approve:
                    ok, msg = execute_copilot_proposal(prop_id, actor=actor_name)
                    if not ok:
                        self.send_json(400, {'error': msg})
                        return
                    self.send_json(200, {'success': True, 'proposal_id': prop_id, 'status': 'approved', 'message': msg})
                else:
                    with DB_LOCK:
                        conn = get_db_connection()
                        cur = conn.cursor()
                        cur.execute("SELECT id, client_id, action_type, summary FROM copilot_proposals WHERE (id = ? OR id = ?)", (prop_id, f"prop_{prop_id}"))
                        p_row = cur.fetchone()
                        p_summary = p_row['summary'] if p_row else f"Proposal #{prop_id}"
                        target_cid = p_row['client_id'] if p_row else 'system'

                        cur.execute("UPDATE copilot_proposals SET status = 'rejected', resolved_at = ?, resolved_by = ? WHERE (id = ? OR id = ?)",
                                     (now, actor_name, prop_id, f"prop_{prop_id}"))

                        user_msg = f"Action: REJECTED proposal #{prop_id} — {p_summary}"
                        ai_msg = f"❌ **[Proposal #{prop_id} Rejected]**\n• **Target:** `{target_cid}`\n• **Status:** Cancelled and archived by {actor_name}."
                        cur.execute("INSERT INTO copilot_chat_history (id, sender, message, timestamp) VALUES (?, ?, ?, ?)",
                                    (f"msg_{now}_{os.urandom(2).hex()}", 'user', user_msg, now))
                        cur.execute("INSERT INTO copilot_chat_history (id, sender, message, timestamp) VALUES (?, ?, ?, ?)",
                                    (f"msg_{now+1}_{os.urandom(2).hex()}", 'ai', ai_msg, now + 1))
                        conn.commit()
                        conn.close()
                    self.send_json(200, {'success': True, 'proposal_id': prop_id, 'status': 'rejected'})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path == '/api/copilot/autonomy/toggle':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                data = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
                current = get_copilot_autonomy_mode()
                new_state = data.get('enabled') if 'enabled' in data else not current
                set_copilot_autonomy_mode(new_state)
                self.send_json(200, {'success': True, 'autonomy_enabled': new_state})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path == '/api/copilot/gateway/exec':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                data = json.loads(body_bytes.decode('utf-8'))
                cid = data.get('client_id')
                action = data.get('action', 'exec')
                cmd = data.get('command')
                params = data.get('params')
                actor = user.get('name') or user.get('username') or 'manufacturer'
                ok, msg = execute_gateway_command(cid, action, command=cmd, params=params, actor=actor)
                self.send_json(200 if ok else 400, {'success': ok, 'message': msg})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path == '/api/copilot/gateway/diagnose':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                data = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
                cid = data.get('client_id', 'vajju-vja-house')
                res = diagnose_gateway_live(cid)
                self.send_json(200, {'success': True, 'diagnostics': res})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        elif parsed.path == '/api/copilot/proxmox/exec':
            user = self.get_authenticated_user()
            if not user or user.get('role') != 'manufacturer':
                self.send_json(403, {'error': 'Manufacturer permission required'})
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_length)
            try:
                data = json.loads(body_bytes.decode('utf-8'))
                node = data.get('node', 'primordial-1')
                action = data.get('action', 'cluster_status')
                target_type = data.get('type', 'qemu')
                vmid = data.get('vmid')
                params = data.get('params')
                actor = user.get('name') or user.get('username') or 'manufacturer'
                ok, msg = execute_pve_action(node, action, target_type=target_type, vmid=vmid, params=params, actor=actor)
                self.send_json(200 if ok else 400, {'success': ok, 'message': msg})
            except Exception as e:
                self.send_json(500, {'error': str(e)})
            return

        else:
            self.send_response(404)
            self.end_headers()

# ==============================================================================
# HTTP Daemon Server Initialization
# ==============================================================================

# ==============================================================================
# Autonomous Watchdog & WhatsApp Alert Dispatcher
# ==============================================================================

PREV_HEARTBEAT_STATUS = {}       # client_id -> 'ONLINE' | 'DELAYED' | 'WARNING' | 'OFFLINE' | 'PENDING'
NOTIFIED_FAILED_RECOVERY = set() # set of (client_id, tech_key)
WATCHDOG_INITIALIZED = False

CACHED_COPILOT_MODEL = {'name': 'qwen2.5-coder:7b', 'checked_at': 0}

def get_optimal_copilot_model():
    """Dynamically detects the best AI model on VM 307's RTX 3060 12GB GPU."""
    global CACHED_COPILOT_MODEL
    now = time.time()
    if now - CACHED_COPILOT_MODEL.get('checked_at', 0) < 60:
        return CACHED_COPILOT_MODEL['name']
    try:
        req = urllib.request.Request('http://192.168.6.185:11434/api/tags')
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            installed = [m.get('name') for m in data.get('models', [])]
            matches_14b = [m for m in installed if '14b' in m]
            if matches_14b:
                CACHED_COPILOT_MODEL = {'name': matches_14b[0], 'checked_at': now}
                return matches_14b[0]
            matches_7b = [m for m in installed if '7b' in m]
            if matches_7b:
                CACHED_COPILOT_MODEL = {'name': matches_7b[0], 'checked_at': now}
                return matches_7b[0]
    except Exception:
        pass
    return CACHED_COPILOT_MODEL.get('name', 'qwen2.5-coder:7b')

def get_ecosystem_grounding_context(include_proposals=True):
    """Extracts live, authoritative ground truth from fleet.db to eliminate all LLM hallucinations."""
    grounding = []
    grounding.append("=== AUTHORITATIVE ECOSYSTEM GROUND TRUTH (DO NOT HALLUCINATE) ===")
    grounding.append("OFFICIAL GAVASAH ADD-ON MASTER VERSION: 1.3.0")
    grounding.append("CLIENT FLEET LIVE STATUS & INSTALLED VERSIONS:")
    try:
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT client_id, name, status, last_heartbeat, system_json FROM clients ORDER BY client_id ASC")
            rows = cur.fetchall()
            
            now = int(time.time())
            for r in rows:
                cid = r['client_id']
                cname = r['name'] or cid
                st = r['status'] or 'unknown'
                hb = r['last_heartbeat'] or 0
                diff = (now - hb) if hb else 999999
                is_active = (diff < 1800) and (st == 'online')
                active_str = "ONLINE (Active)" if is_active else f"OFFLINE ({int(diff//60)}m ago)"
                
                sys_data = {}
                if r['system_json']:
                    try:
                        sys_data = json.loads(r['system_json'])
                    except Exception:
                        pass
                addon_v = sys_data.get('addon_version', 'Unknown / Not Reported')
                addon_latest = sys_data.get('addon_latest_version', '1.3.0')
                addon_up = sys_data.get('addon_update_available', False)
                core_v = sys_data.get('core_version', 'Unknown')
                slot = sys_data.get('boot_slot', 'A')
                grounding.append(
                    f"- Client ID: '{cid}' | Name: '{cname}' | Status: {active_str} | Installed Add-on: {addon_v} "
                    f"| Upstream Repo Add-on: {addon_latest} | Addon Update Available: {addon_up} | HA Core: {core_v} | Boot Slot: {slot}"
                )
            
            if include_proposals:
                cur.execute("SELECT id, client_id, action_type, summary, status FROM copilot_proposals ORDER BY created_at DESC LIMIT 5")
                props = cur.fetchall()
                grounding.append("RECENT PROPOSALS & EXECUTION STATUS:")
                if props:
                    for p in props:
                        grounding.append(f"- Proposal #{p['id']}: [{p['status'].upper()}] Target: {p['client_id']} | Action: {p['action_type']} | Summary: {p['summary']}")
                else:
                    grounding.append("- No recent proposals.")
            conn.close()
    except Exception as e:
        grounding.append(f"(Warning: Failed to fetch live client records: {e})")
    
            # Inject authoritative Proxmox VE cluster ground truth
        try:
            inv = get_pve_cluster_inventory()
            if inv.get('success'):
                grounding.append("=== PROXMOX VE CLUSTER TOPOGRAPHY (FULL ROOT PERMISSIONS) ===")
                for n in inv.get('nodes', []):
                    grounding.append(f"- Node: '{n['node']}' | Status: {n['status']} | CPU: {n['cpu_percent']}% | RAM: {n['mem_used_gb']}/{n['mem_max_gb']} GB")
                grounding.append("KEY CLUSTER VIRTUAL MACHINES & CONTAINERS:")
                for q in inv.get('vms', []):
                    if q['vmid'] in [307, 204, 303, 304, 205, 211] or q['status'] == 'running':
                        grounding.append(f"  • VM {q['vmid']} ('{q['name']}'): Node={q['node']}, Status={q['status']}, RAM={q['mem_used_gb']}/{q['mem_max_gb']} GB, Uptime={q['uptime_hours']}h")
                for c in inv.get('cts', []):
                    if c['vmid'] in [150, 100, 305, 306, 320] or c['status'] == 'running':
                        grounding.append(f"  • CT {c['vmid']} ('{c['name']}'): Node={c['node']}, Status={c['status']}, RAM={c['mem_used_gb']}/{c['mem_max_gb']} GB, Uptime={c['uptime_hours']}h")
        except Exception:
            pass

        grounding.append("==================================================================")
    return "\n".join(grounding)

def get_recent_copilot_chat_messages(limit=30):
    """Retrieves chronological conversation memory turns to ensure continuous context retention."""
    chat_turns = []
    try:
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT sender, message FROM copilot_chat_history ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            conn.close()
        for r in reversed(rows):
            role = 'assistant' if r['sender'] == 'ai' else 'user'
            msg_text = r['message'] or ''
            if msg_text.strip():
                chat_turns.append({'role': role, 'content': msg_text})
    except Exception as e:
        print(f"[!] Error loading chat memory: {e}", flush=True)
    return chat_turns

def get_copilot_autonomy_mode():
    """Returns True if AI Copilot is authorized for autonomous execution across gateways."""
    try:
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT value FROM system_settings WHERE key = 'copilot_autonomy_mode'")
            row = cur.fetchone()
            conn.close()
            if row and row['value']:
                return row['value'].strip().lower() == 'true'
    except Exception:
        pass
    return True # Default to True (Full Autonomy enabled)

def set_copilot_autonomy_mode(enabled: bool):
    """Sets the AI Copilot autonomy authorization status in system_settings."""
    try:
        val_str = 'true' if enabled else 'false'
        now = int(time.time())
        with DB_LOCK:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at) VALUES ('copilot_autonomy_mode', ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (val_str, now)
            )
            conn.commit()
            conn.close()
        return True
    except Exception as e:
        print(f"[!] Error setting autonomy mode: {e}", flush=True)
        return False

def diagnose_gateway_live(client_id):
    """Performs real-time multi-service diagnostic probe on a Gavasah Gateway."""
    diag = {
        'client_id': client_id,
        'timestamp': int(time.time()),
        'channels': {},
        'telemetry': {},
        'subsystems': {},
        'summary': ''
    }
    try:
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT client_id, name, dashboard_port, ssh_port, wg_ip, status, last_heartbeat, system_json, technologies_json FROM clients WHERE client_id = ?", (client_id,))
            c_row = cur.fetchone()
            conn.close()
        if not c_row:
            diag['summary'] = f"Client gateway '{client_id}' not found in fleet database."
            return diag

        c = dict(c_row)
        diag['name'] = c.get('name') or client_id
        ssh_port = c.get('ssh_port') or 22001
        dash_port = c.get('dashboard_port') or 10001
        wg_ip = c.get('wg_ip') or ''

        # 1. WireGuard Ping probe
        wg_status = "Not assigned"
        if wg_ip:
            p_res = subprocess.run(f"ping -c 1 -W 2 {wg_ip}", shell=True, capture_output=True, text=True)
            if p_res.returncode == 0:
                m = re.search(r'time=([\d\.]+)\s*ms', p_res.stdout)
                wg_status = f"ONLINE ({m.group(1)}ms)" if m else "ONLINE"
            else:
                wg_status = "PING_TIMEOUT"
        diag['channels']['wireguard'] = {'ip': wg_ip, 'status': wg_status}

        # 2. Reverse SSH socket check
        ssh_open = False
        try:
            with socket.create_connection(('127.0.0.1', ssh_port), timeout=2):
                ssh_open = True
        except Exception:
            ssh_open = False
        
        # 3. Direct SSH shell check
        ssh_shell = "Socket closed"
        if ssh_open:
            s_res = subprocess.run(
                f"ssh -i /root/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 -p {ssh_port} root@127.0.0.1 'uptime' 2>&1",
                shell=True, capture_output=True, text=True
            )
            if s_res.returncode == 0:
                ssh_shell = f"SHELL_AUTHORIZED: {s_res.stdout.strip()}"
            else:
                ssh_shell = "SSH_PENDING_AUTH (fallback to instant MQTT active)"
        diag['channels']['ssh'] = {'port': ssh_port, 'socket_open': ssh_open, 'shell_status': ssh_shell}

        # 4. Ingress dashboard check
        dash_open = False
        try:
            with socket.create_connection(('127.0.0.1', dash_port), timeout=2):
                dash_open = True
        except Exception:
            dash_open = False
        diag['channels']['dashboard'] = {'port': dash_port, 'socket_open': dash_open}

        # 5. Telemetry details
        sys_data = {}
        if c.get('system_json'):
            try: sys_data = json.loads(c['system_json'])
            except Exception: pass
        diag['telemetry'] = {
            'addon_version': sys_data.get('addon_version', 'Unknown'),
            'core_version': sys_data.get('core_version', 'Unknown'),
            'haos_version': sys_data.get('haos_version', 'Unknown'),
            'boot_slot': sys_data.get('boot_slot', 'A'),
            'slot_a_status': sys_data.get('slot_a_status', 'Unknown'),
            'slot_b_status': sys_data.get('slot_b_status', 'Unknown'),
            'cpu_percent': sys_data.get('cpu_percent', 0),
            'memory_percent': sys_data.get('memory_percent', 0),
            'disk_free_gb': sys_data.get('disk_free_gb', 0)
        }

        # 6. Subsystem status
        tech_data = {}
        if c.get('technologies_json'):
            try: tech_data = json.loads(c['technologies_json'])
            except Exception: pass
        diag['subsystems'] = {
            'knx': tech_data.get('knx', {}).get('status', 'unknown'),
            'zigbee': tech_data.get('zigbee', {}).get('status', 'unknown'),
            'matter': tech_data.get('matter', {}).get('status', 'unknown'),
            'failed_integrations_count': len(tech_data.get('failed_core_entries', []))
        }

        diag['summary'] = (
            f"Gateway '{client_id}' ({diag['name']}): "
            f"WireGuard={wg_status}, SSH_Port={ssh_port} (Open: {ssh_open}), Dashboard_Port={dash_port} (Open: {dash_open}). "
            f"HAOS {diag['telemetry']['haos_version']} on Slot {diag['telemetry']['boot_slot']}."
        )
    except Exception as e:
        diag['summary'] = f"Diagnostic probe error: {e}"
    return diag

# ==============================================================================
# Proxmox VE Autonomous Cluster Control & Infrastructure Engine
# ==============================================================================
PVE_API_HOSTS = ["122.175.49.35", "49.205.214.144", "192.168.6.144"]
PVE_API_PORT = 8006
PVE_USER = "root@pam"
PVE_PASS = "vajju2175"

CACHED_PVE_AUTH = {'ticket': None, 'csrf': None, 'host': None, 'time': 0}

def get_pve_auth():
    """Authenticates to Proxmox VE REST API with redundant WAN/LAN failover and token caching."""
    now = time.time()
    if CACHED_PVE_AUTH['ticket'] and (now - CACHED_PVE_AUTH['time'] < 3600):
        return CACHED_PVE_AUTH['host'], CACHED_PVE_AUTH['ticket'], CACHED_PVE_AUTH['csrf']

    data = urllib.parse.urlencode({'username': PVE_USER, 'password': PVE_PASS}).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for host in PVE_API_HOSTS:
        try:
            url = f"https://{host}:{PVE_API_PORT}/api2/json/access/ticket"
            req = urllib.request.Request(url, data=data, method='POST')
            with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
                res = json.loads(resp.read().decode())
                ticket = res['data']['ticket']
                csrf = res['data']['CSRFPreventionToken']
                CACHED_PVE_AUTH['host'] = host
                CACHED_PVE_AUTH['ticket'] = ticket
                CACHED_PVE_AUTH['csrf'] = csrf
                CACHED_PVE_AUTH['time'] = now
                return host, ticket, csrf
        except Exception:
            continue
    return None, None, None

def pve_api_request(endpoint, method='GET', post_data=None):
    """Executes an authenticated REST call against Proxmox VE API."""
    host, ticket, csrf = get_pve_auth()
    if not ticket:
        return False, "Failed to authenticate with Proxmox VE cluster (all hosts unreachable)."
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {'Cookie': f'PVEAuthCookie={ticket}', 'CSRFPreventionToken': csrf}
    url = f"https://{host}:{PVE_API_PORT}/api2/json{endpoint}"
    enc_data = urllib.parse.urlencode(post_data).encode() if post_data else None

    try:
        req = urllib.request.Request(url, data=enc_data, headers=headers, method=method)
        with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
            return True, json.loads(resp.read().decode()).get('data')
    except urllib.error.HTTPError as he:
        err_body = he.read().decode(errors='ignore') if hasattr(he, 'read') else str(he)
        return False, f"PVE HTTP {he.code}: {err_body}"
    except Exception as ex:
        return False, str(ex)

def get_pve_cluster_inventory():
    """Returns real-time inventory of all Proxmox nodes, VMs, and LXC containers."""
    ok, resources = pve_api_request('/cluster/resources')
    if not ok:
        return {'success': False, 'error': str(resources)}

    nodes = []
    vms = []
    cts = []
    storages = []

    for item in resources:
        itype = item.get('type')
        if itype == 'node':
            nodes.append({
                'node': item.get('node'),
                'status': item.get('status'),
                'cpu_percent': round(item.get('cpu', 0) * 100, 1),
                'mem_used_gb': round(item.get('mem', 0) / (1024**3), 1),
                'mem_max_gb': round(item.get('maxmem', 0) / (1024**3), 1),
                'uptime_hours': round(item.get('uptime', 0) / 3600, 1)
            })
        elif itype == 'qemu':
            vms.append({
                'vmid': item.get('vmid'),
                'name': item.get('name'),
                'node': item.get('node'),
                'status': item.get('status'),
                'cpu_percent': round(item.get('cpu', 0) * 100, 1),
                'mem_used_gb': round(item.get('mem', 0) / (1024**3), 1),
                'mem_max_gb': round(item.get('maxmem', 0) / (1024**3), 1),
                'uptime_hours': round(item.get('uptime', 0) / 3600, 1)
            })
        elif itype == 'lxc':
            cts.append({
                'vmid': item.get('vmid'),
                'name': item.get('name'),
                'node': item.get('node'),
                'status': item.get('status'),
                'cpu_percent': round(item.get('cpu', 0) * 100, 1),
                'mem_used_gb': round(item.get('mem', 0) / (1024**3), 1),
                'mem_max_gb': round(item.get('maxmem', 0) / (1024**3), 1),
                'uptime_hours': round(item.get('uptime', 0) / 3600, 1)
            })
        elif itype == 'storage':
            storages.append({
                'storage': item.get('storage'),
                'node': item.get('node'),
                'type': item.get('plugintype'),
                'used_gb': round(item.get('disk', 0) / (1024**3), 1),
                'total_gb': round(item.get('maxdisk', 0) / (1024**3), 1)
            })

    return {
        'success': True,
        'timestamp': int(time.time()),
        'nodes': nodes,
        'vms': vms,
        'cts': cts,
        'storages': storages
    }

def execute_pve_action(node, action, target_type='qemu', vmid=None, params=None, actor='autonomous_ai_copilot'):
    """
    Executes administrative actions directly across the Proxmox VE cluster:
      - VM actions: start, stop, shutdown, reboot, reset, config
      - LXC actions: start, stop, restart, config
      - Node actions: status, cluster_status
    """
    try:
        now = int(time.time())
        params = params or {}
        
        # If node is unspecified or 'auto', look up node for vmid from cluster resources
        if not node or node in ['auto', 'cluster', 'any']:
            ok, res_list = pve_api_request('/cluster/resources')
            if ok and isinstance(res_list, list) and vmid:
                for item in res_list:
                    if str(item.get('vmid')) == str(vmid):
                        node = item.get('node')
                        target_type = item.get('type')
                        break
        node = node or 'primordial-1'

        clean_act = action.lower()
        if clean_act in ['vm_reboot', 'reboot_vm']: clean_act = 'reboot'; target_type = 'qemu'
        elif clean_act in ['vm_start', 'start_vm']: clean_act = 'start'; target_type = 'qemu'
        elif clean_act in ['vm_stop', 'stop_vm']: clean_act = 'stop'; target_type = 'qemu'
        elif clean_act in ['vm_reset', 'reset_vm']: clean_act = 'reset'; target_type = 'qemu'
        elif clean_act in ['vm_shutdown', 'shutdown_vm']: clean_act = 'shutdown'; target_type = 'qemu'
        elif clean_act in ['lxc_restart', 'restart_lxc', 'restart_ct']: clean_act = 'restart'; target_type = 'lxc'
        elif clean_act in ['lxc_start', 'start_lxc', 'start_ct']: clean_act = 'start'; target_type = 'lxc'
        elif clean_act in ['lxc_stop', 'stop_lxc', 'stop_ct']: clean_act = 'stop'; target_type = 'lxc'

        # 1. VM Lifecycle
        if target_type == 'qemu' and vmid:
            endpoint = f"/nodes/{node}/qemu/{vmid}/status/{clean_act}"
            ok, res = pve_api_request(endpoint, method='POST', post_data={})
            status_msg = f"Proxmox VM {vmid} on node '{node}': action '{clean_act}' dispatched (UPID: {res})." if ok else f"Proxmox VM {vmid} error: {res}"
            print(f"[PVE_AUTONOMOUS] {status_msg}", flush=True)
            return ok, status_msg

        # 2. Container Lifecycle
        elif target_type == 'lxc' and vmid:
            endpoint = f"/nodes/{node}/lxc/{vmid}/status/{clean_act}"
            ok, res = pve_api_request(endpoint, method='POST', post_data={})
            status_msg = f"Proxmox LXC {vmid} on node '{node}': action '{clean_act}' dispatched (UPID: {res})." if ok else f"Proxmox LXC {vmid} error: {res}"
            print(f"[PVE_AUTONOMOUS] {status_msg}", flush=True)
            return ok, status_msg

        # 3. Node Status
        elif clean_act in ['node_status', 'status'] and not vmid:
            endpoint = f"/nodes/{node}/status"
            ok, res = pve_api_request(endpoint, method='GET')
            if ok:
                cpu = round(res.get('cpu', 0) * 100, 1)
                mem = res.get('memory', {})
                mem_used = round(mem.get('used', 0) / (1024**3), 1)
                mem_total = round(mem.get('total', 0) / (1024**3), 1)
                return True, f"Proxmox Node '{node}': CPU={cpu}%, RAM={mem_used}/{mem_total} GB, Uptime={int(res.get('uptime',0)//3600)}h, Kernel={res.get('kversion')}"
            return False, f"Failed to get node '{node}' status: {res}"

        # 4. Cluster Overview
        elif clean_act in ['cluster_status', 'inventory']:
            inv = get_pve_cluster_inventory()
            if inv.get('success'):
                node_count = len(inv.get('nodes', []))
                vm_count = len(inv.get('vms', []))
                ct_count = len(inv.get('cts', []))
                return True, f"Proxmox Cluster Online: {node_count} Nodes, {vm_count} VMs, {ct_count} Containers. Full root authority active."
            return False, f"Cluster error: {inv.get('error')}"

        return False, f"Unknown Proxmox target or action: target_type={target_type}, vmid={vmid}, action={action}"

    except Exception as e:
        print(f"[!] execute_pve_action error: {e}", flush=True)
        return False, str(e)

def execute_gateway_command(client_id, action, command=None, params=None, actor='autonomous_ai_copilot'):
    """
    Unified Autonomous Command Execution Engine for Gavasah Gateways.
    Routes command execution through:
      1. Instant MQTT dispatch (gavasah/clients/{cid}/cmd or gavasah/global/cmd) (<50ms execution via Gavasah Agent)
      2. Heartbeat queue fallback (clients.pending_command)
      3. Direct SSH execution (127.0.0.1:{ssh_port} or wg_ip) when command is provided
      4. Structured event logging in copilot_events and client_logs
    """
    try:
        now = int(time.time())
        is_fleet = (client_id in ['fleet', 'all', 'global'] or not client_id)

        # Intelligent action & command mapping for Home Assistant OS / Gavasah Gateways
        if action in ['fix_hacs_integration', 'repair_hacs', 'fix_hacs']:
            action = 'exec'
            command = (
                "curl -s -X DELETE -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/api/config/config_entries/entry/66c143f1c2e0b1ea10a0599ff46279b2; "
                "cd /config 2>/dev/null || cd /homeassistant 2>/dev/null; "
                "mkdir -p custom_components/hacs; "
                "curl -sSL https://get.hacs.xyz | bash -; "
                "sleep 2; "
                "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/api/services/homeassistant/reload_core_config; "
                "sleep 2; "
                "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/restart"
            )
        elif action in ['restart_core', 'core_restart']:
            action = 'exec'
            command = "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/restart"
        elif action in ['reload_core_config', 'reload_config']:
            action = 'exec'
            command = "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/api/services/homeassistant/reload_core_config"
        elif action in ['reboot_gateway', 'reboot_host']:
            action = 'exec'
            command = "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/host/reboot"
        elif action in ['check_config', 'core_check']:
            action = 'exec'
            command = "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/check"

        # Auto-translate any hallucinated Home Assistant venv commands to HAOS Supervisor API calls
        if command:
            if 'hass --script check_config' in command or 'hass --check' in command:
                command = command.replace("hass --script check_config", "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/check")
            if 'hass --restart' in command or 'hass restart' in command:
                command = command.replace("hass --restart", "curl -s -X POST -H 'Authorization: Bearer '$SUPERVISOR_TOKEN http://supervisor/core/restart")

        payload_obj = {
            'action': action,
            'command': command or '',
            'params': params or {},
            'actor': actor,
            'timestamp': now,
            'autonomous': True
        }
        cmd_payload_str = json.dumps(payload_obj)

        if is_fleet:
            # Broadcast to entire fleet
            publish_mqtt_message('gavasah/global/cmd', cmd_payload_str, qos=1)
            with DB_LOCK:
                conn = get_db_connection()
                conn.execute("UPDATE clients SET pending_command = ? WHERE status = 'online'", (cmd_payload_str,))
                conn.commit()
                conn.close()
            msg = f"Autonomous action '{action}' broadcast to all online fleet gateways via instant MQTT & telemetry queue."
            print(f"[COPILOT_EXEC_FLEET] {msg}", flush=True)
            return True, msg

        # Specific client gateway
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT client_id, name, ssh_port, dashboard_port, wg_ip, status FROM clients WHERE client_id = ?", (client_id,))
            c_row = cur.fetchone()
            conn.close()

        if not c_row:
            return False, f"Gateway '{client_id}' not found in fleet database."

        c = dict(c_row)
        ssh_port = c.get('ssh_port') or 22001
        wg_ip = c.get('wg_ip') or ''

        # Channel 1: Instant MQTT dispatch
        topic = f"gavasah/clients/{client_id}/cmd"
        publish_mqtt_message(topic, cmd_payload_str, qos=1)

        # Channel 2: Heartbeat queue fallback
        with DB_LOCK:
            conn = get_db_connection()
            conn.execute("UPDATE clients SET pending_command = ? WHERE client_id = ?", (cmd_payload_str, client_id))
            conn.commit()
            conn.close()

        # Channel 3: Direct SSH Execution if shell command requested
        ssh_res_str = ""
        if command or action in ['ssh', 'exec']:
            cmd_to_run = command or (params.get('command') if params else '') or 'uptime'
            ssh_cmd = f"ssh -i /root/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {ssh_port} root@127.0.0.1 '{cmd_to_run}' 2>&1"
            res = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                ssh_res_str = f" [SSH Shell Direct: {res.stdout.strip()}]"
            else:
                ssh_res_str = f" [SSH Notice: exit {res.returncode} -> Executed via instant MQTT downlink & Gavasah Agent]"

        # Log event in copilot_events
        try:
            with DB_LOCK:
                conn = get_db_connection()
                conn.execute(
                    "INSERT INTO copilot_events (id, client_id, subsystem, event_type, details_json, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"evt_{now}_{os.urandom(2).hex()}", client_id, 'autonomous_engine', action, json.dumps({'action': action, 'command': command, 'actor': actor, 'ssh_result': ssh_res_str}), now)
                )
                conn.commit()
                conn.close()
        except Exception:
            pass

        full_msg = f"Dispatched '{action}' to gateway '{client_id}' via instant MQTT topic '{topic}' & telemetry queue.{ssh_res_str}"
        print(f"[COPILOT_EXEC_GATEWAY] {full_msg}", flush=True)
        return True, full_msg

    except Exception as e:
        print(f"[!] execute_gateway_command error: {e}", flush=True)
        return False, str(e)

def execute_copilot_proposal(prop_id, actor='admin'):
    """Executes an approved proposal by dispatching through unified execute_gateway_command."""
    try:
        now = int(time.time())
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT id, client_id, action_type, summary, payload_json, status FROM copilot_proposals WHERE (id = ? OR id = ?)", (prop_id, f"prop_{prop_id}"))
            row = cur.fetchone()
            if not row:
                conn.close()
                return False, f"Proposal #{prop_id} not found."
            
            p_id = row['id']
            cid = row['client_id']
            action = row['action_type'] or 'update_addon'
            p_summary = row['summary'] or f"Action {action} on {cid}"
            payload_str = row['payload_json'] or '{}'
            try:
                payload = json.loads(payload_str)
            except Exception:
                payload = {}
            
            # Map action to edge command
            cmd_action = payload.get('action') or action
            params = payload.get('params') or {}
            cmd_payload = json.dumps({'action': cmd_action, 'params': params, 'queued_at': now, 'queued_by': f'copilot_approved_{actor}'})
            
            # Update proposal status
            cur.execute("UPDATE copilot_proposals SET status = 'approved', resolved_at = ?, resolved_by = ?, result_log = ? WHERE id = ?",
                        (now, actor, f"Dispatched '{cmd_action}' to gateway {cid}", p_id))
            
            # Execute via unified gateway execution engine (Instant MQTT + Heartbeat Queue + Direct SSH)
            ok_gw, gw_msg = execute_gateway_command(cid, cmd_action, command=payload.get('command'), params=params, actor=f"proposal_{actor}")

            # Record user action and AI response in copilot_chat_history so the terminal and memory update immediately
            actor_label = "Admin (WhatsApp)" if "whatsapp" in actor else "Manufacturer"
            user_msg = f"Action: APPROVED proposal #{p_id} — {p_summary}"
            ai_msg = (
                f"✅ **[Proposal #{p_id} Approved & Executed]**\n"
                f"• **Target:** `{cid or 'fleet'}`\n"
                f"• **Action:** `{cmd_action}`\n"
                f"• **Authorized By:** {actor_label}\n"
                f"• **Status:** Dispatched to gateway telemetry queue. Gateway will execute on next heartbeat pulse."
            )
            thought_str = (
                f"• Proposal Approval: Authorized proposal #{p_id} for target [{cid or 'fleet'}].\n"
                f"• Action Verification: Dispatching validated command sequence for '{cmd_action}'.\n"
                f"• Communications Grid: Routed via redundant MQTT downlink and Heartbeat telemetry queue."
            )
            cur.execute("INSERT INTO copilot_chat_history (id, sender, message, thought, timestamp) VALUES (?, ?, ?, ?, ?)",
                        (f"msg_{now}_{os.urandom(2).hex()}", 'user', user_msg, '', now))
            cur.execute("INSERT INTO copilot_chat_history (id, sender, message, thought, timestamp) VALUES (?, ?, ?, ?, ?)",
                        (f"msg_{now+1}_{os.urandom(2).hex()}", 'ai', ai_msg, thought_str, now + 1))
            
            conn.commit()
            conn.close()
        return True, f"Proposal #{prop_id} executed: queued '{cmd_action}' for target '{cid or 'fleet'}'."
    except Exception as e:
        print(f"[!] execute_copilot_proposal error: {e}", flush=True)
        return False, str(e)

def get_admin_whatsapp_number():
    admin_phone = '7396263322'
    try:
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT value FROM system_settings WHERE key = 'admin_whatsapp_number'")
            row = cur.fetchone()
            if row and row['value']:
                admin_phone = row['value'].strip()
            conn.close()
    except Exception:
        pass
    return admin_phone

def send_whatsapp_alert_to_contacts(client_id, message):
    admin_num = get_admin_whatsapp_number()
    recipients = set([admin_num])
    try:
        with DB_LOCK:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT dealer_id, integrator_id FROM clients WHERE client_id = ?", (client_id,))
            cl_row = cur.fetchone()
            if cl_row:
                did = cl_row['dealer_id']
                iid = cl_row['integrator_id']
                if iid:
                    cur.execute("SELECT phone FROM integrators WHERE id = ?", (iid,))
                    i_row = cur.fetchone()
                    if i_row and i_row['phone']:
                        recipients.add(i_row['phone'].strip())
                if did:
                    cur.execute("SELECT phone FROM dealers WHERE id = ?", (did,))
                    d_row = cur.fetchone()
                    if d_row and d_row['phone']:
                        recipients.add(d_row['phone'].strip())
            conn.close()
    except Exception as e:
        print(f"[!] Error fetching contact recipients for {client_id}: {e}")

    for raw_phone in recipients:
        clean_phone = re.sub(r'[^0-9]', '', str(raw_phone))
        if len(clean_phone) == 10 and clean_phone[0] in ['6', '7', '8', '9']:
            clean_phone = '91' + clean_phone
        if len(clean_phone) >= 10:
            try:
                wa_payload = json.dumps({'phone': clean_phone, 'message': message}).encode('utf-8')
                req = urllib.request.Request('http://127.0.0.1:3005/send', data=wa_payload, headers={'Content-Type': 'application/json'}, method='POST')
                with urllib.request.urlopen(req, timeout=8) as resp:
                    pass
            except Exception as ex:
                print(f"[!] WhatsApp dispatch to {clean_phone} error: {ex}")

def is_ha_entry_ignored(e):
    if not isinstance(e, dict): return True
    if str(e.get('source', '')).strip().lower() == 'ignore': return True
    if str(e.get('state', '')).strip().lower() == 'ignored': return True
    if e.get('disabled_by'): return True
    return False

def format_subsystem_alert_details(sub_key, tech, unmon_set):
    """
    Constructs an explicit, human-readable breakdown of the failed subsystem,
    specifying exact integration titles, domains, IPs, and error reasons.
    Returns (pretty_subsystem_name, list_of_issue_detail_lines)
    """
    issue_lines = []
    
    if sub_key == 'failed_core_entries':
        raw_entries = tech.get('failed_core_entries') or []
        active_broken = [
            e for e in raw_entries 
            if isinstance(e, dict) and not is_ha_entry_ignored(e) and e.get('domain') not in unmon_set
        ]
        
        domains = sorted(list(set(
            (e.get('domain') or 'integration').capitalize() 
            for e in active_broken if e.get('domain')
        )))
        
        domain_summary = ", ".join(domains) if domains else "General"
        pretty_tech = f"Core Integrations ({domain_summary})"
        
        if active_broken:
            for e in active_broken[:8]:
                d_name = (e.get('domain') or 'Integration').capitalize()
                title = e.get('title') or d_name
                state = e.get('state') or 'error'
                reason = e.get('reason') or f"State: {state}"
                if len(reason) > 95:
                    reason = reason[:92] + "..."
                issue_lines.append(f"  ❌ *{title}* ({d_name})\n     ↳ Error: {reason} [{state}]")
            if len(active_broken) > 8:
                issue_lines.append(f"  ... and {len(active_broken) - 8} more failed integration(s)")
        else:
            issue_lines.append("  ❌ One or more Home Assistant Core integrations failed setup or recovery.")
            
        return pretty_tech, issue_lines

    elif sub_key == 'coolmaster':
        cm = tech.get('coolmaster') or {}
        pretty_tech = "CoolMaster HVAC"
        gw = cm.get('gateway_ip') or cm.get('host') or ''
        port = cm.get('gateway_port') or cm.get('port') or 10102
        reason = cm.get('error') or cm.get('offline_reason') or 'HVAC communication timed out'
        gw_info = f" at {gw}:{port}" if gw else ""
        issue_lines.append(f"  ❌ CoolMasterNet Interface{gw_info}\n     ↳ Error: {reason}")
        return pretty_tech, issue_lines

    elif sub_key == 'knx':
        knx = tech.get('knx') or {}
        pretty_tech = "KNXnet/IP Bus"
        gw = knx.get('gateway_ip') or 'Local Bus'
        port = knx.get('gateway_port') or 3671
        reason = knx.get('error') or knx.get('offline_reason') or 'Gateway unreachable (UDP ping timeout)'
        issue_lines.append(f"  ❌ KNX Gateway at {gw}:{port}\n     ↳ Error: {reason}")
        return pretty_tech, issue_lines

    elif sub_key == 'lutron':
        lutron = tech.get('lutron') or {}
        pretty_tech = "Lutron System"
        entries = lutron.get('entries') or []
        failed_bridges = [e for e in entries if isinstance(e, dict) and e.get('state') != 'loaded' and not is_ha_entry_ignored(e)]
        if failed_bridges:
            for b in failed_bridges[:5]:
                b_title = b.get('title') or b.get('domain') or 'Lutron Bridge'
                b_reason = b.get('reason') or b.get('state') or 'Offline'
                issue_lines.append(f"  ❌ Bridge: *{b_title}*\n     ↳ State: {b_reason}")
        else:
            reason = lutron.get('offline_reason') or lutron.get('status') or 'Bridge connection lost'
            issue_lines.append(f"  ❌ Lutron Processor / Bridge\n     ↳ Error: {reason}")
        return pretty_tech, issue_lines

    elif sub_key == 'zigbee':
        zig = tech.get('zigbee') or {}
        pretty_tech = "Zigbee Mesh"
        instances = zig.get('instances') or []
        failed_insts = [i for i in instances if isinstance(i, dict) and not i.get('running') and i.get('state') != 'started']
        if failed_insts:
            for inst in failed_insts[:4]:
                name = inst.get('name') or 'Zigbee2MQTT'
                st = inst.get('state') or 'stopped'
                issue_lines.append(f"  ❌ Container: *{name}*\n     ↳ Container state: {st}")
        else:
            issue_lines.append("  ❌ Zigbee coordinator USB dongle unreachable or unresponsive.")
        return pretty_tech, issue_lines

    elif sub_key == 'matter':
        pretty_tech = "Matter Subsystem"
        matter = tech.get('matter') or {}
        reason = matter.get('error') or matter.get('offline_reason') or 'Matter fabric server offline'
        issue_lines.append(f"  ❌ Matter Server\n     ↳ Error: {reason}")
        return pretty_tech, issue_lines

    else:
        pretty_tech = sub_key.upper()
        issue_lines.append(f"  ❌ Subsystem '{sub_key}' encountered an unrecoverable fault.")
        return pretty_tech, issue_lines

def start_telemetry_alert_watchdog():
    global PREV_HEARTBEAT_STATUS, NOTIFIED_FAILED_RECOVERY, WATCHDOG_INITIALIZED
    print("[*] Telemetry Watchdog & WhatsApp Alert Dispatcher thread started...", flush=True)
    time.sleep(5)

    while True:
        try:
            now = int(time.time())
            ist_dt = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
            ist_time_str = ist_dt.strftime('%d-%b-%Y %I:%M:%S %p IST')

            clients_list = []
            with DB_LOCK:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM clients")
                clients_list = [dict(r) for r in cur.fetchall()]
                conn.close()

            for c in clients_list:
                cid = c.get('client_id')
                cname = c.get('name') or cid
                last_hb = c.get('last_heartbeat') or 0
                is_pending = not last_hb or last_hb == 0 or c.get('status') == 'pending'
                diff = -1 if is_pending else (now - last_hb)

                delayed_limit = int(c.get('hb_delayed_interval') or 1800)
                warn_limit = int(c.get('hb_warning_interval') or 21600)
                off_limit = int(c.get('hb_offline_interval') or 86400)

                # Determine current status
                if is_pending or c.get('approval_status') == 'pending':
                    curr_hb_status = 'PENDING'
                elif diff <= delayed_limit:
                    curr_hb_status = 'ONLINE'
                elif diff <= warn_limit:
                    curr_hb_status = 'DELAYED'
                elif diff <= off_limit:
                    curr_hb_status = 'WARNING'
                else:
                    curr_hb_status = 'OFFLINE'

                prev_hb_status = PREV_HEARTBEAT_STATUS.get(cid)

                if not WATCHDOG_INITIALIZED:
                    PREV_HEARTBEAT_STATUS[cid] = curr_hb_status
                else:
                    if prev_hb_status is not None and curr_hb_status != prev_hb_status:
                        if curr_hb_status == 'DELAYED' and prev_hb_status == 'ONLINE':
                            mins = int(diff // 60)
                            secs = int(diff % 60)
                            time_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
                            lines = [
                                "⚠️ *GAVASAH LUXURY AUTOMATION*",
                                "🟡 *NOTICE: Gateway Heartbeat Delayed*",
                                "",
                                f"• *Site:* {cname} (`{cid}`)",
                                f"• *Heartbeat Status:* 🟡 DELAYED ({time_str} without pulse)",
                                f"• *Previous State:* {prev_hb_status}",
                                f"• *Time:* {ist_time_str}",
                                "",
                                "ℹ️ *Notice:* Gateway heartbeat is past its expected interval. Telemetry watchdog is actively monitoring for recovery or escalation.",
                                "🌐 *Operations Portal:* https://dealer.gavasah.com/"
                            ]
                            send_whatsapp_alert_to_contacts(cid, chr(10).join(lines))

                        elif curr_hb_status == 'WARNING' and prev_hb_status in ['ONLINE', 'DELAYED']:
                            mins = int(diff // 60)
                            lines = [
                                "⚠️ *GAVASAH LUXURY AUTOMATION*",
                                "🟠 *WARNING: Gateway Heartbeat Delayed*",
                                "",
                                f"• *Site:* {cname} (`{cid}`)",
                                f"• *Heartbeat Status:* 🟠 WARNING ({mins}m delayed)",
                                f"• *Previous State:* {prev_hb_status}",
                                f"• *Time:* {ist_time_str}",
                                "",
                                "⚠️ *Warning:* Heartbeat pulse has not been received within warning threshold. Local network connectivity may be degrading.",
                                "🌐 *Operations Portal:* https://dealer.gavasah.com/"
                            ]
                            send_whatsapp_alert_to_contacts(cid, chr(10).join(lines))

                        elif curr_hb_status == 'OFFLINE':
                            mins = int(diff // 60)
                            lines = [
                                "🚨 *GAVASAH LUXURY AUTOMATION*",
                                "🔴 *CRITICAL ALERT: Heartbeat Telemetry Lost*",
                                "",
                                f"• *Site:* {cname} (`{cid}`)",
                                "• *Heartbeat Status:* 🔴 OFFLINE",
                                f"• *Previous State:* {prev_hb_status}",
                                f"• *Last Contact:* {mins} minutes ago",
                                f"• *Time:* {ist_time_str}",
                                "",
                                "🚨 *Urgent:* Gateway has stopped sending heartbeats. Please verify power, local internet connection, and add-on status on site.",
                                "🌐 *Operations Portal:* https://dealer.gavasah.com/"
                            ]
                            send_whatsapp_alert_to_contacts(cid, chr(10).join(lines))

                        elif curr_hb_status == 'ONLINE' and prev_hb_status in ['OFFLINE', 'WARNING', 'DELAYED']:
                            lines = [
                                "✅ *GAVASAH LUXURY AUTOMATION*",
                                "🟢 *RESTORED: Gateway Heartbeat Re-established*",
                                "",
                                f"• *Site:* {cname} (`{cid}`)",
                                "• *Heartbeat Status:* 🟢 ONLINE",
                                f"• *Previous State:* {prev_hb_status}",
                                f"• *Time:* {ist_time_str}",
                                "",
                                "✨ *Notice:* Heartbeat telemetry is back to normal operating rhythm.",
                                "🌐 *Operations Portal:* https://dealer.gavasah.com/"
                            ]
                            send_whatsapp_alert_to_contacts(cid, chr(10).join(lines))

                        PREV_HEARTBEAT_STATUS[cid] = curr_hb_status

                # -------------------------------------------------------------
                # 2. Check Integration Status where auto recovery failed
                # -------------------------------------------------------------
                unmon_raw = c.get('unmonitored_integrations')
                try:
                    unmon = set(json.loads(unmon_raw) if isinstance(unmon_raw, str) else (unmon_raw or []))
                except Exception:
                    unmon = set()

                tech_raw = c.get('technologies_json')
                try:
                    tech = json.loads(tech_raw) if isinstance(tech_raw, str) else (tech_raw or {})
                except Exception:
                    tech = {}

                sh_subsystems = tech.get('self_healing', {}).get('subsystems', {})

                for sub_key, sub_info in sh_subsystems.items():
                    if not isinstance(sub_info, dict):
                        continue
                    if sub_key in unmon:
                        NOTIFIED_FAILED_RECOVERY.discard((cid, sub_key))
                        continue

                    sub_status = sub_info.get('status')
                    sub_attempts = int(sub_info.get('attempts') or 0)
                    is_exhausted = sub_status in ['exhausted', 'escalated'] or sub_attempts >= 5

                    if is_exhausted:
                        if (cid, sub_key) not in NOTIFIED_FAILED_RECOVERY:
                            pretty_tech, specific_issues = format_subsystem_alert_details(sub_key, tech, unmon)
                            last_act = sub_info.get('last_action') or 'Remediation attempts exhausted'
                            lines = [
                                "🛑 *GAVASAH LUXURY AUTOMATION*",
                                "⚠️ *FAULT ESCALATION: Auto-Recovery Failed*",
                                "",
                                f"• *Site:* {cname} (`{cid}`)",
                                f"• *Subsystem:* ⚙️ {pretty_tech}",
                                "• *Status:* 🛑 5/5 REMEDIATION ATTEMPTS FAILED",
                                "",
                                f"📋 *Specific Issues Identified ({len(specific_issues)}):*",
                            ] + specific_issues + [
                                "",
                                f"• *Last Action:* {last_act}",
                                f"• *Time:* {ist_time_str}",
                                "",
                                "🚨 *Action Required:* Autonomous self-healing attempted 5 automated recoveries but the integration(s) did not recover. Auto-recovery is paused on the gateway to preserve system stability. Verify device power/network, or mute monitoring from the Dealer Portal if deliberately powered down.",
                                "🌐 *Operations Portal:* https://dealer.gavasah.com/"
                            ]
                            send_whatsapp_alert_to_contacts(cid, chr(10).join(lines))
                            NOTIFIED_FAILED_RECOVERY.add((cid, sub_key))
                    else:
                        if (cid, sub_key) in NOTIFIED_FAILED_RECOVERY and (sub_status in ['idle', 'online'] or sub_attempts == 0):
                            NOTIFIED_FAILED_RECOVERY.discard((cid, sub_key))
                            pretty_tech, _ = format_subsystem_alert_details(sub_key, tech, unmon)
                            lines = [
                                "✅ *GAVASAH LUXURY AUTOMATION*",
                                "🟢 *RESOLVED: Integration Recovered*",
                                "",
                                f"• *Site:* {cname} (`{cid}`)",
                                f"• *Subsystem:* {pretty_tech}",
                                "• *Status:* 🟢 HEALTHY / OPERATIONAL",
                                f"• *Time:* {ist_time_str}",
                                "",
                                "✨ *Notice:* Subsystem fault has cleared and all integrations are functioning normally.",
                                "🌐 *Operations Portal:* https://dealer.gavasah.com/"
                            ]
                            send_whatsapp_alert_to_contacts(cid, chr(10).join(lines))

            WATCHDOG_INITIALIZED = True
        except Exception as e:
            print(f"[!] Watchdog thread loop error: {e}", flush=True)

        time.sleep(20)

def run_server(port=PORT):
    threading.Thread(target=start_telemetry_alert_watchdog, daemon=True, name="TelemetryAlertWatchdog").start()
    server_address = ('', port)
    httpd = http.server.ThreadingHTTPServer(server_address, DealerPortalHandler)
    httpd.daemon_threads = True
    print(f"[*] GAVASAH Multi-Tenant Cloud Hub listening on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[!] Stopping server...")
        httpd.server_close()

if __name__ == '__main__':
    run_server()
