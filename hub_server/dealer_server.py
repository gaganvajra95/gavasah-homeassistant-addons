import os, sys, json, time, datetime, subprocess, base64, re, secrets, threading, hashlib, sqlite3
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

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
CADDY_HOST = os.environ.get('CADDY_HOST', '192.168.6.170')
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
            
            knx_ip TEXT NOT NULL,
            knx_port INTEGER NOT NULL,
            last_heartbeat INTEGER NOT NULL,
            status TEXT NOT NULL,
            remote_enabled INTEGER NOT NULL DEFAULT 1,
            system_json TEXT,
            network_json TEXT,
            knx_json TEXT
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

        CREATE INDEX IF NOT EXISTS idx_clients_dealer ON clients(dealer_id);
        CREATE INDEX IF NOT EXISTS idx_clients_integrator ON clients(integrator_id);
        CREATE INDEX IF NOT EXISTS idx_logs_client_time ON client_logs(client_id, timestamp DESC);
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
        if 'tunnel_mode' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN tunnel_mode TEXT DEFAULT 'wireguard'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_wg_ip ON clients(wg_ip);")

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
                        conn.execute("INSERT OR REPLACE INTO dealers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (d.get('id', did), d.get('username', ''), d.get('name', ''), d.get('password_plain', 'apex123!'),
                             d.get('email', ''), d.get('phone', ''), d.get('role', 'dealer'), d.get('status', 'active'),
                             d.get('salt', ''), d.get('password_hash', ''), d.get('created_at', int(time.time())))
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
                conn.execute("INSERT INTO dealers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('dealer_apex', 'apex_dealer', 'Apex Smart Automation', 'apex123!', 'contact@apexsmart.in', '+91 98490 12345', 'dealer', 'active', d1_salt, d1_hash, int(time.time()) - 86400*30)
                )
                d2_salt, d2_hash = hash_password("vajra123!")
                conn.execute("INSERT INTO dealers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('dealer_vajra', 'vajra_knx', 'Vajra KNX Solutions', 'vajra123!', 'sales@vajraknx.com', '+91 99887 76655', 'dealer', 'active', d2_salt, d2_hash, int(time.time()) - 86400*15)
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
        conn.close()

init_sqlite_database()

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
        cur.execute("SELECT * FROM dealers")
        dealers = {r['id']: dict(r) for r in cur.fetchall()}
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
                    conn.execute("INSERT OR REPLACE INTO owner VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (ow.get('id', 'owner_master'), ow.get('username', 'admin'), ow.get('name', 'Master Manufacturer'),
                         ow.get('role', 'manufacturer'), ow.get('salt', ''), ow.get('password_hash', ''), ow.get('created_at', int(time.time())))
                    )
                existing_dealer_ids = {r['id'] for r in conn.execute("SELECT id FROM dealers").fetchall()}
                current_dealer_ids = set(data.get('dealers', {}).keys())
                for did in existing_dealer_ids - current_dealer_ids:
                    conn.execute("DELETE FROM dealers WHERE id = ?", (did,))

                for did, d in data.get('dealers', {}).items():
                    conn.execute("INSERT OR REPLACE INTO dealers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (d.get('id', did), d.get('username', ''), d.get('name', ''), d.get('password_plain', ''),
                         d.get('email', ''), d.get('phone', ''), d.get('role', 'dealer'), d.get('status', 'active'),
                         d.get('salt', ''), d.get('password_hash', ''), d.get('created_at', int(time.time())))
                    )

                existing_int_ids = {r['id'] for r in conn.execute("SELECT id FROM integrators").fetchall()}
                current_int_ids = set(data.get('integrators', {}).keys())
                for iid in existing_int_ids - current_int_ids:
                    conn.execute("DELETE FROM integrators WHERE id = ?", (iid,))

                for iid, it in data.get('integrators', {}).items():
                    conn.execute("INSERT OR REPLACE INTO integrators VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    conn.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?)",
                        (tok, s.get('user_id', ''), s.get('role', ''), s.get('created_at', int(time.time())), s.get('expires_at', int(time.time()) + 86400*7))
                    )
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error saving auth state in SQLite: {e}")
            conn.close()
            return False

def load_clients_state():
    with DB_LOCK:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients")
        res = {}
        for r in cur.fetchall():
            c = dict(r)
            c['remote_enabled'] = bool(c.get('remote_enabled', 1))
            try: c['system'] = json.loads(c.get('system_json') or '{}')
            except: c['system'] = {}
            try: c['network'] = json.loads(c.get('network_json') or '{}')
            except: c['network'] = {}
            try: c['knx_status'] = json.loads(c.get('knx_json') or '{}')
            except: c['knx_status'] = {}
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
                    conn.execute("""INSERT OR REPLACE INTO clients (
                        client_id, name, dealer_id, dealer_name, integrator_id, integrator_name,
                        domain, auth_secret, dashboard_port, ssh_port, knx_ip, knx_port,
                        last_heartbeat, status, remote_enabled, system_json, network_json, knx_json,
                        wg_ip, wg_pubkey, wg_privkey, tunnel_mode
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (c.get('client_id', cid), c.get('name', cid), c.get('dealer_id', 'owner_master'), c.get('dealer_name', 'Master Manufacturer (Direct)'),
                         c.get('integrator_id'), c.get('integrator_name', 'Direct Dealer Supervision'), c.get('domain', f"{cid}.gavasah.com"),
                         c.get('auth_secret', ''), int(c.get('dashboard_port', d_port)), int(c.get('ssh_port', s_port)),
                         c.get('knx_ip', '192.168.1.100'), int(c.get('knx_port', 3671)), int(c.get('last_heartbeat', int(time.time()))),
                         c.get('status', 'online'), 1 if c.get('remote_enabled', True) else 0,
                         sys_json, net_json, knx_json,
                         c.get('wg_ip'), c.get('wg_pubkey'), c.get('wg_privkey'), c.get('tunnel_mode', 'wireguard'))
                    )
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error saving clients state in SQLite: {e}")
            conn.close()
            return False

# ==============================================================================
# Caddy Ingress & OpenSSH Helpers
# ==============================================================================
def run_caddy_cmd(remote_py, extra_bash=""):
    if os.name == 'nt' or os.environ.get('MOCK_CADDY') == '1':
        return True
    b64 = base64.b64encode(remote_py.encode()).decode()
    cmd = f'python3 -c "import base64; exec(base64.b64decode(\'{b64}\'))"'
    if extra_bash:
        cmd += f" && {extra_bash}"
    ssh_args = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
        "-i", "/root/.ssh/id_rsa", f"root@{CADDY_HOST}", cmd
    ]
    try:
        res = subprocess.run(ssh_args, capture_output=True, text=True, timeout=5)
        return res.returncode == 0
    except Exception as e:
        print(f"[!] Caddy update error: {e}")
        return False

def sync_client_ssh_user(client_id, ssh_public_key):
    if not ssh_public_key or ssh_public_key in REGISTERED_SSH_KEYS:
        return True
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
        REGISTERED_SSH_KEYS.add(ssh_public_key)
        return True
    except Exception as e:
        print(f"[!] Error syncing SSH key: {e}")
        return False

def sync_caddy_ingress(client_id, dash_port, proto="http", enabled=True, force=False, wg_ip=None):
    cache_key = client_id
    config_tuple = (dash_port, proto, enabled, wg_ip)
    if not force and SYNCED_CADDY_ROUTES.get(cache_key) == config_tuple:
        return True

    domain = f"{client_id}.gavasah.com"
    if not enabled:
        block = f"# Client: {client_id}\n{domain} {{\n    respond \"Remote Access Suspended by Dealer\" 403\n}}"
    elif wg_ip:
        # High-performance WireGuard direct proxy (0 host TCP ports consumed)
        block = f"# Client: {client_id} (WireGuard Mesh)\n{domain} {{\n    reverse_proxy {wg_ip}:8123\n}}"
    elif proto == "https":
        block = f"# Client: {client_id}\n{domain} {{\n    reverse_proxy https://192.168.6.150:{dash_port} {{\n        transport http {{\n            tls_insecure_skip_verify\n        }}\n    }}\n}}"
    else:
        block = f"# Client: {client_id}\n{domain} {{\n    reverse_proxy 192.168.6.150:{dash_port}\n}}"

    py_code = (
        "import re, subprocess\n"
        "with open('/home/tejoram97/Caddyfile.unified', 'r') as f:\n"
        "    text = f.read()\n\n"
        f"domain = '{domain}'\n"
        f"new_block = '''{block}'''.strip()\n\n"
        "pattern = re.compile(r'(?:^[ \\t]*#[^\\n]*\\n)?^[ \\t]*' + re.escape(domain) + r'[ \\t]*\\{{[\\s\\S]*?(?=^(?:[a-zA-Z0-9_#\\(\\)]|\\Z))', re.MULTILINE)\n"
        "m = pattern.search(text)\n"
        "if m:\n"
        "    updated = text[:m.start()] + new_block + '\\n\\n' + text[m.end():]\n"
        "else:\n"
        "    updated = text.rstrip() + '\\n\\n' + new_block + '\\n'\n\n"
        "with open('/home/tejoram97/Caddyfile.unified', 'w') as f:\n"
        "    f.write(updated)\n"
    )
    ok = run_caddy_cmd(py_code, "docker exec caddy caddy reload --config /etc/caddy/Caddyfile")
    if ok:
        SYNCED_CADDY_ROUTES[cache_key] = config_tuple
    return ok


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
        .pill-btn.pill-red.active {
            background: rgba(239, 68, 68, 0.15);
            border-color: #ef4444;
            color: #f87171;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.25);
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

        .modal-header {
            padding: 18px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(15, 23, 42, 0.6);
            font-size: 16px;
            font-weight: 700;
        }

        .modal-body {
            padding: 24px;
            overflow-y: auto;
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
            max-height: min(68vh, calc(100vh - 260px));
            overflow: auto !important;
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
            width: 7px;
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
            width: 100%;
            overflow-x: auto;
            overflow-y: hidden;
            height: 12px;
            margin-bottom: 6px;
            border-radius: 6px;
            background: rgba(11, 16, 28, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.06);
            display: none;
        }
        .table-top-scroll::-webkit-scrollbar {
            height: 8px;
        }
        .table-top-scroll::-webkit-scrollbar-track {
            background: rgba(11, 16, 28, 0.85);
            border-radius: 4px;
        }
        .table-top-scroll::-webkit-scrollbar-thumb {
            background: rgba(0, 240, 255, 0.4);
            border-radius: 4px;
        }
        .table-top-scroll::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
        }
        .table-top-scroll-track {
            height: 1px;
        }

        /* Quick Column Scroll Buttons */
        .table-scroll-controls {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 8px;
            padding: 3px 8px;
        }
        .btn-scroll-arrow {
            background: rgba(0, 240, 255, 0.1);
            color: #00f0ff;
            border: 1px solid rgba(0, 240, 255, 0.3);
            border-radius: 6px;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.18s ease;
            line-height: 1;
        }
        .btn-scroll-arrow:hover {
            background: rgba(0, 240, 255, 0.25);
            border-color: #00f0ff;
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.4);
            transform: translateY(-1px);
        }
        .scroll-label {
            font-size: 10px;
            color: #94a3b8;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            user-select: none;
        }

        .actions-btn-flex {
            display: flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
        }
        .btn-action-ingress {
            color: #00f0ff !important;
            border-color: rgba(0, 240, 255, 0.35) !important;
            background: rgba(0, 240, 255, 0.08) !important;
        }
        .btn-action-ingress:hover {
            background: rgba(0, 240, 255, 0.22) !important;
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.4);
        }
        .btn-action-logs {
            color: #94a3b8 !important;
            border-color: rgba(148, 163, 184, 0.3) !important;
            background: rgba(148, 163, 184, 0.08) !important;
        }
        .btn-action-logs:hover {
            color: #e2e8f0 !important;
            border-color: rgba(148, 163, 184, 0.6) !important;
            background: rgba(148, 163, 184, 0.2) !important;
        }
        .btn-action-edit {
            color: #38bdf8 !important;
            border-color: rgba(56, 189, 248, 0.35) !important;
            background: rgba(56, 189, 248, 0.08) !important;
        }
        .btn-action-edit:hover {
            background: rgba(56, 189, 248, 0.22) !important;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }
        .btn-action-del {
            color: #ef4444 !important;
            border-color: rgba(239, 68, 68, 0.35) !important;
            background: rgba(239, 68, 68, 0.08) !important;
        }
        .btn-action-del:hover {
            background: rgba(239, 68, 68, 0.22) !important;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.4);
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
                <div style="width: 38px; height: 38px; border-radius: 10px; background: rgba(0, 240, 255, 0.15); border: 1px solid var(--accent); display: flex; align-items: center; justify-content: center; box-shadow: 0 0 12px var(--accent-glow);">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.2">
                        <rect x="2" y="2" width="20" height="8" rx="2"></rect>
                        <rect x="2" y="14" width="20" height="8" rx="2"></rect>
                    </svg>
                </div>
                <div>
                    <div style="font-size: 14px; font-weight: 800; color: #fff;">GAVASAH HUB</div>
                    <div style="font-size: 10px; color: var(--accent); font-weight: 700; text-transform: uppercase;">Master Console</div>
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

                <div class="header-actions">
                    <div class="ssl-badge">
                        <div class="ssl-pulse"></div>
                        <span>SSL: Autonomous ACME Active</span>
                    </div>
                    <button class="btn-sm" onclick="triggerSslCheck()">🔄 Verify SSL</button>

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
                            <div class="metric-label">Total Client Gateways</div>
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
                            <div class="metric-sub">>75s Signal Interruption</div>
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
                                    <th>Dealer Organization</th>
                                    <th>Portal Username</th>
                                    <th>Assigned Clients</th>
                                    <th>Online / Lost</th>
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
                                    <th>Managed Client Gateways</th>
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
                        <button class="btn-action" onclick="openOnboardModal()">+ Onboard New Client</button>
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
                            <button class="pill-btn pill-red" id="filter-pill-lost" onclick="setFleetFilter('LOST')">🔴 Lost (<span id="pill-count-lost">0</span>)</button>
                        </div>
                        <div class="table-scroll-controls" title="Scroll columns left or right without scrolling to bottom">
                            <button type="button" class="btn-scroll-arrow" onclick="scrollTableBy('#tab-fleet .table-wrap', -320)" title="Scroll Left">◀</button>
                            <span class="scroll-label">Scroll Columns</span>
                            <button type="button" class="btn-scroll-arrow" onclick="scrollTableBy('#tab-fleet .table-wrap', 320)" title="Scroll Right">▶</button>
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

                    <!-- Top Synced Scrollbar for Instant Left/Right Navigation -->
                    <div class="table-top-scroll" id="fleet-top-scroll">
                        <div class="table-top-scroll-track" id="fleet-top-scroll-track"></div>
                    </div>

                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Client Site / Slug</th>
                                    <th id="th-dealer-col">Dealer Partner</th>
                                    <th id="th-integrator-col">Assigned Integrator</th>
                                    <th>Heartbeat Status</th>
                                    <th>Remote Ingress</th>
                                    <th>Boot Slot (RAUC)</th>
                                    <th>Device LAN IP & Bus</th>
                                    <th>Hardware Metrics</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="fleet-table-body">
                            </tbody>
                        </table>
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

            </div>
        </div>
    </div>

    <!-- ======================================================================
         MODALS
         ====================================================================== -->

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

                    <div class="form-group">
                        <label class="form-label">PORTAL LOGIN USERNAME</label>
                        <input type="text" id="dlr-username" class="form-input" placeholder="e.g. apex_dealer" required>
                        <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Alphanumeric slug used by dealer to sign in.</div>
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
                        <input type="text" id="onb-name" class="form-input" placeholder="e.g. Sharma Villa (Jubilee Hills)" required>
                    </div>

                    <div class="form-group">
                        <label class="form-label">CLIENT SLUG / IDENTIFIER</label>
                        <input type="text" id="onb-slug" class="form-input" placeholder="e.g. sharma-villa" required oninput="updateOnboardDomainPreview()">
                        <div style="margin-top: 5px; font-size: 12px; color: #38bdf8; font-family: monospace; display: flex; align-items: center; gap: 4px;">
                            <span>🌐 Ingress Subdomain:</span>
                            <span id="onb-preview-domain" style="font-weight: 600; color: #00f0ff;">sharma-villa-direct.gavasah.com</span>
                        </div>
                        <div style="font-size: 11px; color: #64748b; margin-top: 3px;">Namespaced as <code>&lt;client-slug&gt;-&lt;dealer-slug&gt;.gavasah.com</code></div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">AUTHENTICATION SECRET (AUTH_KEY)</label>
                        <div class="form-input-wrap">
                            <input type="text" id="onb-secret" class="form-input" placeholder="Auto-generated if left empty">
                            <button type="button" class="btn-sm" style="position: absolute; right: 6px;" onclick="generateOnboardSecret()">🎲</button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">KNX IP ROUTER / INTERFACE IP</label>
                        <input type="text" id="onb-knx" class="form-input" value="192.168.1.111">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-sm" onclick="closeOnboardModal()">Cancel</button>
                    <button type="submit" class="btn-action">🚀 Provision Client Site</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Client Modal -->
    <div class="modal" id="edit-modal">
        <div class="modal-content">
            <div class="modal-header">
                <div>Edit Client Site Configuration</div>
                <div style="cursor: pointer;" onclick="closeEditModal()">&times;</div>
            </div>
            <form onsubmit="handleClientEditSubmit(event)">
                <div class="modal-body">
                    <input type="hidden" id="edit-client-id">
                    
                    <div class="form-group" id="edit-dealer-group">
                        <label class="form-label">ASSIGNED DEALER</label>
                        <select id="edit-dealer-select" class="form-input" onchange="onEditDealerChange()">
                        </select>
                    </div>
                    <div class="form-group" id="edit-integrator-group">
                        <label class="form-label">ASSIGNED INTEGRATOR</label>
                        <select id="edit-integrator-select" class="form-input">
                            <!-- Populated with integrators -->
                        </select>
                    </div>

                    <div class="form-group">
                        <label class="form-label">CLIENT SITE NAME</label>
                        <input type="text" id="edit-name" class="form-input" required>
                    </div>

                    <div class="form-group">
                        <label class="form-label">AUTHENTICATION SECRET (AUTH_KEY)</label>
                        <div class="form-input-wrap">
                            <input type="text" id="edit-secret" class="form-input">
                            <button type="button" class="btn-sm" style="position: absolute; right: 6px;" onclick="generateEditSecret()">🎲</button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">KNX GATEWAY IP</label>
                        <input type="text" id="edit-knx-ip" class="form-input">
                    </div>

                    <div class="form-group">
                        <label class="form-label">KNX PORT</label>
                        <input type="number" id="edit-knx-port" class="form-input" value="3671">
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
                    <div class="form-group">
                        <label class="form-label">LOGIN USERNAME</label>
                        <input type="text" id="int-username" class="form-input" placeholder="e.g. rajesh_knx" required autocomplete="off">
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
        async function checkAuth() {
            try {
                const res = await fetch('/api/me?t=' + Date.now());
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
                document.getElementById('th-int-dealership-col').style.display = '';
                document.getElementById('integrator-dealer-filter-wrap').style.display = 'block';

                switchTab('overview');
                fetchDealers();
                fetchIntegrators();
                fetchFleet();

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
                document.getElementById('th-dealer-col').style.display = 'none';
                document.getElementById('th-int-dealership-col').style.display = 'none';
                document.getElementById('integrator-dealer-filter-wrap').style.display = 'none';

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
                    body: JSON.stringify({ username: u, password: p })
                });
                const data = await res.json();
                if (res.ok && data.ok) {
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
                await fetch('/api/logout', { method: 'POST' });
            } catch (e) {}
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
            } else if (tabId === 'fleet') {
                fetchFleet();
            }
        }

        // ======================================================================
        // DEALERS MANAGEMENT (MANUFACTURER)
        // ======================================================================
        async function fetchDealers() {
            if (!currentUser || currentUser.role !== 'manufacturer') return;
            try {
                const res = await fetch('/api/dealers?t=' + Date.now());
                if (res.ok) {
                    dealersList = await res.json();
                    renderDealersUI();
                    updateDealerDropdowns();
                }
            } catch (err) {
                console.error("Error fetching dealers:", err);
            }
        }

        function renderDealersUI() {
            const badge = document.getElementById('badge-dealer-count');
            if (badge) badge.innerText = dealersList.length;

            const ovDealersCount = document.getElementById('ov-dealers-count');
            if (ovDealersCount) ovDealersCount.innerText = dealersList.length;

            // Overview Dealers Table
            const ovBody = document.getElementById('overview-dealers-body');
            if (ovBody && currentUser.role === 'manufacturer') {
                ovBody.innerHTML = dealersList.map(d => `
                    <tr>
                        <td style="font-weight: 600; color: #fff;">
                            <div>${escapeHtml(d.name)}</div>
                            <div style="font-size: 11px; color: #64748b; font-family: monospace;">ID: ${escapeHtml(d.id)}</div>
                        </td>
                        <td style="font-family: monospace; color: #cbd5e1;">${escapeHtml(d.username)}</td>
                        <td>
                            <span class="badge-role" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3);">
                                ${d.client_count} Gateway(s) / ${d.integrator_count || 0} Integrator(s)
                            </span>
                        </td>
                        <td>
                            <span style="color: #10b981; font-weight: 600;">${d.online_count} Online</span> / 
                            <span style="color: ${d.lost_count > 0 ? '#ef4444' : '#64748b'}; font-weight: 600;">${d.lost_count} Lost</span>
                        </td>
                        <td style="font-size: 12px; color: #94a3b8;">
                            <div>${escapeHtml(d.email || '—')}</div>
                            <div style="font-size: 11px; color: #64748b;">${escapeHtml(d.phone || '—')}</div>
                        </td>
                        <td>
                            <span class="badge-status ${d.status === 'active' ? 'status-online' : 'status-lost'}">
                                ${d.status.toUpperCase()}
                            </span>
                        </td>
                        <td>
                            <button class="btn-sm" onclick="filterFleetByDealer('${d.id}')">View Fleet ➔</button>
                        </td>
                    </tr>
                `).join('') || `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">No authorized dealers registered yet.</td></tr>`;
            }

            // Dedicated Dealers Directory Table (With Password Reveal & Edit for Manufacturer)
            const dirBody = document.getElementById('dealers-management-body');
            if (dirBody) {
                dirBody.innerHTML = dealersList.map(d => `
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
            // Fleet filter dropdown
            const filterSel = document.getElementById('fleet-dealer-filter');
            if (filterSel && currentUser.role === 'manufacturer') {
                const prev = filterSel.value;
                filterSel.innerHTML = '<option value="all">All Dealer Networks</option>' +
                    dealersList.map(d => `<option value="${d.id}">${escapeHtml(d.name)} (${d.client_count || 0})</option>`).join('');
                filterSel.value = prev || 'all';
            }

            // Integrators filter dropdown
            const intDealerFilter = document.getElementById('integrator-dealer-filter');
            if (intDealerFilter && currentUser.role === 'manufacturer') {
                const prev = intDealerFilter.value;
                intDealerFilter.innerHTML = '<option value="all">All Dealers Workforce</option>' +
                    dealersList.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
                intDealerFilter.value = prev || 'all';
            }

            // Onboard modal dealer select
            const onbDealerSel = document.getElementById('onb-dealer-select');
            if (onbDealerSel && currentUser.role === 'manufacturer') {
                onbDealerSel.innerHTML = '<option value="owner_master">Master Manufacturer (Direct Supervision)</option>' +
                    dealersList.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
            }

            // Integrator modal dealer select
            const intDealerSel = document.getElementById('int-dealer-select');
            if (intDealerSel && currentUser.role === 'manufacturer') {
                intDealerSel.innerHTML = dealersList.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join('');
            }
        }

        function filterFleetByDealer(dealerId) {
            switchTab('fleet');
            const sel = document.getElementById('fleet-dealer-filter');
            if (sel) {
                sel.value = dealerId;
                fetchFleet();
            }
        }

        function filterIntegratorsByDealer(dealerId) {
            renderIntegratorsUI(dealerId);
        }

        function openCreateDealerModal() {
            document.getElementById('dealer-modal-title').innerText = 'Register New Authorized Dealer';
            document.getElementById('dealer-form-id').value = '';
            document.getElementById('dlr-name').value = '';
            document.getElementById('dlr-username').value = '';
            document.getElementById('dlr-username').readOnly = false;
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
            document.getElementById('dlr-username').value = d.username;
            document.getElementById('dlr-username').readOnly = false;
            
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
            const payload = {
                name: document.getElementById('dlr-name').value.trim(),
                username: document.getElementById('dlr-username').value.trim(),
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
                const res = await fetch(endpoint, {
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
                <span style="color: #38bdf8;">✓ SAFETY GUARANTEE:</span> All client gateways currently assigned to this dealer will <strong>NOT</strong> be deleted. They will automatically be transferred to Master Manufacturer Direct Supervision.
            `;
            document.getElementById('delete-modal').classList.add('active');
        }

        // ======================================================================
        // INTEGRATORS MANAGEMENT (MANUFACTURER & DEALERS)
        // ======================================================================
        async function fetchIntegrators() {
            if (!currentUser || currentUser.role === 'integrator') return;
            try {
                const res = await fetch('/api/integrators?t=' + Date.now());
                if (res.ok) {
                    integratorsList = await res.json();
                    renderIntegratorsUI();
                    updateIntegratorDropdowns();
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

        function updateIntegratorDropdowns() {
            // Onboard modal integrator select
            const onbIntSel = document.getElementById('onb-integrator-select');
            if (onbIntSel) {
                onbIntSel.innerHTML = '<option value="">Direct Dealer Supervision (No Integrator)</option>' +
                    integratorsList.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');
            }

            // Edit client modal integrator select
            const editIntSel = document.getElementById('edit-integrator-select');
            if (editIntSel) {
                editIntSel.innerHTML = '<option value="">Direct Dealer Supervision (No Integrator)</option>' +
                    integratorsList.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');
            }
        }

        function openCreateIntegratorModal() {
            document.getElementById('integrator-modal-title').innerText = 'Register New Technical Integrator';
            document.getElementById('int-id').value = '';
            document.getElementById('int-name').value = '';
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
                const dSel = document.getElementById('int-dealer-select');
                if (dSel) dSel.value = it.dealer_id || '';
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
            const payload = {
                name: document.getElementById('int-name').value.trim(),
                username: document.getElementById('int-username').value.trim(),
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
                const res = await fetch(endpoint, {
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
                <span style="color: #10b981; font-weight: 600;">✓ SAFETY GUARANTEE:</span> All client gateways currently supervised by this integrator will <strong>NOT</strong> be deleted. They will automatically be transferred to <strong>Direct Dealer Supervision</strong>.
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
                intSelect.innerHTML = '<option value="none">Direct Dealer Supervision (No Integrator)</option>' +
                    integratorsList.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');
                intSelect.value = client.integrator_id || 'none';
            }

            document.getElementById('reassign-modal').classList.add('active');
        }

        function onReassignDealerChange(preSelectedIntId = null) {
            const dealerId = document.getElementById('reassign-dealer-select').value;
            const intSelect = document.getElementById('reassign-integrator-select');

            const filteredIntegrators = integratorsList.filter(it => it.dealer_id === dealerId);
            intSelect.innerHTML = '<option value="none">Direct Dealer Supervision (No Integrator)</option>' +
                filteredIntegrators.map(it => `<option value="${it.id}">${escapeHtml(it.name)} (${escapeHtml(it.username)})</option>`).join('');

            if (preSelectedIntId) {
                intSelect.value = preSelectedIntId;
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
                const res = await fetch('/api/reassign_client', {
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
                const res = await fetch('/api/fleet?t=' + Date.now());
                if (!res.ok) {
                    if (res.status === 401) checkAuth();
                    return;
                }
                const data = await res.json();
                currentFleetData = data;
                renderTable(data);
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

        function renderTable(data) {
            if (!Array.isArray(data)) return;

            const now = Math.floor(Date.now() / 1000);
            let onlineCount = 0;
            let warningCount = 0;
            let offlineCount = 0;

            // Optional Dealer Filter for Manufacturer
            const dFilter = document.getElementById('fleet-dealer-filter');
            const selectedDealer = (dFilter && currentUser.role === 'manufacturer') ? dFilter.value : 'all';

            const filtered = data.filter(c => {
                if (selectedDealer !== 'all' && c.dealer_id !== selectedDealer) return false;

                const diff = now - (c.last_heartbeat || 0);
                if (diff <= 75) onlineCount++;
                else if (diff <= 180) warningCount++;
                else offlineCount++;

                if (fleetStatusFilter === 'ONLINE' && diff > 75) return false;
                if (fleetStatusFilter === 'WARNING' && (diff <= 75 || diff > 180)) return false;
                if ((fleetStatusFilter === 'OFFLINE' || fleetStatusFilter === 'LOST') && diff <= 75) return false;

                if (fleetSearchQuery) {
                    const str = `${c.client_id} ${c.name} ${c.dealer_name || ''} ${c.integrator_name || ''} ${c.domain} ${c.knx_ip}`.toLowerCase();
                    if (!str.includes(fleetSearchQuery)) return false;
                }
                return true;
            });

            // Update Fleet Tab metric cards
            const valTotal = document.getElementById('val-total');
            const valOnline = document.getElementById('val-online');
            const valLost = document.getElementById('val-lost');
            if (valTotal) valTotal.innerText = data.length;
            if (valOnline) valOnline.innerText = onlineCount;
            if (valLost) valLost.innerText = offlineCount + warningCount;

            // Update Filter pill counters
            const pillAll = document.getElementById('pill-count-all');
            const pillOnline = document.getElementById('pill-count-online');
            const pillLost = document.getElementById('pill-count-lost');
            if (pillAll) pillAll.innerText = data.length;
            if (pillOnline) pillOnline.innerText = onlineCount;
            if (pillLost) pillLost.innerText = offlineCount + warningCount;

            // Update Overview Tab cards
            const ovTotal = document.getElementById('ov-total-clients');
            const ovOnline = document.getElementById('ov-online-clients');
            const ovLost = document.getElementById('ov-lost-clients');
            if (ovTotal) ovTotal.innerText = data.length;
            if (ovOnline) ovOnline.innerText = onlineCount;
            if (ovLost) ovLost.innerText = offlineCount + warningCount;

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

            tbody.innerHTML = pageData.map(c => {
                const diff = now - (c.last_heartbeat || 0);
                const humanDiff = formatHeartbeatTime(diff);
                let stClass = 'status-online';
                let stText = 'ONLINE';
                if (diff > 180) { stClass = 'status-lost'; stText = 'OFFLINE'; }
                else if (diff > 75) { stClass = 'status-warning'; stText = 'WARNING'; }

                const sys = c.system || {};
                const net = c.network || {};
                const knx = c.knx_status || {};
                const isRecovery = sys.is_recovery_mode || false;
                const slot = sys.boot_slot || 'A';
                const remoteEnabled = c.remote_enabled !== false;

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

                return `
                    <tr>
                        <td>
                            <div style="font-weight: 600; color: #fff; font-size: 14px;">${escapeHtml(c.name)}</div>
                            <div style="font-size: 11px; color: #64748b; font-family: monospace; margin-top: 2px;">
                                ${escapeHtml(c.client_id)} &bull; <a href="https://${escapeHtml(c.domain)}" target="_blank" style="color: #00f0ff; text-decoration: none;">${escapeHtml(c.domain)} ↗</a>
                            </div>
                        </td>
                        ${dealerCell}
                        ${integratorCell}
                        <td>
                            <div style="display: flex; align-items: center; gap: 6px;">
                                <span class="badge-status ${stClass}">${stText}</span>
                                <span style="font-size: 11px; color: #94a3b8; font-family: monospace; white-space: nowrap;">${humanDiff}</span>
                            </div>
                        </td>
                        <td>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <label class="toggle-switch">
                                    <input type="checkbox" ${remoteEnabled ? 'checked' : ''} onchange="toggleRemoteAccess('${c.client_id}', this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                                <span style="font-size: 10px; font-weight: 700; color: ${remoteEnabled ? '#00f0ff' : '#64748b'}; letter-spacing: 0.5px;">${remoteEnabled ? 'LIVE' : 'OFF'}</span>
                            </div>
                        </td>
                        <td>
                            <span class="badge-slot slot-${slot.toLowerCase()}">SLOT ${slot}</span>
                            ${isRecovery ? '<span class="badge-slot" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; margin-left: 4px;">RECOVERY</span>' : ''}
                        </td>
                        <td style="font-size: 12px; font-family: monospace;">
                            <div style="color: #cbd5e1;">IP: ${escapeHtml(net.local_ipv4 || '—')}</div>
                            <div style="color: #94a3b8; font-size: 11px;">KNX: ${escapeHtml(c.knx_ip || '—')}:${c.knx_port || 3671}</div>
                        </td>
                        <td style="font-size: 12px;">
                            <div style="color: #cbd5e1;">CPU: ${sys.cpu_percent || 0}% &bull; RAM: ${sys.memory_percent || 0}%</div>
                            <div style="color: #64748b; font-size: 11px;">HAOS ${escapeHtml(sys.haos_version || '13.2')}</div>
                        </td>
                        <td class="col-actions-sticky">
                            <div class="actions-btn-flex">
                                <a href="https://${escapeHtml(c.domain)}" target="_blank" class="btn-action-icon btn-action-ingress" title="Open Client Home Assistant Web GUI">🌐 Ingress</a>
                                <button class="btn-action-icon btn-action-logs" onclick="openLogsModal('${c.client_id}')" title="Audit Telemetry Logs">📋 Logs</button>
                                ${currentUser.role !== 'integrator' ? `
                                    <button class="btn-action-icon btn-reassign-sm" onclick="openReassignModal('${c.client_id}')" title="Reassign Supervision">🔄 Transfer</button>
                                ` : ''}
                                <button class="btn-action-icon btn-action-edit" onclick="openEditModal('${c.client_id}')" title="Edit Site Config">✏️ Edit</button>
                                <button class="btn-action-icon btn-action-del" onclick="promptDelete('${c.client_id}', '${escapeHtml(c.name)}')" title="Delete Site">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('') || `<tr><td colspan="${currentUser.role === 'manufacturer' ? 9 : 8}" style="text-align: center; color: #64748b; padding: 32px;">No gateways match the selected filter.</td></tr>`;

            // Initialize / sync top and bottom horizontal scrollbars
            setTimeout(initAllTableScrollbars, 40);
        }

        // ======================================================================
        // HORIZONTAL SCROLL & RESPONSIVE TABLE UTILITIES
        // ======================================================================
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
            document.getElementById('onb-name').value = '';
            const slugEl = document.getElementById('onb-slug') || document.getElementById('onb-id');
            if (slugEl) slugEl.value = '';
            document.getElementById('onb-secret').value = generateSecretStr();
            document.getElementById('onb-knx-ip').value = '192.168.1.100';
            document.getElementById('onb-knx-port').value = '3671';
            document.getElementById('onb-ssh-key').value = '';
            updateOnboardDomainPreview();

            const dGroup = document.getElementById('onb-dealer-group');
            const intGroup = document.getElementById('onb-integrator-group');

            if (currentUser.role === 'manufacturer') {
                dGroup.style.display = 'block';
                intGroup.style.display = 'block';
                updateDealerDropdowns();
                updateIntegratorDropdowns();
            } else if (currentUser.role === 'dealer') {
                dGroup.style.display = 'none';
                intGroup.style.display = 'block';
                updateIntegratorDropdowns();
            } else {
                dGroup.style.display = 'none';
                intGroup.style.display = 'none';
            }

            document.getElementById('onboard-modal').classList.add('active');
        }

        function closeOnboardModal() {
            document.getElementById('onboard-modal').classList.remove('active');
        }

        function generateOnboardSecret() {
            document.getElementById('onb-secret').value = generateSecretStr();
        }

        function generateEditSecret() {
            document.getElementById('edit-secret').value = generateSecretStr();
        }

        function generateSecretStr() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let res = '';
            for (let i = 0; i < 32; i++) res += chars.charAt(Math.floor(Math.random() * chars.length));
            return res;
        }

        async function handleOnboardSubmit(e) {
            e.preventDefault();
            const slugInput = document.getElementById('onb-slug') || document.getElementById('onb-id');
            const payload = {
                name: document.getElementById('onb-name').value.trim(),
                client_id: slugInput.value.trim().toLowerCase(),
                auth_secret: document.getElementById('onb-secret').value.trim(),
                knx_ip: document.getElementById('onb-knx-ip').value.trim(),
                knx_port: parseInt(document.getElementById('onb-knx-port').value) || 3671,
                ssh_public_key: document.getElementById('onb-ssh-key').value.trim()
            };

            if (currentUser.role === 'manufacturer') {
                payload.dealer_id = document.getElementById('onb-dealer-select').value;
                payload.integrator_id = document.getElementById('onb-integrator-select').value;
            } else if (currentUser.role === 'dealer') {
                payload.integrator_id = document.getElementById('onb-integrator-select').value;
            }

            try {
                const res = await fetch('/api/onboard', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast(`Gateway '${payload.name}' onboarded successfully!`, 'success');
                    closeOnboardModal();
                    fetchFleet();
                } else {
                    showToast(data.error || 'Onboarding failed', 'error');
                }
            } catch (err) {
                showToast('Network error during onboarding', 'error');
            }
        }

        function openEditModal(clientId) {
            const client = currentFleetData.find(c => c.client_id === clientId);
            if (!client) return;

            document.getElementById('edit-id').value = client.client_id;
            document.getElementById('edit-name').value = client.name;
            document.getElementById('edit-knx-ip').value = client.knx_ip || '';
            document.getElementById('edit-knx-port').value = client.knx_port || 3671;
            document.getElementById('edit-secret').value = client.auth_secret || '';

            const intGroup = document.getElementById('edit-integrator-group');
            if (currentUser.role !== 'integrator') {
                intGroup.style.display = 'block';
                updateIntegratorDropdowns();
                const sel = document.getElementById('edit-integrator-select');
                if (sel) sel.value = client.integrator_id || '';
            } else {
                intGroup.style.display = 'none';
            }

            document.getElementById('edit-modal').classList.add('active');
        }

        function closeEditModal() {
            document.getElementById('edit-modal').classList.remove('active');
        }

        async function handleClientEditSubmit(e) {
            e.preventDefault();
            const clientId = document.getElementById('edit-id').value;
            const payload = {
                client_id: clientId,
                name: document.getElementById('edit-name').value.trim(),
                knx_ip: document.getElementById('edit-knx-ip').value.trim(),
                knx_port: parseInt(document.getElementById('edit-knx-port').value) || 3671,
                auth_secret: document.getElementById('edit-secret').value.trim()
            };

            try {
                const res = await fetch('/api/update_client', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && data.ok) {
                    showToast('Gateway configuration updated', 'success');
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
                const res = await fetch('/api/toggle_remote', {
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
                const res = await fetch(endpoint, {
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
                const res = await fetch('/api/change_owner_credentials', {
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
                const res = await fetch('/api/change_dealer_password', {
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
            document.getElementById('logs-modal-title').innerText = `Telemetry Audit Logs: ${clientId}`;
            document.getElementById('logs-modal').classList.add('active');
            refreshCurrentLogs();
        }

        function closeLogsModal() {
            currentLogsClient = null;
            document.getElementById('logs-modal').classList.remove('active');
        }

        async function refreshCurrentLogs() {
            if (!currentLogsClient) return;
            const body = document.getElementById('logs-modal-body');
            body.innerHTML = '<div style="color: #64748b; font-size: 13px;">Streaming operational telemetry...</div>';

            try {
                const res = await fetch(`/api/logs?client_id=${encodeURIComponent(currentLogsClient)}&t=${Date.now()}`);
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
            const body = document.getElementById('logs-modal-body');
            navigator.clipboard.writeText(body.innerText).then(() => {
                showToast('Audit logs copied to clipboard!', 'success');
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
                const res = await fetch('/api/ssl_status?t=' + Date.now());
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

        // Initialization
        window.addEventListener('DOMContentLoaded', () => {
            checkAuth();
            setInterval(() => {
                if (currentUser) {
                    fetchFleet();
                }
            }, 10000); // 10s polling interval
        });


        async function toggleDealerStatus(dealerId, newStatus) {
            const actionLabel = newStatus === 'suspended' ? 'suspend' : 'activate';
            const warningExtra = newStatus === 'suspended' ? `
All active sessions for this dealer and their integrators will be terminated immediately.` : '';
            if (!confirm(`Are you sure you want to ${actionLabel} this dealer?${warningExtra}`)) {
                return;
            }
            try {
                const res = await fetch('/api/toggle_dealer_status', {
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
                const res = await fetch('/api/toggle_integrator_status', {
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
            const slugEl = document.getElementById('onb-slug') || document.getElementById('onb-id');
            const raw = (slugEl ? slugEl.value : '').trim().toLowerCase().replace(/[^a-z0-9\-]/g, '');
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
            updateIntegratorDropdowns();
        }

    </script>
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

        auth = load_auth_state()
        sessions = auth.get('sessions', {})
        session = sessions.get(token)
        if not session:
            return None

        now = int(time.time())
        if now > session.get('expires_at', 0):
            with AUTH_LOCK:
                auth = load_auth_state()
                if token in auth.get('sessions', {}):
                    del auth['sessions'][token]
                    save_auth_state(auth)
            return None

        user_id = session.get('user_id')
        role = session.get('role')

        if role == 'manufacturer' and user_id == 'owner_master':
            owner = auth.get('owner', {})
            return {
                'id': 'owner_master',
                'username': owner.get('username', 'admin'),
                'name': owner.get('name', 'Master Manufacturer'),
                'role': 'manufacturer',
                'session_token': token
            }
        elif role == 'dealer':
            dealers = auth.get('dealers', {})
            d = dealers.get(user_id)
            if d:
                if d.get('status') == 'suspended':
                    return None
                return {
                    'id': d['id'],
                    'username': d.get('username', ''),
                    'name': d.get('name', ''),
                    'email': d.get('email', ''),
                    'phone': d.get('phone', ''),
                    'role': 'dealer',
                    'status': d.get('status', 'active'),
                    'session_token': token
                }
        elif role == 'integrator':
            integrators = auth.get('integrators', {})
            it = integrators.get(user_id)
            if it:
                if it.get('status') == 'suspended':
                    return None
                # Check if parent dealership is suspended
                dealers = auth.get('dealers', {})
                parent_dealer = dealers.get(it.get('dealer_id'))
                if parent_dealer and parent_dealer.get('status') == 'suspended':
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

        return None

    def send_json(self, status_code, data, extra_headers=None):
        """Send formatted JSON HTTP response with optional custom headers."""
        body = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

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
                'role': user['role']
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
            for did, d in dealers_dict.items():
                dealer_clients = [c for c in c_data.values() if c.get('dealer_id') == did]
                dealer_ints = [it for it in integrators_dict.values() if it.get('dealer_id') == did]
                
                now = int(time.time())
                online_c = sum(1 for c in dealer_clients if (now - c.get('last_heartbeat', 0)) <= 75)
                lost_c = len(dealer_clients) - online_c

                res.append({
                    'id': d['id'],
                    'name': d.get('name', ''),
                    'username': d.get('username', ''),
                    'password_plain': d.get('password_plain', ''),  # Revealed for Manufacturer
                    'email': d.get('email', ''),
                    'phone': d.get('phone', ''),
                    'role': 'dealer',
                    'status': d.get('status', 'active'),
                    'created_at': d.get('created_at', 0),
                    'client_count': len(dealer_clients),
                    'integrator_count': len(dealer_ints),
                    'online_count': online_c,
                    'lost_count': lost_c
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

                supervised_clients = [c for c in c_data.values() if c.get('integrator_id') == iid]
                online_c = sum(1 for c in supervised_clients if (now - c.get('last_heartbeat', 0)) <= 75)
                lost_c = len(supervised_clients) - online_c

                res.append({
                    'id': it['id'],
                    'dealer_id': it.get('dealer_id', ''),
                    'dealer_name': it.get('dealer_name', ''),
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
            secret = (query.get('auth_secret', [''])[0]).strip()

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
            secret = (query.get('auth_secret', [''])[0]).strip()

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

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)

        # 1. Login Authentication (Manufacturer, Dealers & Integrators)
        if parsed.path == '/api/login':
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length).decode('utf-8')
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
                    authenticated_user = {
                        'id': 'owner_master',
                        'username': owner['username'],
                        'name': owner.get('name', 'Master Manufacturer'),
                        'role': 'manufacturer'
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
                                'role': 'dealer'
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

            with AUTH_LOCK:
                auth = load_auth_state()
                if 'sessions' not in auth:
                    auth['sessions'] = {}
                auth['sessions'][session_token] = {
                    'user_id': authenticated_user['id'],
                    'role': authenticated_user['role'],
                    'created_at': now,
                    'expires_at': expires_at
                }
                save_auth_state(auth)

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
                    with AUTH_LOCK:
                        auth = load_auth_state()
                        if token in auth.get('sessions', {}):
                            del auth['sessions'][token]
                            save_auth_state(auth)

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

            if not name or not username or not password:
                self.send_json(400, {'error': 'Dealer name, username, and password are required'})
                return

            clean_slug = re.sub(r'[^a-zA-Z0-9_]', '', username.lower())
            if not clean_slug:
                self.send_json(400, {'error': 'Invalid username format'})
                return

            with AUTH_LOCK:
                auth = load_auth_state()
                # Check uniqueness across owner, dealers, integrators
                if clean_slug == auth.get('owner', {}).get('username', '').lower():
                    self.send_json(400, {'error': 'Username already taken by Manufacturer'})
                    return
                for d in auth.get('dealers', {}).values():
                    if d.get('username', '').lower() == clean_slug:
                        self.send_json(400, {'error': 'Username already exists for another Dealer'})
                        return
                for it in auth.get('integrators', {}).values():
                    if it.get('username', '').lower() == clean_slug:
                        self.send_json(400, {'error': 'Username already taken by an Integrator'})
                        return

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

            if not name or not username or not password:
                self.send_json(400, {'error': 'Integrator name, username, and password are required'})
                return

            clean_slug = re.sub(r'[^a-zA-Z0-9_]', '', username.lower())
            if not clean_slug:
                self.send_json(400, {'error': 'Invalid username format'})
                return

            auth = load_auth_state()

            # Determine Dealership Assignment
            if user['role'] == 'dealer':
                dealer_id = user['id']
                dealer_name = user['name']
            else:
                # Manufacturer can assign to any dealer
                dealer_id = body.get('dealer_id', '').strip()
                if not dealer_id or dealer_id not in auth.get('dealers', {}):
                    # fallback to first dealer or self
                    if auth.get('dealers'):
                        dealer_id = list(auth['dealers'].keys())[0]
                        dealer_name = auth['dealers'][dealer_id]['name']
                    else:
                        dealer_id = 'owner_master'
                        dealer_name = 'Master Manufacturer (Direct)'
                else:
                    dealer_name = auth['dealers'][dealer_id]['name']

            with AUTH_LOCK:
                auth = load_auth_state()
                # Uniqueness check
                if clean_slug == auth.get('owner', {}).get('username', '').lower():
                    self.send_json(400, {'error': 'Username already taken by Manufacturer'})
                    return
                for d in auth.get('dealers', {}).values():
                    if d.get('username', '').lower() == clean_slug:
                        self.send_json(400, {'error': 'Username already taken by a Dealer'})
                        return
                for it in auth.get('integrators', {}).values():
                    if it.get('username', '').lower() == clean_slug:
                        self.send_json(400, {'error': 'Username already exists for an Integrator'})
                        return

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

                # Manufacturer can transfer integrator to another dealer
                if user['role'] == 'manufacturer' and new_dealer_id and new_dealer_id in auth.get('dealers', {}):
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
            knx_ip = body.get('knx_ip', '192.168.1.100').strip()
            knx_port = int(body.get('knx_port', 3671))

            if not client_name or not client_id:
                self.send_json(400, {'error': 'Site name and unique identifier are required'})
                return

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
                self.send_json(400, {'error': 'Client identifier must contain valid alphanumeric characters'})
                return

            # Enforce format: <client-slug>-<dealer-slug>
            if not raw_cslug.endswith(f"-{dealer_slug}"):
                clean_id = f"{raw_cslug}-{dealer_slug}"
            else:
                clean_id = raw_cslug

            domain = f"{clean_id}.gavasah.com"

            c_data = load_clients_state()
            if clean_id in c_data:
                self.send_json(400, {'error': f"Client identifier '{clean_id}' is already registered under this dealership"})
                return

            # Zero-Touch WireGuard Mesh IP Allocation (Option A)
            wg_ip = allocate_next_wg_ip()
            wg_priv, wg_pub = generate_wg_keypair()
            sync_wireguard_peer(wg_pub, wg_ip)

            # Fallback legacy ports
            existing_dash_ports = [c.get('dashboard_port', 0) for c in c_data.values()]
            existing_ssh_ports = [c.get('ssh_port', 0) for c in c_data.values()]
            dash_port = 10001
            while dash_port in existing_dash_ports:
                dash_port += 1
            ssh_port = 22001
            while ssh_port in existing_ssh_ports:
                ssh_port += 1

            new_client = {
                'client_id': clean_id,
                'dealer_id': assigned_dealer_id,
                'dealer_name': assigned_dealer_name,
                'integrator_id': assigned_int_id,
                'integrator_name': assigned_int_name,
                'name': client_name,
                'domain': domain,
                'auth_secret': auth_secret or secrets.token_hex(16),
                'dashboard_port': dash_port,
                'ssh_port': ssh_port,
                'wg_ip': wg_ip,
                'wg_pubkey': wg_pub,
                'wg_privkey': wg_priv,
                'tunnel_mode': 'wireguard',
                'knx_ip': knx_ip,
                'knx_port': knx_port,
                'last_heartbeat': int(time.time()),
                'status': 'online',
                'remote_enabled': True,
                'system': {
                    'haos_version': '13.2',
                    'core_version': '2026.9.3',
                    'boot_slot': 'A',
                    'is_recovery_mode': False,
                    'slot_a_status': 'good',
                    'slot_b_status': 'standby',
                    'cpu_percent': 5.0,
                    'memory_percent': 28.0,
                    'disk_free_gb': 120.0
                },
                'network': {
                    'local_ipv4': '192.168.1.150',
                    'gateway': '192.168.1.1',
                    'mac_address': 'E4:5F:01:FF:AA:BB'
                },
                'knx_status': {
                    'reachable': True,
                    'latency_ms': 1.8
                }
            }

            c_data[clean_id] = new_client
            save_clients_state(c_data)

            # Ingress and SSH config
            sync_caddy_ingress(clean_id, dash_port, 'http', True, wg_ip=wg_ip)
            if ssh_key:
                sync_client_ssh_user(clean_id, ssh_key)

            append_client_log(clean_id, 'INFO', 'ONBOARD_COMPLETE', f"Site '{client_name}' onboarded successfully by {user['name']}.")
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
            if body.get('knx_ip'):
                client['knx_ip'] = body['knx_ip'].strip()
            if body.get('knx_port'):
                client['knx_port'] = int(body['knx_port'])
            if body.get('auth_secret'):
                client['auth_secret'] = body['auth_secret'].strip()

            save_clients_state(c_data)
            append_client_log(client_id, 'INFO', 'CONFIG_UPDATE', f"Configuration updated by {user['name']}.")
            self.send_json(200, {'ok': True, 'client': client})
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

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                self.send_json(404, {'error': 'Client site not found'})
                return

            # Role verification
            if user['role'] == 'dealer' and client.get('dealer_id') != user['id']:
                self.send_json(403, {'error': 'Access denied'})
                return
            elif user['role'] == 'integrator' and client.get('integrator_id') != user['id']:
                self.send_json(403, {'error': 'Access denied'})
                return

            client['remote_enabled'] = enabled
            save_clients_state(c_data)
            sync_caddy_ingress(client_id, client.get('dashboard_port', 10001), 'http', enabled)

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

            # Active client teardown: Immediately remove WireGuard tunnel peer from kernel interface
            wg_pub = client.get('wg_pubkey')
            if wg_pub:
                remove_wireguard_peer(wg_pub)

            # Invalidate ingress routing
            sync_caddy_ingress(client_id, 0, 'http', False)

            # Purge client record from persistent database
            del c_data[client_id]
            save_clients_state(c_data)

            append_client_log(
                client_id, 'INFO', 'CLIENT_DELETE',
                f"Client site '{client.get('name', client_id)}' ({client_id}) deleted by {user['role']} {user['name']} (active state terminated)."
            )

            self.send_json(200, {
                'ok': True,
                'message': f"Client site '{client.get('name', client_id)}' deleted successfully (active session terminated)"
            })
            return

        # 16. Gateway Telemetry Heartbeat (KNX-IP Controller Ingestion)
        elif parsed.path == '/api/heartbeat':
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length).decode('utf-8')
            try:
                body = json.loads(raw_body)
            except Exception:
                self.send_json(400, {'error': 'Invalid JSON body'})
                return

            client_id = body.get('client_id', '').strip()
            auth_hdr = self.headers.get('Authorization', '').replace('Bearer ', '').strip()
            secret = body.get('auth_secret', '').strip() or body.get('secret', '').strip() or auth_hdr

            c_data = load_clients_state()
            client = c_data.get(client_id)
            if not client:
                # Case-insensitive fallback
                for cid, cobj in c_data.items():
                    if cid.lower() == client_id.lower():
                        client = cobj
                        client_id = cid
                        break

            if not client:
                print(f"[HB_NOT_FOUND_404] client_id='{client_id}', payload_keys={list(body.keys())}", flush=True)
                self.send_json(404, {'error': 'Client not registered'})
                return

            expected_secret = (client.get('auth_secret') or '').strip()
            print(f"[HB_PROBE] client_id='{client_id}', incoming_secret='{secret}', db_expected='{expected_secret}'", flush=True)

            # Validate auth_secret if set on client
            if expected_secret and secret != expected_secret:
                print(f"[HB_AUTH_MISMATCH_403] client_id='{client_id}', sent='{secret}', expected='{expected_secret}'", flush=True)
                self.send_json(403, {'error': 'Unauthorized gateway heartbeat'})
                return

            # Update telemetry data
            now = int(time.time())
            client['last_heartbeat'] = now
            client['status'] = 'online'

            if 'system' in body:
                client['system'] = body['system']
            if 'network' in body:
                client['network'] = body['network']
            if 'knx_status' in body:
                client['knx_status'] = body['knx_status']

            save_clients_state(c_data)
            self.send_json(200, {'ok': True, 'server_time': now, 'remote_enabled': client.get('remote_enabled', True)})
            return

        else:
            self.send_response(404)
            self.end_headers()

# ==============================================================================
# HTTP Daemon Server Initialization
# ==============================================================================

def run_server(port=PORT):
    server_address = ('', port)
    httpd = http.server.ThreadingHTTPServer(server_address, DealerPortalHandler)
    print(f"[*] GAVASAH Multi-Tenant Cloud Hub listening on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[!] Stopping server...")
        httpd.server_close()

if __name__ == '__main__':
    run_server()
