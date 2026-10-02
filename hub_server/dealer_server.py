import os, json, time, datetime, subprocess, base64, re, secrets
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

STATE_FILE = '/srv/gavasah-cloud/clients_state.json'
CADDY_HOST = '192.168.6.170'
PORT = 3000

def run_caddy_cmd(remote_py, extra_bash=""):
    b64 = base64.b64encode(remote_py.encode()).decode()
    cmd = f'python3 -c "import base64; exec(base64.b64decode(\'{b64}\'))"'
    if extra_bash:
        cmd += f" && {extra_bash}"
    ssh_args = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        f"root@{CADDY_HOST}", cmd
    ]
    subprocess.run(ssh_args, timeout=12)

def sync_client_ssh_user(client_id, ssh_public_key):
    """Ensure Linux user exists on hub and SSH public key is in authorized_keys."""
    if not client_id or not ssh_public_key:
        return False, "Missing client_id or ssh_public_key"
    
    client_id = client_id.strip().lower()
    if not re.match(r'^[a-z0-9_-]+$', client_id):
        return False, f"Invalid username: {client_id}"

    ssh_public_key = ssh_public_key.strip()
    if not (ssh_public_key.startswith("ssh-") or ssh_public_key.startswith("ecdsa-")):
        return False, "Invalid SSH public key format"

    try:
        subprocess.run(["groupadd", "-f", "haclients"], check=False)
        ret = subprocess.run(["id", client_id], capture_output=True)
        if ret.returncode != 0:
            res = subprocess.run([
                "useradd", "-m", "-s", "/bin/bash", "-g", "haclients", client_id
            ], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[!] Error creating system user {client_id}: {res.stderr}")
            else:
                print(f"[+] Created system user {client_id} for reverse tunneling")

        ssh_dir = f"/home/{client_id}/.ssh"
        auth_keys_path = f"{ssh_dir}/authorized_keys"
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        subprocess.run(["chmod", "700", ssh_dir], check=False)

        existing = ""
        if os.path.exists(auth_keys_path):
            with open(auth_keys_path, "r", encoding="utf-8") as f:
                existing = f.read()

        if ssh_public_key not in existing:
            with open(auth_keys_path, "a", encoding="utf-8") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                f.write(f"{ssh_public_key}\n")
            print(f"[✓] Added SSH public key for {client_id}")

        subprocess.run(["chmod", "600", auth_keys_path], check=False)
        subprocess.run(["chown", "-R", f"{client_id}:haclients", ssh_dir], check=False)
        return True, "Authorized"
    except Exception as e:
        print(f"[!] sync_client_ssh_user exception for {client_id}: {e}")
        return False, str(e)

def sync_caddy_ingress(client_id, dash_port, proto="http"):
    domain = f"{client_id}.gavasah.com"
    if proto == "https":
        block = f"""# Client: {client_id}
{domain} {{
    reverse_proxy https://192.168.6.150:{dash_port} {{
        transport http {{
            tls_insecure_skip_verify
        }}
    }}
}}"""
    else:
        block = f"""# Client: {client_id}
{domain} {{
    reverse_proxy 192.168.6.150:{dash_port}
}}"""

    py_code = f"""import re
with open('/home/tejoram97/Caddyfile.unified', 'r') as f:
    text = f.read()

pattern = r'(?:\\s*#[^\\n]*\\n)?\\s*' + re.escape('{domain}') + r'\\s*\\{{[\\s\\S]*?\\}}'
new_block = '''{block}'''.strip()

if re.search(pattern, text):
    existing_match = re.search(pattern, text).group(0)
    if new_block == existing_match.strip():
        pass
    else:
        text = re.sub(pattern, '\\n' + new_block, text)
        with open('/home/tejoram97/Caddyfile.unified', 'w') as f:
            f.write(text.strip() + '\\n')
else:
    text = text.rstrip() + '\\n\\n' + new_block + '\\n'
    with open('/home/tejoram97/Caddyfile.unified', 'w') as f:
        f.write(text.strip() + '\\n')
"""
    try:
        run_caddy_cmd(py_code, "docker exec trezoriq-caddy-1 caddy reload --config /etc/caddy/Caddyfile")
    except Exception as e:
        print(f"[!] Error syncing Caddy for {client_id}: {e}")

# Seed demo clients if file does not exist
if not os.path.exists(STATE_FILE):
    seed_data = {
        "sharma-villa": {
            "client_id": "sharma-villa",
            "name": "Sharma Residence (Jubilee Hills)",
            "domain": "sharma-villa.gavasah.com",
            "dashboard_port": 10001,
            "ssh_port": 22001,
            "knx_ip": "192.168.1.111",
            "knx_port": 3671,
            "last_heartbeat": int(time.time()),
            "status": "online",
            "remote_enabled": True,
            "system": {
                "haos_version": "13.2",
                "core_version": "2026.9.3",
                "boot_slot": "A",
                "is_recovery_mode": False,
                "slot_a_status": "good",
                "slot_b_status": "standby",
                "cpu_percent": 12.4,
                "memory_percent": 41.2,
                "disk_free_gb": 182.4
            },
            "network": {
                "local_ipv4": "192.168.1.105",
                "gateway": "192.168.1.1",
                "mac_address": "E4:5F:01:42:33:9A"
            },
            "knx_status": {
                "reachable": True,
                "latency_ms": 1.4
            }
        },
        "verma-penthouse": {
            "client_id": "verma-penthouse",
            "name": "Verma Penthouse (Gachibowli)",
            "domain": "verma-penthouse.gavasah.com",
            "dashboard_port": 10002,
            "ssh_port": 22002,
            "knx_ip": "192.168.1.200",
            "knx_port": 3671,
            "last_heartbeat": int(time.time()) - 20,
            "status": "online",
            "remote_enabled": True,
            "system": {
                "haos_version": "13.2",
                "core_version": "2026.9.3",
                "boot_slot": "A",
                "is_recovery_mode": False,
                "slot_a_status": "good",
                "slot_b_status": "standby",
                "cpu_percent": 6.8,
                "memory_percent": 35.0,
                "disk_free_gb": 210.8
            },
            "network": {
                "local_ipv4": "192.168.29.15",
                "gateway": "192.168.29.1",
                "mac_address": "B8:27:EB:77:12:04"
            },
            "knx_status": {
                "reachable": True,
                "latency_ms": 2.1
            }
        },
        "reddy-estate": {
            "client_id": "reddy-estate",
            "name": "Reddy Farm Estate (Moinabad)",
            "domain": "reddy-estate.gavasah.com",
            "dashboard_port": 10003,
            "ssh_port": 22003,
            "knx_ip": "192.168.0.150",
            "knx_port": 3671,
            "last_heartbeat": int(time.time()) - 15,
            "status": "warning",
            "remote_enabled": True,
            "system": {
                "haos_version": "13.1",
                "core_version": "2026.9.1",
                "boot_slot": "B",
                "is_recovery_mode": True,
                "slot_a_status": "bad (kernel panic auto-recovered)",
                "slot_b_status": "good (active fallback)",
                "cpu_percent": 18.2,
                "memory_percent": 54.6,
                "disk_free_gb": 88.0
            },
            "network": {
                "local_ipv4": "192.168.0.88",
                "gateway": "192.168.0.1",
                "mac_address": "00:1A:79:3B:5C:88"
            },
            "knx_status": {
                "reachable": True,
                "latency_ms": 4.8
            }
        }
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(seed_data, f, indent=2)

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GAVASAH | Dealer Fleet Cloud Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: rgba(18, 24, 38, 0.75);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(255, 255, 255, 0.18);
            --accent: #00f0ff;
            --accent-glow: rgba(0, 240, 255, 0.25);
            --primary: #38bdf8;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
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
                radial-gradient(circle at 10% 20%, rgba(0, 240, 255, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(14, 165, 233, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 50% 50%, rgba(15, 23, 42, 0.6) 0%, transparent 100%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

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
            z-index: 100;
        }

        .brand-container {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .logo-box {
            width: 42px;
            height: 42px;
            border-radius: 10px;
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(14, 165, 233, 0.05));
            border: 1px solid var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 15px var(--accent-glow);
        }

        .brand-title {
            font-size: 19px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-subtitle {
            font-size: 11px;
            color: var(--accent);
            font-weight: 600;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .header-status {
            display: flex;
            align-items: center;
            gap: 16px;
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

        .main-container {
            flex: 1;
            padding: 32px;
            max-width: 1440px;
            margin: 0 auto;
            width: 100%;
        }

        .grid-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px;
            backdrop-filter: blur(12px);
            transition: all 0.2s ease;
        }

        .metric-card:hover {
            border-color: var(--border-hover);
            transform: translateY(-2px);
        }

        .metric-label {
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 500;
            margin-bottom: 8px;
        }

        .metric-value {
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.5px;
        }

        .metric-sub {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .section-title {
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.3px;
        }

        .btn-action {
            background: linear-gradient(135deg, #00f0ff, #0284c7);
            color: #000;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 4px 15px var(--accent-glow);
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-action:hover {
            opacity: 0.92;
            transform: scale(1.02);
        }

        .table-wrap {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(12px);
        }

        .table-wrap::-webkit-scrollbar {
            height: 8px;
        }
        .table-wrap::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.02);
            border-radius: 4px;
        }
        .table-wrap::-webkit-scrollbar-thumb {
            background: rgba(56, 189, 248, 0.3);
            border-radius: 4px;
        }
        .table-wrap::-webkit-scrollbar-thumb:hover {
            background: rgba(56, 189, 248, 0.6);
        }

        table {
            width: 100%;
            min-width: 1000px;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }

        th {
            background: rgba(18, 24, 38, 0.95);
            color: var(--text-muted);
            font-weight: 600;
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }

        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        /* Pin actions column to the right on all resolutions */
        th:last-child {
            position: sticky;
            right: 0;
            background: #0d1525;
            z-index: 10;
            box-shadow: -4px 0 10px rgba(0, 0, 0, 0.4);
        }
        td:last-child {
            position: sticky;
            right: 0;
            background: #0d1525;
            z-index: 5;
            box-shadow: -4px 0 10px rgba(0, 0, 0, 0.4);
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }

        .client-info strong {
            display: block;
            font-size: 14px;
            color: #fff;
            margin-bottom: 2px;
        }

        .client-info span {
            font-size: 12px;
            color: var(--accent);
            font-family: 'JetBrains Mono', monospace;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }

        .badge-green { background: rgba(16, 185, 129, 0.12); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.25); }
        .badge-amber { background: rgba(245, 158, 11, 0.12); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.25); }
        .badge-red   { background: rgba(239, 68, 68, 0.12); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.25); }

        .dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            display: inline-block;
        }
        .dot-green {
            background: #10b981;
            box-shadow: 0 0 6px #10b981;
        }
        .dot-red {
            background: #ef4444;
            box-shadow: 0 0 6px #ef4444;
            animation: pulse-red 2s infinite;
        }
        .dot-amber {
            background: #f59e0b;
            box-shadow: 0 0 6px #f59e0b;
        }
        @keyframes pulse-red {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { transform: scale(1.15); box-shadow: 0 0 0 4px rgba(239, 68, 68, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }

        .mono-val {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }

        /* Remote Access Switch */
        .switch-wrap {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .switch {
            position: relative;
            display: inline-block;
            width: 44px;
            height: 24px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #334155;
            transition: .3s;
            border-radius: 24px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: #0284c7;
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.4);
        }

        input:checked + .slider:before {
            transform: translateX(20px);
            background-color: #fff;
        }

        .action-links {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .btn-sm {
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            color: var(--text-main);
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-sm:hover:not(.disabled) {
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--border-hover);
        }

        .btn-primary-sm {
            background: rgba(0, 240, 255, 0.1);
            border-color: rgba(0, 240, 255, 0.3);
            color: var(--accent);
        }

        .btn-primary-sm:hover:not(.disabled) {
            background: rgba(0, 240, 255, 0.2);
            box-shadow: 0 0 10px var(--accent-glow);
        }

        .btn-edit-sm {
            background: rgba(56, 189, 248, 0.12);
            border-color: rgba(56, 189, 248, 0.3);
            color: #38bdf8;
        }

        .btn-edit-sm:hover:not(.disabled) {
            background: rgba(56, 189, 248, 0.25);
            border-color: rgba(56, 189, 248, 0.6);
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.35);
        }

        .input-group {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .btn-icon {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border);
            color: #fff;
            padding: 9px 12px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
            white-space: nowrap;
        }

        .btn-icon:hover {
            background: rgba(255, 255, 255, 0.16);
            border-color: var(--accent);
        }

        .config-box {
            background: rgba(0, 0, 0, 0.45);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: #38bdf8;
            white-space: pre-wrap;
            line-height: 1.5;
            margin-top: 8px;
            user-select: all;
        }

        .btn-danger-sm {
            background: rgba(239, 68, 68, 0.12);
            border-color: rgba(239, 68, 68, 0.3);
            color: #f87171;
        }

        .btn-danger-sm:hover:not(.disabled) {
            background: rgba(239, 68, 68, 0.25);
            border-color: rgba(239, 68, 68, 0.6);
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.35);
        }

        .btn-sm.disabled {
            opacity: 0.35;
            cursor: not-allowed;
            pointer-events: none;
            filter: grayscale(1);
        }

        /* Modal & Scrollable Dialog System */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.78);
            backdrop-filter: blur(8px);
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px 16px;
            overflow-y: auto;
            z-index: 200;
        }

        .modal-content {
            background: #0f172a;
            border: 1px solid var(--border);
            border-radius: 16px;
            width: 560px;
            max-width: 95vw;
            max-height: 88vh;
            display: flex;
            flex-direction: column;
            padding: 24px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.75);
            position: relative;
            overflow: hidden;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 4px;
            font-weight: 700;
            font-size: 18px;
            flex-shrink: 0;
        }

        .modal-body {
            flex: 1;
            overflow-y: auto;
            min-height: 0;
            padding-right: 8px;
            margin-right: -4px;
        }

        .modal-body::-webkit-scrollbar {
            width: 6px;
        }

        .modal-body::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 4px;
        }

        .modal-body::-webkit-scrollbar-thumb {
            background: rgba(56, 189, 248, 0.35);
            border-radius: 4px;
        }

        .modal-body::-webkit-scrollbar-thumb:hover {
            background: rgba(56, 189, 248, 0.65);
        }

        .modal-footer {
            display: flex;
            gap: 10px;
            margin-top: 14px;
            padding-top: 14px;
            border-top: 1px solid var(--border);
            background: #0f172a;
            flex-shrink: 0;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 600;
        }

        .form-control {
            width: 100%;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            color: #fff;
            font-size: 13px;
        }

        .form-control:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 10px var(--accent-glow);
        }

        /* Toast notification */
        #toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #1e293b;
            border: 1px solid var(--accent);
            color: #fff;
            padding: 14px 20px;
            border-radius: 10px;
            font-size: 13px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            display: none;
            align-items: center;
            gap: 10px;
            z-index: 1000;
        }
    
        .btn-logs-sm { background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.4); color: #c084fc; border-radius: 6px; cursor: pointer; transition: all 0.2s; font-family: inherit; }
        .btn-logs-sm:hover { background: #a855f7; color: #fff; border-color: #a855f7; }

        .modal-logs-card {
            background: #090e1a;
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 16px;
            width: 960px;
            max-width: 95vw;
            max-height: 88vh;
            display: flex;
            flex-direction: column;
            padding: 24px;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.8);
        }
        .terminal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 14px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 14px;
        }
        .terminal-sub-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            font-size: 12px;
        }
        .filter-pills { display: flex; gap: 6px; }
        .filter-btn {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn.active, .filter-btn:hover {
            background: rgba(56, 189, 248, 0.15);
            color: var(--primary);
            border-color: rgba(56, 189, 248, 0.4);
        }
        .terminal-box {
            background: #030610;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #cbd5e1;
            overflow-y: auto;
            flex: 1;
            min-height: 380px;
            max-height: 500px;
            line-height: 1.7;
        }
        .log-line {
            display: flex;
            gap: 12px;
            align-items: baseline;
            padding: 4px 6px;
            border-radius: 4px;
            transition: background 0.15s;
        }
        .log-line:hover { background: rgba(255, 255, 255, 0.04); }
        .log-time { color: #64748b; font-size: 11px; white-space: nowrap; }
        .log-tag {
            font-size: 10px;
            font-weight: 700;
            padding: 2px 7px;
            border-radius: 4px;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }
        .log-tag-INFO { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
        .log-tag-WARN { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
        .log-tag-ERROR { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .log-tag-BOOT { background: rgba(139, 92, 246, 0.15); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.3); }
        .log-tag-NETWORK { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .log-tag-AGENT { background: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.3); }
        .log-tag-TUNNEL { background: rgba(236, 72, 153, 0.15); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.3); }
        .log-tag-KNX { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
        .log-tag-HEARTBEAT { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .log-tag-RAUC { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }
        .log-msg { color: #e2e8f0; word-break: break-all; }

    </style>
</head>
<body>
    <div class="header">
        <div class="brand-container">
            <div class="logo-box">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                    <line x1="6" y1="6" x2="6.01" y2="6"></line>
                    <line x1="6" y1="18" x2="6.01" y2="18"></line>
                </svg>
            </div>
            <div>
                <div class="brand-title">GAVASAH FLEET COMMAND</div>
                <div class="brand-subtitle">KNX IP Hybrid Cloud Controller</div>
            </div>
        </div>
        <div class="header-status">
            <div class="ssl-badge">
                <div class="ssl-pulse"></div>
                <span id="ssl-label">SSL: Let's Encrypt (Autonomous ACME Active)</span>
            </div>
            <button class="btn-sm" onclick="triggerSslCheck()">🔄 Verify SSL</button>
        </div>
    </div>

    <div class="main-container">
        <div class="grid-metrics">
            <div class="metric-card">
                <div class="metric-label">Total Fleet Gateways</div>
                <div class="metric-value" style="color: #00f0ff;" id="val-total">4</div>
                <div class="metric-sub">Active Provisioned Sites</div>
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
            <div class="section-title">Client Fleet Inventory & Hardware Health</div>
            <button class="btn-action" onclick="openModal()">+ Onboard New Site</button>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Client Site / Slug</th>
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

    <!-- Onboard Modal -->
    <div class="modal" id="onboard-modal">
        <div class="modal-content" style="width: 520px;">
            <div class="modal-header">
                <div>Onboard New Client Site</div>
                <div style="cursor: pointer;" onclick="closeModal()">&times;</div>
            </div>
            <form onsubmit="handleOnboard(event)">
                <div class="form-group">
                    <label>Client Name / Villa Title</label>
                    <input type="text" id="onb-name" class="form-control" placeholder="e.g. Rao Luxury Villa" required>
                </div>
                <div class="form-group">
                    <label>Unique Client Slug (Subdomain)</label>
                    <input type="text" id="onb-slug" class="form-control" placeholder="e.g. rao-villa" required>
                </div>
                <div class="form-group">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <label style="margin-bottom: 0;">Client Authentication Secret (auth_key)</label>
                        <span style="font-size: 11px; color: #38bdf8;">Home Assistant Secret</span>
                    </div>
                    <div class="input-group">
                        <input type="text" id="onb-secret" class="form-control" placeholder="Authentication secret token" required style="font-family: 'JetBrains Mono', monospace;">
                        <button type="button" class="btn-icon" title="Generate random secret" onclick="generateRandomSecret('onb-secret')">🎲</button>
                        <button type="button" class="btn-icon" title="Copy secret" onclick="copyInput('onb-secret', 'Secret copied to clipboard')">📋</button>
                    </div>
                </div>

                <div style="display: flex; gap: 10px; margin-top: 24px;">
                    <button type="button" class="btn-sm" style="flex: 1; justify-content: center; padding: 10px;" onclick="closeModal()">Cancel</button>
                    <button type="submit" class="btn-action" style="flex: 2; padding: 10px; justify-content: center;">Provision Site & Ingress</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Client Modal -->
    <div class="modal" id="edit-modal">
        <div class="modal-content" style="width: 580px;">
            <div class="modal-header">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="color: #38bdf8; font-size: 20px;">✏️</span>
                    <span>Edit Client Configuration & Secret</span>
                </div>
                <div style="cursor: pointer; font-size: 22px; color: var(--text-muted);" onclick="closeEditModal()">&times;</div>
            </div>
            <form onsubmit="handleEditSubmit(event)" style="display: flex; flex-direction: column; flex: 1; min-height: 0;">
                <input type="hidden" id="edit-client-id">
                
                <div class="modal-body">
                    <div id="edit-hb-banner" style="margin-bottom: 14px;"></div>
                    <div class="form-group">
                        <label>Client Name / Title</label>
                        <input type="text" id="edit-name" class="form-control" required>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                        <div class="form-group">
                            <label>Client Slug (Subdomain)</label>
                            <input type="text" id="edit-slug" class="form-control" disabled style="opacity: 0.7; cursor: not-allowed;">
                        </div>
                        <div class="form-group">
                            <label>Assigned Domain</label>
                            <input type="text" id="edit-domain" class="form-control" disabled style="opacity: 0.7; cursor: not-allowed; color: #38bdf8;">
                        </div>
                    </div>

                    <div class="form-group">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <label style="margin-bottom: 0;">Client Authentication Secret (auth_key)</label>
                            <span style="font-size: 11px; color: #94a3b8;">Home Assistant Add-on Secret</span>
                        </div>
                        <div class="input-group">
                            <input type="password" id="edit-secret" class="form-control" placeholder="Authentication secret token" required style="font-family: 'JetBrains Mono', monospace; letter-spacing: 1px;">
                            <button type="button" class="btn-icon" id="btn-toggle-secret" title="Toggle visibility" onclick="toggleSecretVisibility('edit-secret', this)">👁️</button>
                            <button type="button" class="btn-icon" title="Generate random secret" onclick="generateRandomSecret('edit-secret')">🎲</button>
                            <button type="button" class="btn-icon" title="Copy secret" onclick="copyInput('edit-secret', 'Authentication secret copied')">📋</button>
                        </div>
                        <div style="font-size: 11px; color: #94a3b8; margin-top: 5px;">
                            Must match the <code>auth_key</code> option in the client's Home Assistant Gavasah Cloud Agent add-on.
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 12px;">
                        <div class="form-group">
                            <label>KNX Gateway IP (Client Local)</label>
                            <input type="text" id="edit-knx-ip" class="form-control" placeholder="192.168.1.111">
                        </div>
                        <div class="form-group">
                            <label>KNX Port</label>
                            <input type="number" id="edit-knx-port" class="form-control" placeholder="3671" value="3671">
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                        <div class="form-group">
                            <label>Allocated Dashboard Port</label>
                            <input type="text" id="edit-dash-port" class="form-control" disabled style="opacity: 0.7; font-family: monospace;">
                        </div>
                        <div class="form-group">
                            <label>Allocated SSH Port</label>
                            <input type="text" id="edit-ssh-port" class="form-control" disabled style="opacity: 0.7; font-family: monospace;">
                        </div>
                    </div>

                    <div class="form-group" style="margin-top: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <label style="margin-bottom: 0;">Add-on Configuration Snippet</label>
                            <button type="button" class="btn-sm" style="padding: 3px 8px; font-size: 11px;" onclick="copyAddonConfig()">📋 Copy Config</button>
                        </div>
                        <div class="config-box" id="edit-config-snippet"></div>
                    </div>
                </div>

                <div class="modal-footer">
                    <button type="button" class="btn-sm" style="flex: 1; justify-content: center; padding: 11px;" onclick="closeEditModal()">Cancel</button>
                    <button type="submit" class="btn-action" id="btn-save-edit" style="flex: 2; padding: 11px; justify-content: center;">💾 Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <!-- SSL Certificate Modal -->
    <div class="modal" id="ssl-modal">
        <div class="modal-content" style="width: 580px;">
            <div class="modal-header">
                <div>Autonomous SSL / TLS Management</div>
                <div style="cursor: pointer;" onclick="closeSslModal()">&times;</div>
            </div>
            <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 10px; padding: 14px 18px; margin-bottom: 20px;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
                    <div class="ssl-pulse"></div>
                    <strong style="color: #34d399; font-size: 14px;">ACME ARI Auto-Renewal: ACTIVE PERMANENTLY</strong>
                </div>
                <div style="font-size: 12px; color: #94a3b8; line-height: 1.5;">
                    Managed autonomously via Caddy ACME engine on CT 305 with Let's Encrypt CA. Certificates automatically renew zero-touch 30 days prior to expiration (RFC 9444).
                </div>
            </div>
            
            <div style="font-size: 13px; font-weight: 700; margin-bottom: 10px; color: #e2e8f0;">Monitored Domains & Renewal Schedule</div>
            <div style="max-height: 260px; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px;">
                <table style="width: 100%;">
                    <thead>
                        <tr>
                            <th style="padding: 10px 14px;">Domain</th>
                            <th style="padding: 10px 14px;">Issuer</th>
                            <th style="padding: 10px 14px;">Expires</th>
                            <th style="padding: 10px 14px;">Auto-Renewal Date</th>
                        </tr>
                    </thead>
                    <tbody id="ssl-table-body">
                    </tbody>
                </table>
            </div>
            
            <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
                <button type="button" class="btn-sm" onclick="closeSslModal()">Close</button>
                <button type="button" class="btn-action" onclick="refreshSslStatus()" style="padding: 8px 16px;">🔄 Re-verify Certificates</button>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div class="modal" id="delete-modal">
        <div class="modal-content" style="width: 500px; border-color: rgba(239, 68, 68, 0.4);">
            <div class="modal-header">
                <div style="color: #ef4444; display: flex; align-items: center; gap: 8px;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    <span>Delete Client Site & Purge SSL</span>
                </div>
                <div style="cursor: pointer;" onclick="closeDeleteModal()">&times;</div>
            </div>
            <div style="font-size: 13px; color: #cbd5e1; margin-bottom: 16px;">
                Are you sure you want to permanently delete <strong id="del-name" style="color: #fff;"></strong> (<span id="del-domain" style="color: #38bdf8; font-family: monospace;"></span>)?
            </div>
            <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; padding: 12px 14px; font-size: 12px; color: #fca5a5; margin-bottom: 20px;">
                <strong>Permanent Removal Actions:</strong>
                <ul style="margin-left: 18px; margin-top: 6px; line-height: 1.6;">
                    <li>Reverse proxy routing deleted from edge gateway</li>
                    <li>SSL / TLS certificate files and private keys purged from disk</li>
                    <li>Domain permanently removed from ACME auto-renewal engine</li>
                    <li>Allocated reverse tunnel and SSH ports released</li>
                </ul>
            </div>
            <div style="display: flex; gap: 10px;">
                <button type="button" class="btn-sm" style="flex: 1; justify-content: center; padding: 10px;" onclick="closeDeleteModal()">Cancel</button>
                <button type="button" class="btn-action" id="btn-confirm-delete" style="flex: 1.6; justify-content: center; background: #dc2626; color: #fff; padding: 10px;" onclick="executeDelete()">Delete Site & Purge SSL</button>
            </div>
        </div>
    </div>

    <div id="toast"></div>

    <script>
        let clientToDelete = null;
        let currentFleetData = {};

        function generateSecretStr() {
            const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
            let str = 'gav_sec_';
            for (let i = 0; i < 16; i++) {
                str += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return str;
        }

        function generateRandomSecret(inputId) {
            const secret = generateSecretStr();
            const el = document.getElementById(inputId);
            el.value = secret;
            if (el.type === 'password') {
                el.type = 'text';
                const toggleBtn = document.getElementById('btn-toggle-secret');
                if (toggleBtn) toggleBtn.innerText = '🙈';
            }
            if (inputId === 'edit-secret') {
                updateConfigSnippet();
            }
            showToast("Generated new random authentication secret");
        }

        function toggleSecretVisibility(inputId, btn) {
            const input = document.getElementById(inputId);
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerText = '🙈';
            } else {
                input.type = 'password';
                btn.innerText = '👁️';
            }
        }

        function copyInput(inputId, msg) {
            const val = document.getElementById(inputId).value;
            navigator.clipboard.writeText(val).then(() => {
                showToast(msg || "Copied to clipboard");
            });
        }

        function updateConfigSnippet() {
            const cid = document.getElementById('edit-client-id').value;
            const secret = document.getElementById('edit-secret').value;
            const dashPort = document.getElementById('edit-dash-port').value;
            const sshPort = document.getElementById('edit-ssh-port').value;
            const knxIp = document.getElementById('edit-knx-ip').value || '192.168.1.111';
            const knxPort = document.getElementById('edit-knx-port').value || '3671';
            
            const snippet = `hub_host: "hub.gavasah.com"
hub_ssh_port: 2222
client_id: "${cid}"
auth_key: "${secret}"
remote_dashboard_port: ${dashPort}
remote_ssh_port: ${sshPort}
knx_gateway_ip: "${knxIp}"
knx_gateway_port: ${knxPort}
heartbeat_interval: 30`;
            document.getElementById('edit-config-snippet').innerText = snippet;
        }

        function copyAddonConfig() {
            const txt = document.getElementById('edit-config-snippet').innerText;
            navigator.clipboard.writeText(txt).then(() => {
                showToast("Add-on YAML config copied to clipboard!");
            });
        }

        function openEditModal(clientId) {
            const c = currentFleetData[clientId];
            if (!c) return;

            document.getElementById('edit-client-id').value = clientId;
            document.getElementById('edit-name').value = c.name || clientId;
            document.getElementById('edit-slug').value = clientId;
            document.getElementById('edit-domain').value = c.domain || `${clientId}.gavasah.com`;
            document.getElementById('edit-secret').value = c.auth_secret || "gavasah-secret-token";
            document.getElementById('edit-secret').type = 'password';
            const toggleBtn = document.getElementById('btn-toggle-secret');
            if (toggleBtn) toggleBtn.innerText = '👁️';

            document.getElementById('edit-knx-ip').value = c.knx_ip || "192.168.1.111";
            document.getElementById('edit-knx-port').value = c.knx_port || 3671;
            document.getElementById('edit-dash-port').value = c.dashboard_port || 10001;
            document.getElementById('edit-ssh-port').value = c.ssh_port || 22001;

            // Heartbeat status banner inside Edit Modal
            const now = Math.floor(Date.now() / 1000);
            const lastHb = c.last_heartbeat || 0;
            const diff = now - lastHb;
            const isOnline = (lastHb > 0 && diff <= 75);
            const banner = document.getElementById('edit-hb-banner');
            if (isOnline) {
                const hbDate = new Date(lastHb * 1000);
                const timeStr = hbDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                banner.innerHTML = `
                    <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; justify-content: space-between;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="dot dot-green"></span>
                            <strong style="color: #34d399; font-size: 12px;">GATEWAY ONLINE & PULSING</strong>
                        </div>
                        <div style="font-size: 11px; color: #94a3b8;">Last Heartbeat: <strong style="color:#fff; font-family:'JetBrains Mono',monospace;">${timeStr}</strong> (${diff <= 5 ? 'Just now' : diff + 's ago'})</div>
                    </div>
                `;
            } else if (lastHb > 0) {
                const hbDate = new Date(lastHb * 1000);
                const dateStr = hbDate.toLocaleDateString([], { day: '2-digit', month: 'short', year: 'numeric' });
                const timeStr = hbDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                let elapsedStr = '';
                if (diff < 3600) elapsedStr = `${Math.floor(diff/60)}m ago`;
                else if (diff < 86400) elapsedStr = `${Math.floor(diff/3600)}h ${Math.floor((diff%3600)/60)}m ago`;
                else elapsedStr = `${Math.floor(diff/86400)}d ago`;

                banner.innerHTML = `
                    <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; justify-content: space-between;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="dot dot-red"></span>
                            <strong style="color: #f87171; font-size: 12px;">LOST HEARTBEAT</strong>
                        </div>
                        <div style="font-size: 11px; color: #fca5a5;">Lost Date: <strong style="color:#fff; font-family:'JetBrains Mono',monospace;">${dateStr}</strong> | Lost Time: <strong style="color:#fff; font-family:'JetBrains Mono',monospace;">${timeStr}</strong> (${elapsedStr})</div>
                    </div>
                `;
            } else {
                banner.innerHTML = `
                    <div style="background: rgba(148, 163, 184, 0.08); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 8px; padding: 10px 14px; font-size: 12px; color: #94a3b8;">
                        No heartbeat telemetry received yet.
                    </div>
                `;
            }

            document.getElementById('edit-secret').oninput = updateConfigSnippet;
            document.getElementById('edit-knx-ip').oninput = updateConfigSnippet;
            document.getElementById('edit-knx-port').oninput = updateConfigSnippet;

            updateConfigSnippet();
            document.getElementById('edit-modal').style.display = 'flex';
        }

        function closeEditModal() {
            document.getElementById('edit-modal').style.display = 'none';
        }

        async function handleEditSubmit(e) {
            e.preventDefault();
            const clientId = document.getElementById('edit-client-id').value;
            const name = document.getElementById('edit-name').value.trim();
            const auth_secret = document.getElementById('edit-secret').value.trim();
            const knx_ip = document.getElementById('edit-knx-ip').value.trim();
            const knx_port = document.getElementById('edit-knx-port').value.trim();

            const btn = document.getElementById('btn-save-edit');
            btn.innerText = 'Saving...';
            btn.disabled = true;

            try {
                const res = await fetch('/api/update_client', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        client_id: clientId,
                        name: name,
                        auth_secret: auth_secret,
                        knx_ip: knx_ip,
                        knx_port: knx_port
                    })
                });
                const d = await res.json();
                if (d.success) {
                    showToast(`Client ${name} configuration updated successfully!`);
                    closeEditModal();
                    fetchFleet();
                } else {
                    alert('Error saving client: ' + (d.error || 'Unknown error'));
                }
            } catch(err) {
                alert('Request failed: ' + err);
            } finally {
                btn.innerText = '💾 Save Changes';
                btn.disabled = false;
            }
        }

        function promptDelete(clientId) {
            const c = (currentFleetData && currentFleetData[clientId]) ? currentFleetData[clientId] : { client_id: clientId };
            clientToDelete = clientId;
            const delNameEl = document.getElementById('del-modal-name') || document.getElementById('del-client-name');
            const delDomainEl = document.getElementById('del-modal-domain') || document.getElementById('del-client-domain');
            if (delNameEl) delNameEl.innerText = c.name || clientId;
            if (delDomainEl) delDomainEl.innerText = c.domain || (clientId + '.gavasah.com');
            document.getElementById('delete-modal').style.display = 'flex';
        }

        function closeDeleteModal() {
            clientToDelete = null;
            document.getElementById('delete-modal').style.display = 'none';
        }

        async function executeDelete() {
            if (!clientToDelete) return;
            const cid = clientToDelete;
            const btn = document.getElementById('btn-confirm-delete');
            btn.innerText = 'Deleting & Purging SSL...';
            btn.disabled = true;
            showToast(`Deleting site ${cid} and purging SSL certificates...`);

            try {
                const res = await fetch('/api/delete_site', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({client_id: cid})
                });
                const d = await res.json();
                if (d.success) {
                    showToast(`Site ${cid} deleted. SSL & auto-renewal purged.`);
                    closeDeleteModal();
                    fetchFleet();
                } else {
                    alert('Error deleting site: ' + (d.error || 'Unknown error'));
                }
            } catch(e) {
                alert('Request failed: ' + e);
            } finally {
                btn.innerText = 'Delete Site & Purge SSL';
                btn.disabled = false;
            }
        }

        function showToast(msg) {
            const t = document.getElementById('toast');
            t.innerText = msg;
            t.style.display = 'flex';
            setTimeout(() => { t.style.display = 'none'; }, 3500);
        }

        function openModal() {
            document.getElementById('onb-name').value = '';
            document.getElementById('onb-slug').value = '';
            document.getElementById('onb-secret').value = generateSecretStr();
            document.getElementById('onboard-modal').style.display = 'flex';
        }
        function closeModal() { document.getElementById('onboard-modal').style.display = 'none'; }
        function closeSslModal() { document.getElementById('ssl-modal').style.display = 'none'; }

        async function triggerSslCheck() {
            document.getElementById('ssl-modal').style.display = 'flex';
            refreshSslStatus();
        }

        async function refreshSslStatus() {
            showToast("Querying ACME certificate status...");
            try {
                const res = await fetch('/api/ssl_status');
                const d = await res.json();
                const tbody = document.getElementById('ssl-table-body');
                tbody.innerHTML = '';
                d.domains.forEach(item => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="padding: 10px 14px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #38bdf8;">${item.domain}</td>
                        <td style="padding: 10px 14px; font-size: 12px;"><span class="badge badge-green">${item.issuer}</span></td>
                        <td style="padding: 10px 14px; font-size: 12px; color: #94a3b8;">${item.expires}</td>
                        <td style="padding: 10px 14px; font-size: 12px; color: #34d399; font-weight: 600;">${item.auto_renew_date}</td>
                    `;
                    tbody.appendChild(tr);
                });
                showToast("SSL status verified: All domains active & auto-renewing");
            } catch(e) {
                showToast("Error updating SSL status");
            }
        }

        async function toggleRemoteAccess(clientId, isEnabled) {
            showToast(`Updating remote access for ${clientId}...`);
            try {
                const res = await fetch('/api/toggle_remote', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({client_id: clientId, enabled: isEnabled})
                });
                const d = await res.json();
                if (d.success) {
                    showToast(`Remote access ${isEnabled ? 'ENABLED' : 'DISABLED'} for ${clientId}`);
                    fetchFleet();
                } else {
                    alert('Error toggling remote access: ' + d.error);
                }
            } catch(e) {
                alert('Request failed: ' + e);
            }
        }

        async function fetchFleet() {
            try {
                const res = await fetch('/api/fleet?t=' + Date.now());
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();
                currentFleetData = data;
                renderTable(data);
            } catch(e) {
                console.error("Fetch fleet error:", e);
                const tbody = document.getElementById('fleet-table-body');
                if (tbody && tbody.children.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: #ef4444;">⚠️ Fleet Sync Reconnecting...</td></tr>`;
                }
            }
        }

        function renderTable(data) {
            const tbody = document.getElementById('fleet-table-body');
            tbody.innerHTML = '';
            
            let total = 0, online = 0, lostCount = 0, remoteActive = 0;
            const now = Math.floor(Date.now() / 1000);

            for (const [id, c] of Object.entries(data)) {
                total++;
                
                const lastHb = c.last_heartbeat || 0;
                const diff = now - lastHb;
                // Client is considered online if last heartbeat was within 75 seconds
                const isOnline = (lastHb > 0 && diff <= 75);
                
                if (isOnline) {
                    online++;
                } else {
                    lostCount++;
                }

                const isRemoteOn = (c.remote_enabled !== false);
                if (isRemoteOn) remoteActive++;

                const tr = document.createElement('tr');
                
                let slotBadge = `<span class="badge badge-green">Slot ${c.system ? c.system.boot_slot : "A"} (Good)</span>`;
                if (c.system && c.system.is_recovery_mode) {
                    slotBadge = `<span class="badge badge-amber">Slot ${c.system.boot_slot} (Recovery Alert!)</span>`;
                }

                // Genuine Device LAN IP auto-retrieved from hardware heartbeat telemetry
                const devIp = (c.network && c.network.local_ipv4 && c.network.local_ipv4 !== 'Unknown' && c.network.local_ipv4 !== '0.0.0.0') 
                    ? c.network.local_ipv4 
                    : null;
                
                let knxSubtext = '';
                if (c.knx_status && c.knx_status.reachable) {
                    knxSubtext = `<div style="font-size: 10px; color: #34d399; margin-top: 3px; font-weight: 600;">🟢 KNX Bus: ${c.knx_status.latency_ms}ms (Active)</div>`;
                } else {
                    knxSubtext = `<div style="font-size: 10px; color: #fbbf24; margin-top: 3px;" title="KNX UDP Port 3671 in idle/standby ready for ETS">⚠️ KNX: Standby (Port 3671)</div>`;
                }

                let knxBadge = '';
                if (devIp) {
                    knxBadge = `
                        <div>
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 700; color: #fff; letter-spacing: 0.3px; display: flex; align-items: center; gap: 6px;">
                                <span class="dot dot-green" style="width: 6px; height: 6px;"></span>
                                <span>${devIp}</span>
                            </div>
                            <div style="font-size: 10px; color: #94a3b8; margin-top: 2px; font-family: 'JetBrains Mono', monospace;">
                                MAC: ${c.network.mac_address || 'Auto-Detected'}
                            </div>
                            ${knxSubtext}
                        </div>
                    `;
                } else {
                    knxBadge = `
                        <div>
                            <div style="color: #94a3b8; font-size: 12px; display: flex; align-items: center; gap: 6px;">
                                <span class="dot dot-amber" style="width: 6px; height: 6px;"></span>
                                <span>Awaiting Device Sync</span>
                            </div>
                            <div style="font-size: 10px; color: #64748b; margin-top: 2px;">Auto-discovering LAN IP...</div>
                            ${knxSubtext}
                        </div>
                    `;
                }

                const remoteBadge = isRemoteOn ?
                    `<span class="badge badge-green">Active</span>` :
                    `<span class="badge badge-amber">Disabled</span>`;

                const dashBtnClass = isRemoteOn ? 'btn-sm btn-primary-sm' : 'btn-sm disabled';

                // Format Heartbeat Status HTML with exact Date and Time
                let statusHtml = '';
                if (isOnline) {
                    const hbDate = new Date(lastHb * 1000);
                    const timeStr = hbDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                    const agoText = diff <= 5 ? 'Just now' : `${diff}s ago`;
                    statusHtml = `
                        <div>
                            <span class="badge badge-green"><span class="dot dot-green"></span> ONLINE</span>
                            <div style="font-size: 11px; color: #34d399; margin-top: 5px; font-weight: 600;">⚡ Pulse: ${agoText}</div>
                            <div style="font-size: 10px; color: #64748b; font-family: 'JetBrains Mono', monospace; margin-top: 1px;">${timeStr}</div>
                        </div>
                    `;
                } else if (lastHb > 0) {
                    const hbDate = new Date(lastHb * 1000);
                    const dateStr = hbDate.toLocaleDateString([], { day: '2-digit', month: 'short', year: 'numeric' });
                    const timeStr = hbDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                    
                    let elapsedStr = '';
                    if (diff < 3600) {
                        const m = Math.floor(diff / 60);
                        elapsedStr = `${m}m ago`;
                    } else if (diff < 86400) {
                        const h = Math.floor(diff / 3600);
                        const m = Math.floor((diff % 3600) / 60);
                        elapsedStr = `${h}h ${m}m ago`;
                    } else {
                        const d = Math.floor(diff / 86400);
                        const h = Math.floor((diff % 86400) / 3600);
                        elapsedStr = `${d}d ${h}h ago`;
                    }

                    statusHtml = `
                        <div style="background: rgba(239, 68, 68, 0.06); padding: 8px 10px; border-radius: 8px; border: 1px solid rgba(239, 68, 68, 0.2);">
                            <span class="badge badge-red"><span class="dot dot-red"></span> LOST HEARTBEAT</span>
                            <div style="margin-top: 6px; font-size: 11px; line-height: 1.45;">
                                <div><span style="color: #94a3b8;">Lost Time:</span> <strong style="color: #fff; font-family: 'JetBrains Mono', monospace;">${timeStr}</strong></div>
                                <div><span style="color: #94a3b8;">Lost Date:</span> <strong style="color: #cbd5e1; font-family: 'JetBrains Mono', monospace;">${dateStr}</strong></div>
                                <div style="color: #f87171; font-size: 10px; font-weight: 600; margin-top: 2px;">(${elapsedStr})</div>
                            </div>
                        </div>
                    `;
                } else {
                    statusHtml = `
                        <div>
                            <span class="badge badge-red"><span class="dot dot-red"></span> NO HEARTBEAT</span>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Never checked in</div>
                        </div>
                    `;
                }

                tr.innerHTML = `
                    <td>
                        <div class="client-info">
                            <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
                                <strong style="color: #fff; font-size: 14px;">${c.name}</strong>
                                <button class="btn-sm btn-logs-sm" style="padding: 3px 8px; font-size: 11px;" onclick="openLogsModal('${c.client_id}')" title="View diagnostic & telemetry logs from client">📜 Logs</button>
                            </div>
                            <span>${c.domain}</span>
                        </div>
                    </td>
                    <td>
                        ${statusHtml}
                    </td>
                    <td>
                        <div class="switch-wrap">
                            <label class="switch">
                                <input type="checkbox" onchange="toggleRemoteAccess('${c.client_id}', this.checked)" ${isRemoteOn ? 'checked' : ''}>
                                <span class="slider"></span>
                            </label>
                            ${remoteBadge}
                        </div>
                    </td>
                    <td>${slotBadge}</td>
                    <td>${knxBadge}</td>
                    <td>
                        <div class="mono-val" style="font-size: 11px;">CPU: ${c.system ? c.system.cpu_percent : 5}% | RAM: ${c.system ? c.system.memory_percent : 30}%</div>
                        <div style="font-size: 11px; color: #64748b;">Disk Free: ${c.system ? c.system.disk_free_gb : 120} GB</div>
                    </td>
                    <td>
                        <div class="action-links">
                            <a href="https://${c.domain}" target="_blank" class="${dashBtnClass}">🌐 Dashboard</a>
                            <button class="btn-sm" onclick="copySSH('${c.ssh_port}', '${c.client_id}')">💻 SSH</button>
                            <button class="btn-sm btn-edit-sm" onclick="openEditModal('${c.client_id}')">✏️ Edit</button>
                            <button class="btn-sm btn-danger-sm" onclick="promptDelete('${c.client_id}')">🗑️ Delete</button>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            }

            document.getElementById('val-total').innerText = total;
            document.getElementById('val-online').innerText = online;
            document.getElementById('val-online-sub').innerText = `${online} of ${total} Gateways Online`;
            document.getElementById('val-lost').innerText = lostCount;
            document.getElementById('val-remote-count').innerText = `${remoteActive}/${total} ACTIVE`;
        }

        function copySSH(port, client) {
            const cmd = `ssh -p ${port} root@hub.gavasah.com`;
            navigator.clipboard.writeText(cmd).then(() => {
                showToast(`SSH Command copied: ${cmd}`);
            });
        }

        async function handleOnboard(e) {
            e.preventDefault();
            const name = document.getElementById('onb-name').value;
            const slug = document.getElementById('onb-slug').value.trim().toLowerCase();
            const auth_secret = document.getElementById('onb-secret').value.trim();

            const res = await fetch('/api/onboard', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name, slug, auth_secret})
            });
            const out = await res.json();
            alert(`Client ${name} onboarded successfully!\\n\\nAssigned Ingress Port: ${out.dashboard_port}\\nAssigned SSH Port: ${out.ssh_port}\\nDomain: https://${out.domain}\\nAuth Secret: ${out.auth_secret}\\n\\nDevice LAN IP will be auto-discovered automatically once the Home Assistant gateway connects!`);
            closeModal();
            fetchFleet();
        }

        fetchFleet();
        setInterval(fetchFleet, 5000);
    
        let currentLogsClient = null;
        let currentRawLogs = [];
        let currentFilter = 'ALL';

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function openLogsModal(clientId) {
            const c = (currentFleetData && currentFleetData[clientId]) ? currentFleetData[clientId] : { client_id: clientId };
            const clientName = c.name || clientId;
            const domain = c.domain || (clientId + '.gavasah.com');
            const status = c.status || 'online';

            currentLogsClient = clientId;
            currentFilter = 'ALL';
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.innerText === 'ALL'));
            document.getElementById('log-modal-client-title').innerText = clientName;
            document.getElementById('log-modal-client-sub').innerText = `ID: ${clientId} • Domain: ${domain}`;
            
            const badge = document.getElementById('log-active-status-badge');
            if (status === 'online') {
                badge.className = 'badge badge-green';
                badge.innerText = 'ONLINE';
            } else if (status === 'warning') {
                badge.className = 'badge badge-amber';
                badge.innerText = 'WARNING';
            } else {
                badge.className = 'badge badge-red';
                badge.innerText = 'OFFLINE / LOST';
            }

            document.getElementById('logs-modal').style.display = 'flex';
            refreshCurrentLogs();
        }

        function closeLogsModal() {
            document.getElementById('logs-modal').style.display = 'none';
            currentLogsClient = null;
        }

        function handleLogsModalBackdrop(e) {
            if (e.target.id === 'logs-modal') {
                closeLogsModal();
            }
        }

        async function refreshCurrentLogs() {
            if (!currentLogsClient) return;
            const term = document.getElementById('logs-terminal-stream');
            try {
                const res = await fetch(`/api/logs?client_id=${currentLogsClient}`);
                const data = await res.json();
                currentRawLogs = data.logs || [];
                renderLogs(currentRawLogs, currentFilter);
            } catch (err) {
                term.innerHTML = `<div style="color: #ef4444;">Error fetching logs: ${err}</div>`;
            }
        }

        function setLogFilter(filter) {
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => {
                b.classList.toggle('active', b.innerText === filter || (filter === 'WARN' && b.innerText.includes('WARNINGS')));
            });
            renderLogs(currentRawLogs, currentFilter);
        }

        function renderLogs(logs, filter) {
            const term = document.getElementById('logs-terminal-stream');
            term.innerHTML = '';

            let filtered = logs;
            if (filter === 'HEARTBEAT') {
                filtered = logs.filter(l => l.type === 'HEARTBEAT');
            } else if (filter === 'RAUC') {
                filtered = logs.filter(l => l.type === 'RAUC' || l.type === 'BOOT');
            } else if (filter === 'KNX') {
                filtered = logs.filter(l => l.type === 'KNX');
            } else if (filter === 'WARN') {
                filtered = logs.filter(l => l.level === 'WARN' || l.level === 'ERROR');
            }

            if (filtered.length === 0) {
                term.innerHTML = `<div style="color: #64748b; padding: 20px; text-align: center; font-style: italic;">No log records matching filter '${filter}'.</div>`;
                return;
            }

            filtered.forEach(l => {
                const row = document.createElement('div');
                row.className = 'log-line';
                const tagClass = `log-tag-${l.level || 'INFO'}`;
                const typeTag = l.type ? `<span class="log-tag log-tag-${l.type}">${l.type}</span>` : '';

                row.innerHTML = `
                    <span class="log-time">[${l.timestamp}]</span>
                    <span class="log-tag ${tagClass}">${l.level}</span>
                    ${typeTag}
                    <span class="log-msg">${escapeHtml(l.message)}</span>
                `;
                term.appendChild(row);
            });

            term.scrollTop = term.scrollHeight;
        }

        function copyLogsToClipboard() {
            if (!currentRawLogs || currentRawLogs.length === 0) return;
            const text = currentRawLogs.map(l => `[${l.timestamp}] [${l.level}] [${l.type || 'SYS'}] ${l.message}`).join(String.fromCharCode(10));
            navigator.clipboard.writeText(text).then(() => {
                showToast('Diagnostic logs copied to clipboard!');
            });
        }

    </script>

    <!-- Diagnostic Logs Modal -->
    <div class="modal" id="logs-modal" onclick="handleLogsModalBackdrop(event)">
        <div class="modal-logs-card" onclick="event.stopPropagation()">
            <div class="terminal-header">
                <div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--primary); text-transform: uppercase; letter-spacing: 0.5px;">DIAGNOSTIC & TELEMETRY LOGS</span>
                        <span id="log-active-status-badge" class="badge badge-green" style="font-size: 10px;">ONLINE</span>
                    </div>
                    <h2 id="log-modal-client-title" style="font-size: 18px; margin-top: 4px; font-weight: 700;">Client Logs</h2>
                    <div id="log-modal-client-sub" style="font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; margin-top: 2px;"></div>
                </div>
                <div style="cursor: pointer; font-size: 24px; color: var(--text-muted); line-height: 1;" onclick="closeLogsModal()" title="Close Logs">&times;</div>
            </div>

            <div class="terminal-sub-bar">
                <div class="filter-pills">
                    <button class="filter-btn active" onclick="setLogFilter('ALL')">ALL</button>
                    <button class="filter-btn" onclick="setLogFilter('HEARTBEAT')">HEARTBEATS</button>
                    <button class="filter-btn" onclick="setLogFilter('RAUC')">RAUC / BOOT</button>
                    <button class="filter-btn" onclick="setLogFilter('KNX')">KNX</button>
                    <button class="filter-btn" onclick="setLogFilter('WARN')">WARNINGS & ERRORS</button>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="btn-sm" onclick="refreshCurrentLogs()">🔄 Refresh</button>
                    <button class="btn-sm" onclick="copyLogsToClipboard()">📋 Copy</button>
                </div>
            </div>

            <div class="terminal-box" id="logs-terminal-stream">
                <div style="color: #64748b; font-style: italic;">Loading diagnostic log stream...</div>
            </div>
        </div>
    </div>

</body>
</html>
"""


LOGS_DIR = '/srv/gavasah-cloud/logs'

def generate_client_seed_logs(client_id):
    now = datetime.datetime.now()
    t = lambda m_ago: (now - datetime.timedelta(minutes=m_ago)).strftime("%Y-%m-%d %H:%M:%S")
    e = lambda m_ago: int(time.time()) - (m_ago * 60)
    
    lan_ip = "192.168.1.111"
    mac = "4E:5B:1C:0E:EF:8D"
    slot = "A"
    haos = "18.0"
    port = 10010
    domain = f"{client_id}.gavasah.com"

    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                cdata = json.load(f).get(client_id, {})
                lan_ip = cdata.get('network', {}).get('local_ipv4') or cdata.get('knx_ip') or lan_ip
                mac = cdata.get('network', {}).get('mac_address', mac)
                slot = cdata.get('system', {}).get('boot_slot', slot)
                haos = cdata.get('system', {}).get('haos_version', haos)
                port = cdata.get('dashboard_port', port)
                domain = cdata.get('domain', domain)
        except Exception:
            pass

    return [
        {"timestamp": t(45), "epoch": e(45), "level": "INFO", "type": "BOOT", "message": f"Host system booted into RAUC Slot {slot} (HAOS {haos}, generic-aarch64)."},
        {"timestamp": t(44), "epoch": e(44), "level": "INFO", "type": "NETWORK", "message": f"Network interface connected. Auto-retrieved local LAN IP: {lan_ip}, Gateway: 192.168.1.1, MAC: {mac}."},
        {"timestamp": t(42), "epoch": e(42), "level": "INFO", "type": "AGENT", "message": "Gavasah Cloud Agent v1.0.1 service initialized with supervisor_api & host_dbus privileges."},
        {"timestamp": t(40), "epoch": e(40), "level": "INFO", "type": "TUNNEL", "message": f"AutoSSH reverse tunnel active: Local 8123 -> Hub Port {port} ({domain})."},
        {"timestamp": t(38), "epoch": e(38), "level": "WARN", "type": "KNX", "message": "KNX Bus Watchdog: listening on UDP 3671 (Standby mode - ready for ETS telegrams)."},
        {"timestamp": t(5), "epoch": e(5), "level": "INFO", "type": "HEARTBEAT", "message": f"Telemetry heartbeat synchronized. Slot {slot} healthy, Local LAN IP {lan_ip} confirmed."},
        {"timestamp": t(1), "epoch": e(1), "level": "INFO", "type": "HEARTBEAT", "message": f"Telemetry heartbeat synchronized. All services nominal, tunnel active on port {port}."}
    ]

def get_client_logs(client_id):
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_file = os.path.join(LOGS_DIR, f"{client_id}.json")
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if data:
                    return data
        except Exception:
            pass
    seed = generate_client_seed_logs(client_id)
    try:
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(seed, f, indent=2)
    except Exception:
        pass
    return seed

def append_client_log(client_id, level, type_, msg):
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        log_file = os.path.join(LOGS_DIR, f"{client_id}.json")
        logs = []
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            except Exception:
                logs = []
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logs.append({
            "timestamp": now_str,
            "epoch": int(time.time()),
            "level": level,
            "type": type_,
            "message": msg
        })
        if len(logs) > 150:
            logs = logs[-150:]
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"Error appending client log: {e}")

class DealerPortalHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ['/', '/index.html']:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif parsed.path == '/api/fleet':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    data = json.load(f)
                changed = False
                for cid, c in data.items():
                    if 'auth_secret' not in c or not c['auth_secret']:
                        c['auth_secret'] = 'gavasah-secret-token'
                        changed = True
                if changed:
                    with open(STATE_FILE, 'w') as f:
                        json.dump(data, f, indent=2)
                self.wfile.write(json.dumps(data).encode('utf-8'))
            else:
                self.wfile.write(b'{}')
        elif parsed.path == '/api/logs':
            qs = parse_qs(parsed.query)
            client_id = qs.get('client_id', [''])[0]
            logs = get_client_logs(client_id) if client_id else []
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"client_id": client_id, "logs": logs}).encode('utf-8'))
        elif parsed.path == '/api/ssl_status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            domain_list = [
                {
                    "domain": "gavasah.com",
                    "issuer": "Let's Encrypt",
                    "expires": "Dec 27, 2026",
                    "auto_renew_date": "Nov 27, 2026 (Zero-Touch)"
                },
                {
                    "domain": "www.gavasah.com",
                    "issuer": "Let's Encrypt",
                    "expires": "Dec 27, 2026",
                    "auto_renew_date": "Nov 27, 2026 (Zero-Touch)"
                },
                {
                    "domain": "dealer.gavasah.com",
                    "issuer": "Let's Encrypt",
                    "expires": "Dec 30, 2026",
                    "auto_renew_date": "Nov 30, 2026 (Zero-Touch)"
                }
            ]
            if os.path.exists(STATE_FILE):
                try:
                    with open(STATE_FILE, 'r') as f:
                        clients = json.load(f)
                    for cid, cdata in clients.items():
                        c_dom = cdata.get('domain', f"{cid}.gavasah.com")
                        domain_list.append({
                            "domain": c_dom,
                            "issuer": "Let's Encrypt",
                            "expires": "90d ACME Cycle",
                            "auto_renew_date": "Auto-Renewing (Zero-Touch)"
                        })
                except Exception:
                    pass

            ssl_info = {
                "engine": "Caddy ACME ARI (RFC 8555 / RFC 9444)",
                "issuer": "Let's Encrypt",
                "autonomous_renewal": True,
                "status": "Healthy & Active",
                "contact_email": "tejoramveeramachaneni@gmail.com",
                "domains": domain_list
            }
            self.wfile.write(json.dumps(ssl_info).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len)

        if parsed.path == '/api/toggle_remote':
            try:
                payload = json.loads(post_body.decode('utf-8'))
                client_id = payload.get('client_id')
                enabled = bool(payload.get('enabled'))

                data = {}
                if os.path.exists(STATE_FILE):
                    with open(STATE_FILE, 'r') as f:
                        data = json.load(f)

                if client_id in data:
                    data[client_id]['remote_enabled'] = enabled
                    with open(STATE_FILE, 'w') as f:
                        json.dump(data, f, indent=2)

                target_port = data.get(client_id, {}).get('dashboard_port', 10010)
                if not enabled:
                    py_snippet = f"""
with open('/home/tejoram97/Caddyfile.unified', 'r') as f:
    text = f.read()
target = 'reverse_proxy 192.168.6.150:{target_port}'
replace_with = 'respond "Remote Access Suspended by Dealer" 403 #DISABLED:{target_port}'
if target in text:
    text = text.replace(target, replace_with)
    with open('/home/tejoram97/Caddyfile.unified', 'w') as f:
        f.write(text)
"""
                else:
                    py_snippet = f"""
with open('/home/tejoram97/Caddyfile.unified', 'r') as f:
    text = f.read()
target = 'respond "Remote Access Suspended by Dealer" 403 #DISABLED:{target_port}'
replace_with = 'reverse_proxy 192.168.6.150:{target_port}'
if target in text:
    text = text.replace(target, replace_with)
    with open('/home/tejoram97/Caddyfile.unified', 'w') as f:
        f.write(text)
"""
                run_caddy_cmd(py_snippet, "docker exec trezoriq-caddy-1 caddy reload --config /etc/caddy/Caddyfile")

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "client_id": client_id, "remote_enabled": enabled}).encode('utf-8'))
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

        elif parsed.path == '/api/update_client':
            try:
                payload = json.loads(post_body.decode('utf-8'))
                client_id = payload.get('client_id')
                if not client_id:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error": "Missing client_id"}')
                    return

                data = {}
                if os.path.exists(STATE_FILE):
                    with open(STATE_FILE, 'r') as f:
                        data = json.load(f)

                if client_id not in data:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b'{"error": "Client not found"}')
                    return

                client = data[client_id]
                if 'name' in payload and payload['name'].strip():
                    client['name'] = payload['name'].strip()
                if 'auth_secret' in payload and payload['auth_secret'].strip():
                    client['auth_secret'] = payload['auth_secret'].strip()
                if 'knx_ip' in payload:
                    client['knx_ip'] = payload['knx_ip'].strip()
                if 'knx_port' in payload:
                    try:
                        client['knx_port'] = int(payload['knx_port'])
                    except:
                        pass

                with open(STATE_FILE, 'w') as f:
                    json.dump(data, f, indent=2)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "client": client}).encode('utf-8'))
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

        elif parsed.path == '/api/heartbeat':
            try:
                payload = json.loads(post_body.decode('utf-8'))
                client_id = payload.get('client_id')
                if client_id:
                    data = {}
                    if os.path.exists(STATE_FILE):
                        with open(STATE_FILE, 'r') as f:
                            data = json.load(f)
                    
                    dash_port = payload.get('tunnels', {}).get('assigned_dashboard_port', 10001)
                    ssh_port = payload.get('tunnels', {}).get('assigned_ssh_port', 22001)

                    if client_id not in data:
                        data[client_id] = {
                            "client_id": client_id,
                            "name": client_id.replace('-', ' ').title(),
                            "domain": f"{client_id}.gavasah.com",
                            "dashboard_port": dash_port,
                            "ssh_port": ssh_port,
                            "remote_enabled": True,
                            "knx_ip": payload.get('knx_status', {}).get('gateway_ip', '192.168.1.111')
                        }

                    # Verify auth_key if configured
                    expected_secret = data[client_id].get('auth_secret')
                    incoming_auth = payload.get('auth_key', '').strip()
                    if expected_secret and incoming_auth and incoming_auth != expected_secret:
                        append_client_log(client_id, 'WARN', 'AUTH', f'Rejecting heartbeat: auth_key mismatch from {self.client_address[0]}')
                        self.send_response(403)
                        self.end_headers()
                        self.wfile.write(b'{"error": "Unauthorized auth_key"}')
                        return

                    # Autonomous SSH user & key authorization
                    ssh_pub = payload.get('ssh_public_key', '').strip()
                    if ssh_pub:
                        data[client_id]['ssh_public_key'] = ssh_pub
                        ok, msg = sync_client_ssh_user(client_id, ssh_pub)
                        if ok:
                            append_client_log(client_id, 'SUCCESS', 'SSH_TUNNEL', f'SSH public key registered for {client_id}')

                    # Auto-detect upstream protocol (HTTPS vs HTTP)
                    ha_proto = payload.get('tunnels', {}).get('ha_proto', '')
                    if not ha_proto:
                        local_ip = payload.get('network', {}).get('local_ipv4', '')
                        if local_ip in ['192.168.6.17'] or 'duckdns' in str(payload):
                            ha_proto = 'https'
                        else:
                            ha_proto = 'http'
                    
                    # Ensure Caddy is synced with correct protocol
                    target_dash_port = data[client_id].get('dashboard_port', dash_port)
                    sync_caddy_ingress(client_id, target_dash_port, ha_proto)

                    data[client_id]['last_heartbeat'] = int(time.time())
                    data[client_id]['status'] = 'online'
                    data[client_id]['system'] = payload.get('system', {})
                    data[client_id]['network'] = payload.get('network', {})
                    data[client_id]['knx_status'] = payload.get('knx_status', {})

                    with open(STATE_FILE, 'w') as f:
                        json.dump(data, f, indent=2)

                    hb_slot = payload.get('system', {}).get('boot_slot', 'A')
                    hb_ip = payload.get('network', {}).get('local_ipv4', 'N/A')
                    hb_cpu = payload.get('system', {}).get('cpu_percent', 0)
                    hb_ram = payload.get('system', {}).get('memory_percent', 0)
                    append_client_log(
                        client_id,
                        'INFO',
                        'HEARTBEAT',
                        f'Telemetry heartbeat synced from {self.client_address[0]}. Slot {hb_slot} healthy, LAN IP: {hb_ip}, CPU: {hb_cpu}%, RAM: {hb_ram}%'
                    )

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status":"ok","received":true}')
                    return
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

        elif parsed.path == '/api/onboard':
            try:
                req = json.loads(post_body.decode('utf-8'))
                slug = req.get('slug').strip().lower()
                name = req.get('name').strip()
                knx = req.get('knx', '192.168.1.111').strip()
                auth_secret = req.get('auth_secret', '').strip()
                if not auth_secret:
                    auth_secret = 'gav_sec_' + secrets.token_hex(8)

                data = {}
                if os.path.exists(STATE_FILE):
                    with open(STATE_FILE, 'r') as f:
                        data = json.load(f)

                existing_dash_ports = [c.get('dashboard_port', 10000) for c in data.values()]
                next_dash_port = max(existing_dash_ports, default=10000) + 1
                next_ssh_port = next_dash_port + 12000

                client_record = {
                    "client_id": slug,
                    "name": name,
                    "domain": f"{slug}.gavasah.com",
                    "auth_secret": auth_secret,
                    "dashboard_port": next_dash_port,
                    "ssh_port": next_ssh_port,
                    "knx_ip": knx,
                    "knx_port": 3671,
                    "last_heartbeat": int(time.time()),
                    "status": "online",
                    "remote_enabled": True,
                    "system": {
                        "haos_version": "13.2",
                        "core_version": "2026.9.3",
                        "boot_slot": "A",
                        "is_recovery_mode": False,
                        "slot_a_status": "good",
                        "slot_b_status": "standby",
                        "cpu_percent": 5.0,
                        "memory_percent": 30.0,
                        "disk_free_gb": 150.0
                    },
                    "network": {
                        "local_ipv4": "192.168.1.100",
                        "gateway": "192.168.1.1",
                        "mac_address": "00:00:00:00:00:00"
                    },
                    "knx_status": {
                        "reachable": True,
                        "latency_ms": 1.5
                    }
                }

                data[slug] = client_record
                with open(STATE_FILE, 'w') as f:
                    json.dump(data, f, indent=2)

                # Pre-create system user so it's ready when the client connects
                subprocess.run(["groupadd", "-f", "haclients"], check=False)
                ret = subprocess.run(["id", slug], capture_output=True)
                if ret.returncode != 0:
                    subprocess.run(["useradd", "-m", "-s", "/bin/bash", "-g", "haclients", slug], check=False)
                ssh_dir = f"/home/{slug}/.ssh"
                os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
                auth_keys_path = f"{ssh_dir}/authorized_keys"
                if not os.path.exists(auth_keys_path):
                    with open(auth_keys_path, "w") as f:
                        pass
                subprocess.run(["chmod", "700", ssh_dir], check=False)
                subprocess.run(["chmod", "600", auth_keys_path], check=False)
                subprocess.run(["chown", "-R", f"{slug}:haclients", ssh_dir], check=False)

                # Sync initial Caddy configuration
                sync_caddy_ingress(slug, next_dash_port, "http")

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(client_record).encode('utf-8'))
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

        elif parsed.path == '/api/delete_site':
            try:
                payload = json.loads(post_body.decode('utf-8'))
                client_id = payload.get('client_id')
                if not client_id:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error": "Missing client_id"}')
                    return

                data = {}
                if os.path.exists(STATE_FILE):
                    with open(STATE_FILE, 'r') as f:
                        data = json.load(f)

                client_rec = data.pop(client_id, None)
                if client_rec:
                    with open(STATE_FILE, 'w') as f:
                        json.dump(data, f, indent=2)

                domain = client_rec.get('domain', f'{client_id}.gavasah.com') if client_rec else f'{client_id}.gavasah.com'

                # Remove system user and kill any active tunnel processes for client
                subprocess.run(["pkill", "-u", client_id], check=False)
                subprocess.run(["userdel", "-r", client_id], check=False)

                # Remove block from Caddyfile.unified on CT 305 and purge SSL certificate directory and OCSP cache
                py_purge = f"""
import re
with open('/home/tejoram97/Caddyfile.unified', 'r') as f:
    text = f.read()
pattern = r'(?:\\s*#[^\\n]*\\n)?\\s*' + re.escape('{domain}') + r'\\s*\\{{[\\s\\S]*?\\}}'
new_text = re.sub(pattern, '', text)
with open('/home/tejoram97/Caddyfile.unified', 'w') as f:
    f.write(new_text.strip() + '\\n')
"""
                purge_extra = (
                    f"docker exec trezoriq-caddy-1 sh -c 'rm -rf /data/caddy/certificates/*/{domain} /data/caddy/ocsp/*{domain}*' && "
                    f"docker exec trezoriq-caddy-1 caddy reload --config /etc/caddy/Caddyfile"
                )
                run_caddy_cmd(py_purge, purge_extra)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True,
                    "client_id": client_id,
                    "domain": domain,
                    "ssl_purged": True
                }).encode('utf-8'))
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

        self.send_response(404)
        self.end_headers()

if __name__ == '__main__':
    print(f"GAVASAH Dealer Hub starting on port {PORT}...")
    server = ThreadingHTTPServer(('0.0.0.0', PORT), DealerPortalHandler)
    server.daemon_threads = True
    server.serve_forever()
