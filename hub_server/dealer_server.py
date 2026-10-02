import os, json, time, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

STATE_FILE = '/srv/gavasah-cloud/clients_state.json'
DYNAMIC_DIR = '/srv/gavasah-cloud/dynamic'
LOGS_DIR = '/srv/gavasah-cloud/client_logs'
PORT = 3000

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DYNAMIC_DIR, exist_ok=True)

def append_client_log(client_id, level, event_type, message):
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_file = os.path.join(LOGS_DIR, f"{client_id}.json")
    logs = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        except Exception:
            logs = []
    
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "epoch": int(time.time()),
        "level": level,
        "type": event_type,
        "message": message
    }
    logs.append(entry)
    if len(logs) > 200:
        logs = logs[-200:]
    try:
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"Failed to write log for {client_id}: {e}")

def generate_seed_logs(client_id):
    now = datetime.datetime.now()
    t = lambda m_ago: (now - datetime.timedelta(minutes=m_ago)).strftime("%Y-%m-%d %H:%M:%S")
    e = lambda m_ago: int(time.time()) - (m_ago * 60)

    if client_id == 'testing-client1':
        return [
            {"timestamp": t(45), "epoch": e(45), "level": "INFO", "type": "BOOT", "message": "Host system booted into RAUC Slot A (HAOS 18.0, generic-aarch64)."},
            {"timestamp": t(44), "epoch": e(44), "level": "INFO", "type": "NETWORK", "message": "Network interface connected. Auto-retrieved local LAN IP: 192.168.1.111, Gateway: 192.168.1.1, MAC: 4E:5B:1C:0E:EF:8D."},
            {"timestamp": t(42), "epoch": e(42), "level": "INFO", "type": "AGENT", "message": "Gavasah Cloud Agent v1.0.1 service initialized with supervisor_api & host_dbus privileges."},
            {"timestamp": t(40), "epoch": e(40), "level": "INFO", "type": "TUNNEL", "message": "AutoSSH reverse tunnel active: Local 8123 -> Hub Port 10010 (testing-client1.gavasah.com)."},
            {"timestamp": t(38), "epoch": e(38), "level": "WARN", "type": "KNX", "message": "KNX Gateway IP unconfigured (127.0.0.1 placeholder detected). Configure physical KNX IP in Add-on options."},
            {"timestamp": t(5), "epoch": e(5), "level": "INFO", "type": "HEARTBEAT", "message": "Telemetry heartbeat received from 49.205.114.180. Slot A healthy, Local IP 192.168.1.111, CPU 0%, RAM 28%."},
            {"timestamp": t(1), "epoch": e(1), "level": "INFO", "type": "HEARTBEAT", "message": "Telemetry heartbeat received from 49.205.114.180. Slot A healthy, Local IP 192.168.1.111, Free Disk: 10.1 GB."}
        ]
    elif client_id == 'reddy-estate':
        return [
            {"timestamp": t(180), "epoch": e(180), "level": "INFO", "type": "BOOT", "message": "System initiated boot sequence on primary Slot A (HAOS 13.1)."},
            {"timestamp": t(175), "epoch": e(175), "level": "ERROR", "type": "RAUC", "message": "Kernel panic detected on Slot A! Hardware watchdog tripped after boot failure."},
            {"timestamp": t(174), "epoch": e(174), "level": "WARN", "type": "RAUC", "message": "RAUC bootloader auto-switched active partition to fallback Slot B."},
            {"timestamp": t(170), "epoch": e(170), "level": "INFO", "type": "BOOT", "message": "System rebooted successfully into backup Slot B (HAOS 13.1 Recovery Mode)."},
            {"timestamp": t(168), "epoch": e(168), "level": "WARN", "type": "ALERT", "message": "Dealer Alert generated: Client running in RECOVERY MODE on Slot B. Slot A requires firmware re-flash."},
            {"timestamp": t(12), "epoch": e(12), "level": "INFO", "type": "KNX", "message": "KNXnet/IP Router 192.168.0.150 reachable (latency: 4.8ms)."}
        ]
    elif client_id == 'sharma-villa':
        return [
            {"timestamp": t(120), "epoch": e(120), "level": "INFO", "type": "BOOT", "message": "Boot Slot A active (HAOS 13.2). Core version 2026.9.3."},
            {"timestamp": t(118), "epoch": e(118), "level": "INFO", "type": "NETWORK", "message": "Auto-retrieved local LAN IP: 192.168.1.105, Gateway: 192.168.1.1."},
            {"timestamp": t(115), "epoch": e(115), "level": "INFO", "type": "KNX", "message": "KNXnet/IP Gateway 192.168.1.111 verified healthy (latency: 1.4ms)."},
            {"timestamp": t(60), "epoch": e(60), "level": "INFO", "type": "HEARTBEAT", "message": "Heartbeat telemetry OK. Slot A good, Memory 41.2%, Disk Free 182.4 GB."}
        ]
    elif client_id == 'verma-penthouse':
        return [
            {"timestamp": t(90), "epoch": e(90), "level": "INFO", "type": "BOOT", "message": "Boot Slot A active (HAOS 13.2). Core version 2026.9.3."},
            {"timestamp": t(88), "epoch": e(88), "level": "INFO", "type": "NETWORK", "message": "Auto-retrieved local LAN IP: 192.168.29.15, Gateway: 192.168.29.1."},
            {"timestamp": t(85), "epoch": e(85), "level": "INFO", "type": "KNX", "message": "KNXnet/IP Gateway 192.168.1.200 verified healthy (latency: 2.1ms)."},
            {"timestamp": t(30), "epoch": e(30), "level": "INFO", "type": "HEARTBEAT", "message": "Heartbeat telemetry OK. Slot A good, Memory 35.0%, Disk Free 210.8 GB."}
        ]
    elif client_id == 'vajju-Vja-house':
        return [
            {"timestamp": t(200), "epoch": e(200), "level": "INFO", "type": "ONBOARD", "message": "Site 'Vajju VJA house' provisioned via Dealer Portal. Assigned Ingress Port 10011, SSH Port 22011."},
            {"timestamp": t(199), "epoch": e(199), "level": "INFO", "type": "ROUTER", "message": "Traefik router registered Host(`vajju-vja-house.gavasah.com`)."},
            {"timestamp": t(195), "epoch": e(195), "level": "WARN", "type": "NETWORK", "message": "Awaiting initial physical hardware connection. Local LAN IP will auto-sync on first heartbeat."}
        ]
    else:
        return [
            {"timestamp": t(10), "epoch": e(10), "level": "INFO", "type": "ONBOARD", "message": f"Client site '{client_id}' registered."},
            {"timestamp": t(9), "epoch": e(9), "level": "INFO", "type": "TUNNEL", "message": "Awaiting device heartbeat and reverse tunnel connection."}
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
    seed = generate_seed_logs(client_id)
    try:
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(seed, f, indent=2)
    except Exception:
        pass
    return seed

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
            "last_heartbeat": int(time.time()) - 4,
            "status": "online",
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
            "last_heartbeat": int(time.time()) - 18,
            "status": "online",
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
            "last_heartbeat": int(time.time()) - 11,
            "status": "warning",
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
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: rgba(18, 24, 38, 0.75);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(56, 189, 248, 0.35);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.25);
            --accent-green: #10b981;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
            --accent-purple: #a855f7;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px;
            background-image: 
                radial-gradient(circle at 15% 10%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 85% 85%, rgba(168, 85, 247, 0.08) 0%, transparent 40%);
        }
        .container { max-width: 1440px; margin: 0 auto; }
        
        /* Header */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 32px;
        }
        .brand { display: flex; align-items: center; gap: 14px; }
        .logo-badge {
            background: linear-gradient(135deg, #38bdf8, #6366f1);
            color: #000;
            font-weight: 900;
            font-size: 18px;
            padding: 8px 14px;
            border-radius: 10px;
            letter-spacing: 1px;
            box-shadow: 0 0 20px var(--primary-glow);
        }
        .title h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
        .title p { font-size: 13px; color: var(--text-muted); }
        
        .header-badges {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .hub-tag {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(56, 189, 248, 0.1);
            color: var(--primary);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
        }
        .heartbeat-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }

        /* Pulsing Dot Styles */
        .pulse-dot-green {
            width: 10px;
            height: 10px;
            background-color: #10b981;
            border-radius: 50%;
            display: inline-block;
            position: relative;
            box-shadow: 0 0 10px #10b981;
        }
        .pulse-dot-green::after {
            content: '';
            position: absolute;
            top: -3px;
            left: -3px;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            border: 2px solid #10b981;
            animation: heartbeat-ripple 1.6s cubic-bezier(0, 0.2, 0.8, 1) infinite;
        }

        .pulse-dot-amber {
            width: 10px;
            height: 10px;
            background-color: #f59e0b;
            border-radius: 50%;
            display: inline-block;
            position: relative;
            box-shadow: 0 0 10px #f59e0b;
        }
        .pulse-dot-amber::after {
            content: '';
            position: absolute;
            top: -3px;
            left: -3px;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            border: 2px solid #f59e0b;
            animation: heartbeat-ripple 1.6s cubic-bezier(0, 0.2, 0.8, 1) infinite;
        }

        .pulse-dot-red {
            width: 10px;
            height: 10px;
            background-color: #ef4444;
            border-radius: 50%;
            display: inline-block;
            position: relative;
            box-shadow: 0 0 10px #ef4444;
        }
        .pulse-dot-red::after {
            content: '';
            position: absolute;
            top: -3px;
            left: -3px;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            border: 2px solid #ef4444;
            animation: heartbeat-ripple 1.6s cubic-bezier(0, 0.2, 0.8, 1) infinite;
        }

        @keyframes heartbeat-ripple {
            0% { transform: scale(0.6); opacity: 1; }
            100% { transform: scale(2.4); opacity: 0; }
        }

        /* Metric Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            backdrop-filter: blur(12px);
            transition: transform 0.2s, border-color 0.2s;
        }
        .metric-card:hover { transform: translateY(-2px); border-color: var(--border-hover); }
        .metric-label { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 8px; }
        .metric-value { font-size: 30px; font-weight: 800; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; gap: 10px; }
        .metric-sub { font-size: 12px; color: var(--text-muted); margin-top: 6px; display: flex; align-items: center; gap: 6px; }

        /* Fleet Section */
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .section-title { font-size: 18px; font-weight: 700; }
        .btn-action {
            background: linear-gradient(135deg, #0284c7, #2563eb);
            color: #fff;
            border: none;
            padding: 10px 18px;
            border-radius: 10px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);
            transition: opacity 0.2s;
        }
        .btn-action:hover { opacity: 0.9; }

        /* Table */
        .table-wrap {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow: hidden;
            backdrop-filter: blur(12px);
        }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th {
            background: rgba(255, 255, 255, 0.02);
            color: var(--text-muted);
            text-align: left;
            padding: 14px 18px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }
        td { padding: 16px 18px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }
        .badge-green { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-red { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
        
        .client-info strong { display: block; font-size: 14px; font-weight: 600; color: #fff; }
        .client-info span { font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
        .mono-val { font-family: 'JetBrains Mono', monospace; color: #cbd5e1; font-size: 12px; }

        .action-links { display: flex; gap: 6px; align-items: center; }
        .btn-sm {
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            border: 1px solid var(--border);
            color: #cbd5e1;
            background: rgba(255, 255, 255, 0.04);
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-sm:hover { background: rgba(255, 255, 255, 0.1); color: #fff; border-color: var(--primary); }
        .btn-primary-sm { background: rgba(56, 189, 248, 0.15); border-color: rgba(56, 189, 248, 0.4); color: var(--primary); }
        .btn-primary-sm:hover { background: var(--primary); color: #000; }
        .btn-logs-sm { background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.4); color: #c084fc; }
        .btn-logs-sm:hover { background: #a855f7; color: #fff; }

        /* Modals */
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            align-items: center;
            justify-content: center;
            z-index: 100;
        }
        .modal-content {
            background: #111827;
            border: 1px solid var(--border);
            border-radius: 16px;
            width: 500px;
            padding: 28px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }
        .modal-header { font-size: 18px; font-weight: 700; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }
        .form-control {
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            color: #fff;
            font-size: 13px;
            font-family: inherit;
        }
        .form-control:focus { outline: none; border-color: var(--primary); }

        /* Dedicated Logs Modal (Only appears when icon is clicked) */
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
        .log-tag-WARN { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
        .log-tag-ERROR { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
        .log-tag-HEARTBEAT { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .log-tag-BOOT { background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
        .log-tag-RAUC { background: rgba(236, 72, 153, 0.2); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.4); }
        .log-msg { word-break: break-word; color: #e2e8f0; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="logo-badge">GAVASAH</div>
                <div class="title">
                    <h1>Dealer Fleet Cloud Hub</h1>
                    <p>Centralized Reverse Tunnel Ingress, KNX net/IP Gateway & Telemetry Control</p>
                </div>
            </div>
            <div class="header-badges">
                <div class="heartbeat-pill">
                    <span class="pulse-dot-green"></span>
                    <span>Heartbeat Monitor: <strong>Live & Listening</strong></span>
                </div>
                <div class="hub-tag">Node: CT 150 (192.168.6.150:3000)</div>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Fleet Nodes</div>
                <div class="metric-value" id="val-total">4</div>
                <div class="metric-sub">Managed villas & customer sites</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Heartbeat Telemetry</div>
                <div class="metric-value" style="color: #34d399;" id="val-online">
                    <span class="pulse-dot-green"></span> Live
                </div>
                <div class="metric-sub">Pings arriving every 30s</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Slot A/B Recovery Warnings</div>
                <div class="metric-value" style="color: #fbbf24;" id="val-warnings">1</div>
                <div class="metric-sub"><span class="pulse-dot-amber"></span> 1 site operating on Slot B fallback</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Central Ingress</div>
                <div class="metric-value" style="color: #38bdf8;">ACTIVE</div>
                <div class="metric-sub">Traefik v3.4 + Port 2222 Tunnel Hub</div>
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
                        <th>Heartbeat Monitoring</th>
                        <th>Boot Slot (RAUC)</th>
                        <th>Local Network (Auto)</th>
                        <th>KNX-IP Gateway</th>
                        <th>Hardware Metrics</th>
                        <th>Actions & Logs</th>
                    </tr>
                </thead>
                <tbody id="fleet-table-body">
                </tbody>
            </table>
        </div>
    </div>

    <!-- Onboard Modal -->
    <div class="modal" id="onboard-modal">
        <div class="modal-content">
            <div class="modal-header">
                <div>Onboard New Client Site</div>
                <div style="cursor: pointer; font-size: 20px;" onclick="closeModal()">&times;</div>
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
                    <label>KNX Gateway IP on Customer LAN (Optional)</label>
                    <input type="text" id="onb-knx" class="form-control" placeholder="e.g. 192.168.1.111" value="">
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 5px;">
                        Note: Home Assistant device LAN IP is automatically retrieved from device hardware.
                    </div>
                </div>
                <div style="display: flex; gap: 10px; margin-top: 24px;">
                    <button type="button" class="btn-sm" style="flex: 1; justify-content: center; padding: 10px;" onclick="closeModal()">Cancel</button>
                    <button type="submit" class="btn-action" style="flex: 2; padding: 10px;">Generate Credentials & Port</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Client Logs Modal (Only appears when clicking the Logs icon) -->
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

    <script>
        let currentLogsClient = null;
        let currentRawLogs = [];
        let currentFilter = 'ALL';

        function openModal() { document.getElementById('onboard-modal').style.display = 'flex'; }
        function closeModal() { document.getElementById('onboard-modal').style.display = 'none'; }

        function openLogsModal(clientId, clientName, domain, status) {
            currentLogsClient = clientId;
            currentFilter = 'ALL';
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.innerText === 'ALL'));
            document.getElementById('log-modal-client-title').innerText = clientName;
            document.getElementById('log-modal-client-sub').innerText = `ID: ${clientId} • Domain: ${domain || clientId + '.gavasah.com'}`;
            
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

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeLogsModal();
                closeModal();
            }
        });

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
            const text = currentRawLogs.map(l => `[${l.timestamp}] [${l.level}] [${l.type || 'SYS'}] ${l.message}`).join('\n');
            navigator.clipboard.writeText(text).then(() => {
                alert('Diagnostic logs copied to clipboard!');
            });
        }

        function escapeHtml(text) {
            if (!text) return '';
            return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        async function fetchFleet() {
            try {
                const res = await fetch('/api/fleet');
                const data = await res.json();
                renderTable(data);
            } catch(e) {
                console.error("Fetch fleet error:", e);
            }
        }

        function renderTable(data) {
            const tbody = document.getElementById('fleet-table-body');
            tbody.innerHTML = '';
            
            let total = 0, online = 0, warnings = 0;
            const now = Math.floor(Date.now() / 1000);

            for (const [id, c] of Object.entries(data)) {
                total++;
                if (c.status === 'online') online++;
                if (c.system && c.system.is_recovery_mode) warnings++;

                const tr = document.createElement('tr');
                
                // Heartbeat status calculations
                const lastHb = c.last_heartbeat;
                let hbBadge = '';

                if (!lastHb) {
                    hbBadge = `
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span class="pulse-dot-amber" style="animation: none; opacity: 0.6;" title="Awaiting first heartbeat"></span>
                            <div>
                                <span class="badge" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3);">PENDING</span>
                                <div style="font-size: 10px; color: #64748b; font-family: 'JetBrains Mono', monospace; margin-top: 3px;">Awaiting First Ping</div>
                            </div>
                        </div>
                    `;
                } else {
                    const diff = Math.max(0, now - lastHb);
                    if (diff <= 45) {
                        hbBadge = `
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <span class="pulse-dot-green" title="Heartbeat healthy"></span>
                                <div>
                                    <span class="badge badge-green">LIVE</span>
                                    <div style="font-size: 11px; color: #94a3b8; font-family: 'JetBrains Mono', monospace; margin-top: 3px;">${diff}s ago</div>
                                </div>
                            </div>
                        `;
                    } else if (diff <= 90) {
                        hbBadge = `
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <span class="pulse-dot-amber" title="Heartbeat delayed"></span>
                                <div>
                                    <span class="badge badge-amber">DELAYED</span>
                                    <div style="font-size: 11px; color: #fbbf24; font-family: 'JetBrains Mono', monospace; margin-top: 3px;">${diff}s ago</div>
                                </div>
                            </div>
                        `;
                    } else {
                        // HEARTBEAT LOST - DISPLAY EXACTLY WHEN IT WAS LOST
                        const lostDate = new Date(lastHb * 1000);
                        const lostTime = lostDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
                        const lostDateStr = lostDate.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
                        
                        let elapsed = '';
                        if (diff < 3600) {
                            elapsed = `${Math.floor(diff / 60)}m ago`;
                        } else if (diff < 86400) {
                            const hours = Math.floor(diff / 3600);
                            const mins = Math.floor((diff % 3600) / 60);
                            elapsed = `${hours}h ${mins}m ago`;
                        } else {
                            const days = Math.floor(diff / 86400);
                            const hours = Math.floor((diff % 86400) / 3600);
                            elapsed = `${days}d ${hours}h ago`;
                        }

                        hbBadge = `
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <span class="pulse-dot-red" title="Heartbeat lost"></span>
                                <div>
                                    <div style="display: flex; align-items: center; gap: 6px;">
                                        <span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4);">LOST</span>
                                        <span style="font-size: 10px; color: #ef4444; font-weight: 700; font-family: 'JetBrains Mono', monospace;">OFFLINE</span>
                                    </div>
                                    <div style="font-size: 11px; color: #fca5a5; font-weight: 600; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">
                                        Lost at: ${lostTime}
                                    </div>
                                    <div style="font-size: 10px; color: #94a3b8; font-family: 'JetBrains Mono', monospace;">
                                        ${lostDateStr} (${elapsed})
                                    </div>
                                </div>
                            </div>
                        `;
                    }
                }

                let slotBadge = `<span class="badge" style="background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2);">Pending Sync</span>`;
                if (c.system && c.system.boot_slot) {
                    slotBadge = `<span class="badge badge-green">Slot ${c.system.boot_slot} (Good)</span>`;
                    if (c.system.is_recovery_mode) {
                        slotBadge = `<span class="badge badge-amber">Slot ${c.system.boot_slot} (Recovery Alert!)</span>`;
                    }
                }

                // KNX-IP Gateway status
                let knxBadge = '';
                const knxStatus = c.knx_status || {};
                const knxIp = c.knx_ip || knxStatus.gateway_ip;

                if (!knxIp || knxIp === '' || (knxIp === '127.0.0.1' && !knxStatus.reachable)) {
                    knxBadge = `
                        <div>
                            <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">NOT CONFIGURED</span>
                            <div style="font-size: 10px; color: #94a3b8; font-family: 'JetBrains Mono', monospace; margin-top: 3px;">
                                Set Gateway IP in Add-on
                            </div>
                        </div>
                    `;
                } else if (knxStatus.reachable) {
                    knxBadge = `
                        <div>
                            <div class="mono-val" style="color: #34d399; font-weight: 600;">${knxIp}</div>
                            <div style="font-size: 11px; color: #10b981; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                                ● Online (${knxStatus.latency_ms || 1.4}ms)
                            </div>
                        </div>
                    `;
                } else {
                    knxBadge = `
                        <div>
                            <div class="mono-val" style="color: #f87171; font-weight: 600;">${knxIp}</div>
                            <div style="font-size: 11px; color: #ef4444; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                                ● Unreachable (${knxStatus.error || 'timeout'})
                            </div>
                        </div>
                    `;
                }

                // Local Network IP - Auto-retrieved from client device
                let netBadge = '';
                const localIp = c.network && c.network.local_ipv4;
                const isAutoRetrieved = localIp && localIp !== 'Unknown' && localIp !== '192.168.1.100' && c.network.mac_address && c.network.mac_address !== '00:00:00:00:00:00';

                if (isAutoRetrieved) {
                    netBadge = `
                        <div class="mono-val" style="font-weight: 600; color: #38bdf8; font-size: 13px;">${localIp}</div>
                        <div style="font-size: 11px; color: #64748b; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                            GW: ${c.network.gateway || '--'}
                        </div>
                        <div style="font-size: 10px; color: #475569; font-family: 'JetBrains Mono', monospace;">
                            MAC: ${c.network.mac_address}
                        </div>
                    `;
                } else {
                    netBadge = `
                        <div style="display: flex; flex-direction: column; gap: 4px;">
                            <span class="badge" style="background: rgba(56, 189, 248, 0.1); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.25); font-size: 10px; width: fit-content;">
                                Auto-Retrieving...
                            </span>
                            <div style="font-size: 10px; color: #64748b; font-family: 'JetBrains Mono', monospace;">
                                Syncs from hardware
                            </div>
                        </div>
                    `;
                }

                // Hardware Metrics
                let hwBadge = '';
                if (c.system && c.system.cpu_percent !== undefined && c.system.disk_free_gb !== undefined && c.system.haos_version) {
                    hwBadge = `
                        <div class="mono-val" style="font-size: 11px;">CPU: ${c.system.cpu_percent}% | RAM: ${c.system.memory_percent}%</div>
                        <div style="font-size: 11px; color: #64748b;">Disk Free: ${c.system.disk_free_gb} GB</div>
                    `;
                } else {
                    hwBadge = `<span style="font-size: 11px; color: #64748b; font-style: italic;">Awaiting telemetry...</span>`;
                }

                const clientNameEsc = (c.name || id).replace(/'/g, "\'");
                const domainEsc = (c.domain || id + '.gavasah.com').replace(/'/g, "\'");
                const statusEsc = (c.status || 'unknown').replace(/'/g, "\'");

                tr.innerHTML = `
                    <td>
                        <div class="client-info">
                            <strong>${c.name}</strong>
                            <span>${c.domain}</span>
                        </div>
                    </td>
                    <td>${hbBadge}</td>
                    <td>${slotBadge}</td>
                    <td>${netBadge}</td>
                    <td>${knxBadge}</td>
                    <td>${hwBadge}</td>
                    <td>
                        <div class="action-links">
                            <a href="https://${c.domain}" target="_blank" class="btn-sm btn-primary-sm" title="Open Home Assistant Web Dashboard">🌐 HA</a>
                            <button class="btn-sm btn-logs-sm" onclick="openLogsModal('${id}', '${clientNameEsc}', '${domainEsc}', '${statusEsc}')" title="Click to view Diagnostic & Telemetry Logs">📜 Logs</button>
                            <button class="btn-sm" onclick="copySSH('${c.ssh_port}', '${c.client_id}')" title="Copy Remote SSH Command">💻 SSH</button>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            }

            document.getElementById('val-total').innerText = total;
            document.getElementById('val-warnings').innerText = warnings;
        }

        function copySSH(port, client) {
            const cmd = `ssh -p ${port} root@ssh.gavasah.com`;
            navigator.clipboard.writeText(cmd).then(() => {
                alert(`Dealer SSH command copied to clipboard:\n\n${cmd}`);
            });
        }

        async function handleOnboard(e) {
            e.preventDefault();
            const name = document.getElementById('onb-name').value;
            const slug = document.getElementById('onb-slug').value;
            const knx = document.getElementById('onb-knx').value;

            const res = await fetch('/api/onboard', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name, slug, knx})
            });
            const out = await res.json();
            alert(`Client ${name} onboarded successfully!\n\nAssigned Tunnel Port: ${out.dashboard_port}\nAssigned SSH Port: ${out.ssh_port}\nDomain: https://${out.domain}`);
            closeModal();
            fetchFleet();
        }

        fetchFleet();
        setInterval(fetchFleet, 3000);
    </script>
</body>
</html>
"""

class DealerPortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/' or parsed.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif parsed.path == '/api/fleet':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r', encoding='utf-8') as f:
                    self.wfile.write(f.read().encode('utf-8'))
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
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len)

        if parsed.path == '/api/heartbeat':
            try:
                payload = json.loads(post_body.decode('utf-8'))
                client_id = payload.get('client_id')
                if client_id:
                    data = {}
                    if os.path.exists(STATE_FILE):
                        with open(STATE_FILE, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                    
                    if client_id not in data:
                        data[client_id] = {
                            "client_id": client_id,
                            "name": client_id.replace('-', ' ').title(),
                            "domain": f"{client_id}.gavasah.com",
                            "dashboard_port": payload.get('tunnels', {}).get('assigned_dashboard_port', 10001),
                            "ssh_port": payload.get('tunnels', {}).get('assigned_ssh_port', 22001),
                            "knx_ip": payload.get('knx_status', {}).get('gateway_ip', '')
                        }

                    data[client_id]['last_heartbeat'] = int(time.time())
                    data[client_id]['status'] = 'online'
                    data[client_id]['system'] = payload.get('system', {})
                    data[client_id]['network'] = payload.get('network', {})
                    data[client_id]['knx_status'] = payload.get('knx_status', {})

                    with open(STATE_FILE, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2)

                    # Log heartbeat entry
                    sys_info = payload.get('system', {})
                    net_info = payload.get('network', {})
                    knx_info = payload.get('knx_status', {})
                    is_rec = sys_info.get('is_recovery_mode', False)
                    slot = sys_info.get('boot_slot', 'A')
                    remote_ip = self.client_address[0]
                    local_ip = net_info.get('local_ipv4', 'Unknown')
                    
                    knx_desc = "Online" if knx_info.get('reachable') else ("Not Configured" if knx_info.get('reason') == 'unconfigured' or knx_info.get('gateway_ip') in ['127.0.0.1', ''] else f"Unreachable ({knx_info.get('error', 'timeout')})")
                    
                    msg = f"Telemetry received from {remote_ip}: RAUC Slot {slot} ({'RECOVERY FALLBACK!' if is_rec else 'Healthy'}) | LAN IP: {local_ip} | KNX: {knx_desc} | Free Disk: {sys_info.get('disk_free_gb', 0)}GB | CPU: {sys_info.get('cpu_percent', 0)}%"
                    append_client_log(client_id, "WARN" if is_rec else "INFO", "HEARTBEAT", msg)

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
                slug = req.get('slug')
                name = req.get('name')
                knx = req.get('knx', '')

                data = {}
                if os.path.exists(STATE_FILE):
                    with open(STATE_FILE, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                existing_dash_ports = [c.get('dashboard_port', 10000) for c in data.values()]
                next_dash_port = max(existing_dash_ports, default=10000) + 1
                next_ssh_port = next_dash_port + 12000

                client_record = {
                    "client_id": slug,
                    "name": name,
                    "domain": f"{slug}.gavasah.com",
                    "dashboard_port": next_dash_port,
                    "ssh_port": next_ssh_port,
                    "knx_ip": knx if knx and knx != '127.0.0.1' else "",
                    "knx_port": 3671,
                    "last_heartbeat": None,
                    "status": "provisioned",
                    "system": {},
                    "network": {
                        "local_ipv4": None,
                        "gateway": None,
                        "mac_address": None
                    },
                    "knx_status": {
                        "configured": bool(knx and knx != '127.0.0.1'),
                        "reachable": False
                    }
                }

                data[slug] = client_record
                with open(STATE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)

                append_client_log(slug, "INFO", "ONBOARD", f"Site '{name}' provisioned. Assigned ingress port: {next_dash_port}, SSH port: {next_ssh_port}.")
                append_client_log(slug, "INFO", "NETWORK", "Awaiting initial physical hardware connection. Local LAN IP will auto-sync on first heartbeat.")

                os.makedirs(DYNAMIC_DIR, exist_ok=True)
                traefik_yaml = f"""http:
  routers:
    {slug}-router:
      rule: "Host(`{slug}.gavasah.com`)"
      entryPoints:
        - websecure
      tls:
        certResolver: le
      service: {slug}-service

  services:
    {slug}-service:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:{next_dash_port}"
"""
                with open(f"{DYNAMIC_DIR}/{slug}.yaml", 'w') as tf:
                    tf.write(traefik_yaml)

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

        self.send_response(404)
        self.end_headers()

if __name__ == '__main__':
    print(f"GAVASAH Dealer Hub starting on port {PORT}...")
    server = HTTPServer(('0.0.0.0', PORT), DealerPortalHandler)
    server.serve_forever()
