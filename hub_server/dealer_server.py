import os, json, time, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

STATE_FILE = '/srv/gavasah-cloud/clients_state.json'
DYNAMIC_DIR = '/srv/gavasah-cloud/dynamic'
PORT = 3000

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
            --bg-card: rgba(18, 24, 38, 0.7);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(56, 189, 248, 0.3);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.2);
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
        .container { max-width: 1400px; margin: 0 auto; }
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
        .hub-tag {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(56, 189, 248, 0.1);
            color: var(--primary);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
        }
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
        .metric-value { font-size: 32px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
        .metric-sub { font-size: 12px; color: var(--text-muted); margin-top: 6px; display: flex; align-items: center; gap: 6px; }
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
        .badge-amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); animation: pulse 2s infinite; }
        @keyframes pulse {
            0% { opacity: 0.8; }
            50% { opacity: 1; filter: drop-shadow(0 0 8px rgba(245, 158, 11, 0.6)); }
            100% { opacity: 0.8; }
        }
        .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
        .dot-green { background: #10b981; box-shadow: 0 0 10px #10b981; }
        .dot-amber { background: #f59e0b; box-shadow: 0 0 10px #f59e0b; }
        .client-info strong { display: block; font-size: 14px; font-weight: 600; color: #fff; }
        .client-info span { font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
        .mono-val { font-family: 'JetBrains Mono', monospace; color: #cbd5e1; font-size: 12px; }
        .action-links { display: flex; gap: 8px; }
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
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.7);
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
        .modal-header { font-size: 18px; font-weight: 700; margin-bottom: 18px; display: flex; justify-content: space-between; }
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
            <div class="hub-tag">Hub Node: CT 150 (192.168.6.150:3000)</div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Fleet Nodes</div>
                <div class="metric-value" id="val-total">3</div>
                <div class="metric-sub">Managed villas & customer sites</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Online & Healthy</div>
                <div class="metric-value" style="color: #34d399;" id="val-online">3</div>
                <div class="metric-sub"><span class="dot dot-green"></span> 100% active reverse tunnels</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Slot A/B Recovery Warnings</div>
                <div class="metric-value" style="color: #fbbf24;" id="val-warnings">1</div>
                <div class="metric-sub"><span class="dot dot-amber"></span> 1 site operating on Slot B fallback</div>
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
                        <th>Status</th>
                        <th>Boot Slot (RAUC)</th>
                        <th>Local Network</th>
                        <th>KNX-IP Gateway</th>
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
        <div class="modal-content">
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
                    <label>KNX Gateway IP (Client Local)</label>
                    <input type="text" id="onb-knx" class="form-control" placeholder="e.g. 192.168.1.111" value="192.168.1.111">
                </div>
                <div style="display: flex; gap: 10px; margin-top: 24px;">
                    <button type="button" class="btn-sm" style="flex: 1; justify-content: center; padding: 10px;" onclick="closeModal()">Cancel</button>
                    <button type="submit" class="btn-action" style="flex: 2; padding: 10px;">Generate Credentials & Port</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function openModal() { document.getElementById('onboard-modal').style.display = 'flex'; }
        function closeModal() { document.getElementById('onboard-modal').style.display = 'none'; }

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

            for (const [id, c] of Object.entries(data)) {
                total++;
                if (c.status === 'online') online++;
                if (c.system && c.system.is_recovery_mode) warnings++;

                const tr = document.createElement('tr');
                
                let slotBadge = `<span class="badge badge-green">Slot ${c.system.boot_slot} (Good)</span>`;
                if (c.system.is_recovery_mode) {
                    slotBadge = `<span class="badge badge-amber">Slot ${c.system.boot_slot} (Recovery Alert!)</span>`;
                }

                let knxBadge = `<span class="mono-val" style="color:#ef4444;">Offline</span>`;
                if (c.knx_status && c.knx_status.reachable) {
                    knxBadge = `<span class="mono-val" style="color:#34d399;">${c.knx_ip} (${c.knx_status.latency_ms}ms)</span>`;
                }

                tr.innerHTML = `
                    <td>
                        <div class="client-info">
                            <strong>${c.name}</strong>
                            <span>${c.domain}</span>
                        </div>
                    </td>
                    <td>
                        <span class="badge badge-green"><span class="dot dot-green"></span> ONLINE</span>
                    </td>
                    <td>${slotBadge}</td>
                    <td>
                        <div class="mono-val">${c.network.local_ipv4}</div>
                        <div style="font-size: 11px; color: #64748b;">GW: ${c.network.gateway}</div>
                    </td>
                    <td>${knxBadge}</td>
                    <td>
                        <div class="mono-val" style="font-size: 11px;">CPU: ${c.system.cpu_percent}% | RAM: ${c.system.memory_percent}%</div>
                        <div style="font-size: 11px; color: #64748b;">Disk Free: ${c.system.disk_free_gb} GB</div>
                    </td>
                    <td>
                        <div class="action-links">
                            <a href="https://${c.domain}" target="_blank" class="btn-sm btn-primary-sm">🌐 Dashboard</a>
                            <button class="btn-sm" onclick="copySSH('${c.ssh_port}', '${c.client_id}')">💻 Copy SSH</button>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            }

            document.getElementById('val-total').innerText = total;
            document.getElementById('val-online').innerText = online;
            document.getElementById('val-warnings').innerText = warnings;
        }

        function copySSH(port, client) {
            const cmd = `ssh -p ${port} root@ssh.gavasah.com`;
            navigator.clipboard.writeText(cmd).then(() => {
                alert(`Dealer SSH command copied to clipboard:\\n\\n${cmd}`);
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
            alert(`Client ${name} onboarded successfully!\\n\\nAssigned Tunnel Port: ${out.dashboard_port}\\nAssigned SSH Port: ${out.ssh_port}\\nDomain: https://${out.domain}`);
            closeModal();
            fetchFleet();
        }

        fetchFleet();
        setInterval(fetchFleet, 5000);
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
                with open(STATE_FILE, 'r') as f:
                    self.wfile.write(f.read().encode('utf-8'))
            else:
                self.wfile.write(b'{}')
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
                        with open(STATE_FILE, 'r') as f:
                            data = json.load(f)
                    
                    if client_id not in data:
                        data[client_id] = {
                            "client_id": client_id,
                            "name": client_id.replace('-', ' ').title(),
                            "domain": f"{client_id}.gavasah.com",
                            "dashboard_port": payload.get('tunnels', {}).get('assigned_dashboard_port', 10001),
                            "ssh_port": payload.get('tunnels', {}).get('assigned_ssh_port', 22001),
                            "knx_ip": payload.get('knx_status', {}).get('gateway_ip', '192.168.1.111')
                        }

                    data[client_id]['last_heartbeat'] = int(time.time())
                    data[client_id]['status'] = 'online'
                    data[client_id]['system'] = payload.get('system', {})
                    data[client_id]['network'] = payload.get('network', {})
                    data[client_id]['knx_status'] = payload.get('knx_status', {})

                    with open(STATE_FILE, 'w') as f:
                        json.dump(data, f, indent=2)

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
                knx = req.get('knx', '192.168.1.111')

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
                    "dashboard_port": next_dash_port,
                    "ssh_port": next_ssh_port,
                    "knx_ip": knx,
                    "knx_port": 3671,
                    "last_heartbeat": int(time.time()),
                    "status": "online",
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
