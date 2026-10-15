#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "    GAVASAH CLOUD AGENT - MULTI-TENANT HA & KNX HUB      "
echo "=========================================================="

OPTIONS_PATH="/data/options.json"

if [ ! -f "$OPTIONS_PATH" ]; then
    echo "[!] Error: $OPTIONS_PATH not found!"
    exit 1
fi

HUB_HOST=$(jq -r '.hub_host // "122.175.49.35"' "$OPTIONS_PATH")
HUB_PORT=$(jq -r '.hub_ssh_port // 2222' "$OPTIONS_PATH")
CLIENT_ID=$(jq -r '.client_id // "client01"' "$OPTIONS_PATH")
DASH_PORT=$(jq -r '.remote_dashboard_port // 10001' "$OPTIONS_PATH")
SSH_PORT=$(jq -r '.remote_ssh_port // 22001' "$OPTIONS_PATH")
KNX_IP=$(jq -r '.knx_gateway_ip // empty' "$OPTIONS_PATH")
KNX_PORT=$(jq -r '.knx_gateway_port // 3671' "$OPTIONS_PATH")

echo "[+] Client Site ID:         $CLIENT_ID"
echo "[+] Central Hub Target:     $HUB_HOST:$HUB_PORT"
echo "[+] Remote Dashboard Port:  $DASH_PORT -> 127.0.0.1:8123"
echo "[+] Remote Admin SSH Port:  $SSH_PORT -> 127.0.0.1:22"

# 1. Setup Persistent SSH Keys
mkdir -p /data/ssh ~/.ssh
chmod 700 /data/ssh ~/.ssh

if [ ! -f /data/ssh/id_ed25519 ]; then
    echo "[+] Generating new Ed25519 SSH client identity for $CLIENT_ID..."
    ssh-keygen -t ed25519 -f /data/ssh/id_ed25519 -N "" -C "$CLIENT_ID@gavasah"
fi

if [ -f /data/ssh/id_ed25519 ]; then
    chmod 600 /data/ssh/id_ed25519
    chmod 644 /data/ssh/id_ed25519.pub 2>/dev/null || true
fi

cp -f /data/ssh/id_ed25519 ~/.ssh/id_ed25519
cp -f /data/ssh/id_ed25519.pub ~/.ssh/id_ed25519.pub
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub 2>/dev/null || true

echo "----------------------------------------------------------"
echo "CLIENT PUBLIC KEY (Authorize on Gavasah Hub if needed):"
cat /data/ssh/id_ed25519.pub
echo "----------------------------------------------------------"

# 2. Disable Strict Host Key Checking for outbound tunnel
cat <<EOF > ~/.ssh/config
Host *
    Port $HUB_PORT
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 5
    ServerAliveInterval 15
    ServerAliveCountMax 3
    IdentityFile ~/.ssh/id_ed25519
EOF

# 2b. Synchronously Pre-register client SSH identity with Gavasah Hub
echo "[+] Registering SSH public key with Gavasah Hub at $HUB_HOST..."
python3 -c "
import urllib.request, json, os, ssl
ctx = ssl._create_unverified_context()
try:
    opts = json.load(open('$OPTIONS_PATH'))
    hub = opts.get('hub_host', '$HUB_HOST')
    cid = opts.get('client_id', '$CLIENT_ID')
    sec = opts.get('auth_key', '')
    pub = open('/data/ssh/id_ed25519.pub').read().strip() if os.path.exists('/data/ssh/id_ed25519.pub') else ''
    if cid and pub:
        payload = json.dumps({'client_id': cid, 'auth_key': sec, 'ssh_public_key': pub}).encode()
        endpoints = [
            f'https://{hub}/api/heartbeat',
            f'http://{hub}:3000/api/heartbeat',
            f'http://{hub}/api/heartbeat',
            'https://dealer.gavasah.com/api/heartbeat',
            'http://122.175.49.35:3000/api/heartbeat'
        ]
        for ep in endpoints:
            try:
                req = urllib.request.Request(ep, data=payload, headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, context=ctx, timeout=4) as r:
                    if r.status in [200, 201]:
                        print('[✓] SSH Public key successfully authorized on Central Hub!')
                        break
            except Exception:
                pass
except Exception:
    pass
"

# 2c. Auto-provision Home Assistant External URL on storage before launch
echo "[+] Verifying Home Assistant External Network URL for $CLIENT_ID.gavasah.com..."
python3 -c "
import json, os
try:
    opts = json.load(open('$OPTIONS_PATH'))
    if opts.get('auto_update_external_url', True):
        cid = opts.get('client_id', '$CLIENT_ID').strip()
        if cid:
            target = f'https://{cid}.gavasah.com'
            for spath in ['/homeassistant/.storage/core.config', '/config/.storage/core.config']:
                if os.path.exists(spath):
                    try:
                        with open(spath, 'r', encoding='utf-8') as f:
                            cfg = json.load(f)
                        if cfg.get('data', {}).get('external_url') != target:
                            cfg.setdefault('data', {})['external_url'] = target
                            tmp = f'{spath}.tmp'
                            with open(tmp, 'w', encoding='utf-8') as f:
                                json.dump(cfg, f, indent=4)
                            os.replace(tmp, spath)
                            print(f'[✓] Pre-configured Home Assistant External URL to {target} in {spath}')
                    except (PermissionError, OSError):
                        pass
                    except Exception:
                        pass
except Exception:
    pass
"

# 2d. Autonomous IP-Ban Purge & Reverse Proxy Self-Healing
echo "[+] Verifying Home Assistant IP ban list and reverse proxy trusted headers..."
python3 - << 'EOF'
import os
config_paths = ['/homeassistant', '/config']
for base in config_paths:
    # 1. Purge loopback/tunnel IPs from ip_bans.yaml
    ban_file = os.path.join(base, 'ip_bans.yaml')
    if os.path.exists(ban_file):
        try:
            with open(ban_file, 'r', encoding='utf-8') as f:
                content = f.read()
            if '127.0.0.1' in content or '::1' in content or '10.42.0.' in content:
                lines = content.splitlines()
                cleaned = []
                skip = False
                for line in lines:
                    is_loopback = (
                        ('127.0.0.1' in line or '::1' in line or '10.42.0.' in line) and
                        (':' in line and not line.startswith(' ') and not line.startswith('\t'))
                    )
                    if is_loopback:
                        skip = True
                        continue
                    elif skip and (line.startswith(' ') or line.startswith('\t')):
                        continue
                    else:
                        skip = False
                        cleaned.append(line)
                with open(ban_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(cleaned) + '\n')
                print(f'[✓] Autonomous Self-Heal: Purged loopback/tunnel ban entries from {ban_file}')
        except Exception as e:
            print(f'[!] Notice: Could not clean {ban_file}: {e}')

    # 2. Ensure ip_ban_enabled: false & trusted_proxies in configuration.yaml
    cfg_file = os.path.join(base, 'configuration.yaml')
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, 'r', encoding='utf-8') as f:
                cfg_content = f.read()
            if 'use_x_forwarded_for' not in cfg_content or 'trusted_proxies' not in cfg_content or 'ip_ban_enabled' not in cfg_content:
                proxy_snippet = '''

# GAVASAH Cloud Autonomous Fleet Ingress Reverse Proxy Configuration
http:
  ip_ban_enabled: false
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
    - ::1
    - 10.42.0.0/24
    - 192.168.0.0/16
    - 172.16.0.0/12
'''
                with open(cfg_file, 'a', encoding='utf-8') as f:
                    f.write(proxy_snippet)
                print(f'[✓] Autonomous Self-Heal: Appended ip_ban_enabled & trusted_proxies configuration to {cfg_file}')
        except Exception as e:
            print(f'[!] Notice: Could not update {cfg_file}: {e}')
EOF

# 3. Start Telemetry Engine in background
echo "[+] Starting Gavasah Telemetry & Slot Watchdog..."
python3 /usr/bin/heartbeat.py &
HEARTBEAT_PID=$!

# 4. Optional KNX UDP & TCP forwarders for remote ETS programming (supports dedicated LAN KNX devices)
if [ -n "$KNX_IP" ] && [ "$KNX_IP" != "127.0.0.1" ] && [ "$KNX_IP" != "localhost" ]; then
    echo "[+] Starting KNXnet/IP UDP Bridge to LAN device $KNX_IP:$KNX_PORT..."
    socat UDP-LISTEN:3671,fork,reuseaddr UDP:$KNX_IP:$KNX_PORT &
    socat TCP-LISTEN:3671,fork UDP:$KNX_IP:$KNX_PORT &
elif [ "$KNX_IP" = "127.0.0.1" ] || [ -z "$KNX_IP" ]; then
    echo "[+] Onboard NCN5120 knxd service handles local port 3671 directly."
fi

# 5. Detect Local Home Assistant Port (80 vs 8123)
LOCAL_HA_PORT=8123
if nc -z 127.0.0.1 80 2>/dev/null || (exec 3<>/dev/tcp/127.0.0.1/80) 2>/dev/null; then
    LOCAL_HA_PORT=80
elif nc -z 127.0.0.1 8123 2>/dev/null || (exec 3<>/dev/tcp/127.0.0.1/8123) 2>/dev/null; then
    LOCAL_HA_PORT=8123
fi
echo "[+] Forwarding Ingress to Local Home Assistant Core on port $LOCAL_HA_PORT..."

# 6. Launch AutoSSH Reverse Tunnel
echo "[+] Launching AutoSSH Ingress Tunnel to $HUB_HOST:$HUB_PORT..."
export AUTOSSH_GATETIME=0
export AUTOSSH_POLL=30

exec autossh -M 0 -N \
    -o "ConnectTimeout=5" \
    -o "ServerAliveInterval=15" \
    -o "ServerAliveCountMax=3" \
    -o "ExitOnForwardFailure=yes" \
    -p "$HUB_PORT" \
    -R "127.0.0.1:${DASH_PORT}:127.0.0.1:${LOCAL_HA_PORT}" \
    -R "127.0.0.1:${SSH_PORT}:127.0.0.1:22" \
    "$CLIENT_ID@$HUB_HOST"
