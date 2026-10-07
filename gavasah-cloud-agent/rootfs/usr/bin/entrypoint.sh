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

# 3. Start Telemetry Engine in background
echo "[+] Starting Gavasah Telemetry & Slot Watchdog..."
python3 /usr/bin/heartbeat.py &
HEARTBEAT_PID=$!

# 4. Optional KNX UDP-to-TCP forwarder for ETS programming
if [ -n "$KNX_IP" ]; then
    echo "[+] Starting KNXnet/IP UDP Bridge to $KNX_IP:$KNX_PORT..."
    socat TCP-LISTEN:3671,fork UDP:$KNX_IP:$KNX_PORT &
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
