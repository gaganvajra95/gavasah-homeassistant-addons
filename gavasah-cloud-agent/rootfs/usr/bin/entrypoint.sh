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

cp /data/ssh/id_ed25519 ~/.ssh/id_ed25519
cp /data/ssh/id_ed25519.pub ~/.ssh/id_ed25519.pub
chmod 600 ~/.ssh/id_ed25519

echo "----------------------------------------------------------"
echo "CLIENT PUBLIC KEY (Authorize on Gavasah Hub if needed):"
cat /data/ssh/id_ed25519.pub
echo "----------------------------------------------------------"

# 2. Disable Strict Host Key Checking for outbound tunnel
cat <<EOF > ~/.ssh/config
Host $HUB_HOST
    Port $HUB_PORT
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ServerAliveInterval 30
    ServerAliveCountMax 3
    IdentityFile ~/.ssh/id_ed25519
EOF

# 3. Start Telemetry Engine in background
echo "[+] Starting Gavasah Telemetry & Slot Watchdog..."
python3 /usr/bin/heartbeat.py &
HEARTBEAT_PID=$!

# 4. Optional KNX UDP-to-TCP forwarder for ETS programming
if [ -n "$KNX_IP" ]; then
    echo "[+] Starting KNXnet/IP UDP Bridge to $KNX_IP:$KNX_PORT..."
    socat TCP-LISTEN:3671,fork UDP:$KNX_IP:$KNX_PORT &
fi

# 5. Launch AutoSSH Reverse Tunnel
echo "[+] Launching AutoSSH Ingress Tunnel to $HUB_HOST:$HUB_PORT..."
export AUTOSSH_GATETIME=0
export AUTOSSH_POLL=30

exec autossh -M 0 -N \
    -o "ServerAliveInterval=30" \
    -o "ServerAliveCountMax=3" \
    -o "ExitOnForwardFailure=yes" \
    -p "$HUB_PORT" \
    -R "127.0.0.1:${DASH_PORT}:127.0.0.1:8123" \
    -R "127.0.0.1:${SSH_PORT}:127.0.0.1:22" \
    "$CLIENT_ID@$HUB_HOST"
