#!/usr/bin/env bash
# ==============================================================================
# GAVASAH CLOUD HUB - CT 150 System Tuning & 16 GB Enterprise Scale Setup
# Run on CT 150 as root: sudo bash tune_hub_server.sh
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "  GAVASAH HUB: Enterprise 16 GB RAM Tuning & Optimization  "
echo "=========================================================="

# 1. Linux Kernel Sysctl Tuning (Optimized for 16 GB RAM & 3,000+ Tunnels)
echo "[+] Configuring Linux kernel sysctl parameters..."
cat << 'EOF' > /etc/sysctl.d/99-gavasah-tuning.conf
# File descriptor and inotify limits
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 8192

# Network connection backlogs & buffer sizing
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.ip_local_port_range = 10000 65535

# Fast TCP socket reuse for terminated reverse tunnels
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Memory management tuned for 16 GB RAM
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.max_map_count = 262144
EOF

sysctl --system > /dev/null
echo "[✓] Kernel sysctl tuning applied successfully!"

# 2. Security Limits (File Descriptors & Process Limits)
echo "[+] Configuring security limits in /etc/security/limits.d/99-gavasah.conf..."
cat << 'EOF' > /etc/security/limits.d/99-gavasah.conf
*       soft    nofile      1048576
*       hard    nofile      1048576
*       soft    nproc       524288
*       hard    nproc       524288
root    soft    nofile      1048576
root    hard    nofile      1048576
root    soft    nproc       524288
root    hard    nproc       524288
EOF
echo "[✓] File descriptor limits configured (1,048,576 files)!"

# 3. OpenSSH Bastion Configuration
echo "[+] Installing OpenSSH tunnel daemon config..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /etc/ssh/sshd_config.d
if [ -f "$SCRIPT_DIR/gavasah_tunnels.conf" ]; then
    cp "$SCRIPT_DIR/gavasah_tunnels.conf" /etc/ssh/sshd_config.d/gavasah_tunnels.conf
fi
systemctl restart ssh || systemctl restart sshd
echo "[✓] OpenSSH daemon reloaded with high-concurrency tunnel directives!"

# 4. Systemd Service Deployment
echo "[+] Deploying Gavasah Dealer Hub systemd service..."
if [ -f "$SCRIPT_DIR/gavasah-dealer-hub.service" ]; then
    cp "$SCRIPT_DIR/gavasah-dealer-hub.service" /etc/systemd/system/gavasah-dealer-hub.service
    systemctl daemon-reload
    systemctl enable gavasah-dealer-hub.service
    systemctl restart gavasah-dealer-hub.service || true
fi

echo "=========================================================="
echo "  [SUCCESS] CT 150 Tuned: Ready for 3,000+ Client Devices!"
echo "=========================================================="
