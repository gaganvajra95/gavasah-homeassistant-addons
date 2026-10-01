# Checkpoint: continue 34
**Created:** 2026-10-02 02:05:14 IST
**Project:** GAVASAH KNX-IP Gateway & Multi-Tenant Home Assistant Add-on
**Target Repository:** `git@github.com:gaganvajra95/gavasah-homeassistant-addons.git`
**Server Hub:** CT 150 (`192.168.6.150:3000` / `gavasah.com`) on Proxmox `primordial-1`

---

## 1. Context & What Was Accomplished Up To continue 34
1. **Server Hub Ingress & CT 150 Deployed (Ubuntu 24.04 LTS)**:
   - Deployed on `primordial-1` with dedicated static IP `192.168.6.150/24`.
   - Traefik v3.4 installed and configured for wildcard `*.gavasah.com`.
   - OpenSSH Reverse Tunnel Gateway running on port `2222`.
   - **Gavasah Dealer Fleet Portal** deployed and running as a systemd service (`gavasah-dealer-hub.service`) on port `3000`.
   - Proxmox Summary Notes updated with all IPs, ports, and credentials for CT 150, VM 307, VM 304, LXC 310, and LXC 320.

2. **Gavasah Cloud Agent Add-on Created**:
   - Packaged as a standard Home Assistant OS Add-on:
     - `repository.yaml`
     - `gavasah-cloud-agent/config.yaml` (`host_dbus: true`, `host_network: true`, `supervisor_api: true`)
     - `Dockerfile` (Alpine 3.19 + Python 3 + AutoSSH + Socat + Wireguard)
     - `rootfs/usr/bin/heartbeat.py`: Queries Supervisor API and RAUC D-Bus for:
       - Active boot slot (Slot A vs Slot B)
       - Slot health status (`good`, `bad`, recovery mode detection)
       - Local IP, Gateway, DNS, MAC address
       - KNXnet/IP gateway reachability & latency (UDP 3671)
       - CPU, RAM, Disk metrics
     - `rootfs/usr/bin/entrypoint.sh`: AutoSSH reverse tunnel to `hub_host:2222` + UDP KNX bridge.

3. **Files Migrated to This Workspace**:
   - `docs/server_architecture_plan.md`
   - `hub_server/dealer_server.py`
   - `hub_server/gavasah-dealer-hub.service`
   - `knx_device_guide.md`
   - Full Add-on repository structure (`gavasah-cloud-agent/`)

---

## 2. GitHub Status & Upload Action Required
- **Local Git Repository**: Initialized on branch `main`.
- **Remote Configured**: `git@github.com:gaganvajra95/gavasah-homeassistant-addons.git`
- **SSH Auth Status**: Successfully authenticated as `gaganvajra95`.
- **Next Step**: Create the repository on GitHub:
  1. Open: [https://github.com/new?name=gavasah-homeassistant-addons](https://github.com/new?name=gavasah-homeassistant-addons)
  2. Select **Public** and click **Create repository** (do not initialize with README).
  3. Run: `git push -u origin main`
  4. In Home Assistant &rarr; Add-on Store &rarr; Repositories &rarr; Add:
     `https://github.com/gaganvajra95/gavasah-homeassistant-addons`

---

## 3. Resume Point
To resume seamlessly in this project, prompt: **continue 34**.
