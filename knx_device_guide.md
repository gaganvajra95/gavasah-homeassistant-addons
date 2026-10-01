# KNX-IP Gateway & Home Assistant: Architecture, Offline Operation & Runbook

**Device IP:** `192.168.1.111`  
**System:** Home Assistant OS 18.0 (Kernel 6.12.30-haos) on Allwinner ARM64 SoC (`generic-aarch64`)  
**KNX Hardware:** ON Semiconductor NCN5120 Transceiver wired to UART `/dev/ttyS1`  
**Date of Inspection:** September 23, 2026  

---

## 1. Executive Summary

This document captures the complete technical investigation, discovery, offline setup, and maintenance guidelines for the combined KNX-IP Router and Home Assistant embedded controller.

### Key Outcomes:
1. **Addon Redundancy Clarified:** The actual KNX-IP router is **not** managed by Docker addons. It runs natively as a Linux systemd service (`knx.service` / *TSY KNX IPROUTER*) at the host OS layer. Disabling the `LUMI KNX IPRouter` addon does not disrupt KNX routing.
2. **Offline / Standalone Operation Achieved:** By switching Home Assistant's KNX integration endpoint from the external IP `192.168.1.111:3671` to loopback **`127.0.0.1:3671`**, the device communicates 100% locally in memory. Unplugging the LAN cable causes zero interruption to KNX control.
3. **Update Resilience Established:** Regular Home Assistant Core and Add-on updates are completely safe and do not touch the host KNX daemon. If a full OS update ever wipes the host service, the pre-installed `knxd` addon serves as an immediate drop-in replacement.
4. **Hardware RTC Verified:** The onboard Real-Time Clock (`/dev/rtc0`) is active and initialized for offline scheduling.

---

## 2. Hardware & Architecture Map

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PHYSICAL HARDWARE LAYER                              │
│  - Allwinner ARM64 SoC (sunxi platform)                                │
│  - ON Semiconductor NCN5120 KNX Transceiver on /dev/ttyS1              │
│  - Hardware RTC: /dev/rtc0 (Allwinner 0x07000000.rtc)                  │
│  - Physical Network Interface: eth0 (Static: 192.168.1.111/24)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                    HOST OPERATING SYSTEM (HAOS 18.0)                   │
│                                                                        │
│   [ knx.service ] (TSY KNX IPROUTER)                                   │
│   ├── Exclusively locks /dev/ttyS1 (NCN5120 KNX transceiver)           │
│   ├── Binds KNXnet/IP standard port 3671 (UDP)                         │
│   └── Listens on 127.0.0.1 (Loopback) & 192.168.1.111 (eth0)           │
│                                                                        │
│   [ Hardware RTC ] -> Auto-read by kernel on offline boot              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Internal Loopback / 127.0.0.1:3671)
┌───────────────────────────────────▼────────────────────────────────────┐
│                 CONTAINER / APPLICATION LAYER (DOCKER)                 │
│                                                                        │
│   [ Home Assistant Core 2026.6.4 ] (net=host)                         │
│   ├── Integration: KNX (Tunneling UDP @ 127.0.0.1:3671)                │
│   ├── Assigned KNX Individual Address: 1.2.1                           │
│   └── Controls: switch.knx_switch_1, knx_switch_2, automations, etc.   │
│                                                                        │
│   [ local_lumi-knx-iprouter ] (State: STOPPED)                        │
│   └── Web status viewer only. Not needed for bus operation.            │
│                                                                        │
│   [ local_knxd ] (State: STOPPED)                                      │
│   └── Pre-configured for /dev/ttyS1. Standby emergency fallback.      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Investigated Services & Device State

### A. Host System Services
* **`knx.service` (Active):** Description: *TSY KNX IPROUTER*. Binds UDP 3671 and drives the NCN5120 transceiver on `/dev/ttyS1`.
* **`dropbear.service` (Active):** Host-level SSH daemon.
* **`systemd-timesyncd.service` (Active):** Time synchronization service; synchronizes against NTP when internet is available, falls back to `/dev/rtc0` when offline.

### B. Addon State Table
| Addon Name | Slug | State | Purpose / Role |
| :--- | :--- | :--- | :--- |
| **LUMI KNX IPRouter** | `local_lumi-knx-iprouter` | **Stopped** | Web diagnostics dashboard & remote proxy (`*.lumiknx.top`). Safe to keep disabled. |
| **KNXD daemon** | `local_knxd` | **Stopped** | Alternate KNX driver. Kept stopped to avoid serial port collision on `/dev/ttyS1`. |
| **Terminal & SSH** | `core_ssh` | **Started** | Ingress web terminal for administrative access. |
| **Studio Code Server** | `a0d7b954_vscode` | **Started** | Visual Studio Code web editor. |

### C. Home Assistant KNX Integration
* **Title:** `Tunneling UDP @ 127.0.0.1`
* **Status:** `loaded`
* **Assigned KNX Address:** `1.2.1`
* **Telegram Count:** Over 1,123 telegrams processed with **0 incoming errors** and **0 outgoing errors**.

---

## 4. Offline / No-LAN Operation Guide

### Why It Previously Dropped Offline
When Home Assistant was configured with the host address set to `192.168.1.111`:
1. Disconnecting the Ethernet cable caused `eth0` to enter `NO-CARRIER`.
2. Linux marked the route to `192.168.1.111` as unreachable (`ENETUNREACH`).
3. Home Assistant's UDP packets to `192.168.1.111:3671` failed, crashing the KNX tunnel.

### Why `127.0.0.1` Solves It Permanently
* Both Home Assistant Core and `knx.service` reside on the same board and share the host network stack.
* The loopback interface (`lo` / `127.0.0.1`) never loses carrier, regardless of cable state.
* KNX telegrams are routed directly within local memory.

### On-Site Maintenance Without a Router (Direct Laptop Access)
Because `eth0` has a static IP address (`192.168.1.111`, netmask `255.255.255.0`):
1. Connect a standard Ethernet patch cable directly between a laptop and the device.
2. Assign the laptop's Ethernet adapter a static IP in the same subnet (e.g., `192.168.1.50`, netmask `255.255.255.0`).
3. Open `http://192.168.1.111:8123` in any browser to access Home Assistant.

---

## 5. Hardware RTC (Real-Time Clock) Configuration

* **Device Path:** `/dev/rtc0` -> `/sys/devices/platform/soc/7000000.rtc/rtc/rtc0`
* **Symlink:** `/dev/rtc`
* **Behavior:**
  * When internet is connected, `systemd-timesyncd` synchronizes the system clock from NTP.
  * When offline, the Linux kernel reads the timestamp from `/dev/rtc0` during early boot.
  * **Important:** Ensure the onboard coin cell battery (CR1220 or CR2032) is properly seated in the motherboard's battery clip so the RTC retains time across complete power cuts.

---

## 6. Update Safety & Disaster Recovery Plan

### A. Regular Updates (Safe)
* **Home Assistant Core Updates:** 100% safe. Runs in Docker and does not touch the host operating system, systemd services, or `/dev/ttyS1`.
* **Add-on Updates:** 100% safe. Each addon is isolated in its own container.
* **Integration Configuration:** Stored in `/config/.storage/core.config_entries`, which persists across all updates.

### B. Operating System (HAOS) Updates (Caution)
* **Do NOT perform generic upstream Home Assistant OS firmware updates** unless explicitly supplied by the manufacturer (LUMI). A generic upstream HAOS flash could overwrite custom host rootfs services.

### C. Disaster Recovery: If `knx.service` Is Ever Wiped
If an OS update or filesystem reset ever removes `knx.service`:

#### Solution 1: Use the Built-in `knxd` Addon (Easiest)
1. Go to **Settings > Add-ons > KNXD daemon**.
2. Verify the configuration:
   ```yaml
   address: "0.0.1"
   client_address: "0.0.2:8"
   interface: "ncn5120"
   device: "/dev/ttyS1"
   ```
3. Click **Start** and enable **Start on boot**.
4. The addon takes over `/dev/ttyS1` and exposes port `3671`. Home Assistant connects to `127.0.0.1` immediately without any host-level intervention.

#### Solution 2: Manual Host Service Restoration
If restoring the native host daemon:
1. Place the binary back in its directory (e.g., `/root/.knx/` or `/usr/local/bin/`).
2. Restore `/etc/systemd/system/knx.service`.
3. Reload and start:
   ```bash
   systemctl daemon-reload
   systemctl enable --now knx.service
   ```
