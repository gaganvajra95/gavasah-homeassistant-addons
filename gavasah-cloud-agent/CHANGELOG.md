# Changelog

All notable changes to the **Gavasah Cloud Agent** Home Assistant Add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.5] - 2026-10-22

### Added
- **10-Second High-Speed MQTT Telemetry with Peak Detection**: Realtime telemetry pulses every 10 seconds to `gavasah/clients/{client_id}/telemetry`. Samples CPU and physical RAM every 1 second across the 1-10s interval, reporting the maximum peak values along with storage metrics (free, total, and used percentage).

---

## [1.3.4] - 2026-10-22

### Added
- **300-Second Stabilization Soak Delay for Auto-Reset**: When a previously failed or exhausted subsystem recovers to a healthy state, the edge self-healing engine enforces a continuous 300-second stabilization window (`STABILIZATION_SEC = 300`) before clearing the `exhausted` flag and resetting the attempt counter to 0, preventing rapid counter resets during transient or flapping network conditions.

---

## [1.3.3] - 2026-10-22

### Fixed
- **Add-on Self-Update API 404 Resolution**: Dynamically discovers the add-on slug from `GET /addons/self/info` and calls `POST /addons/{slug}/update` (with core `update.install` service fallback) instead of nonexistent `/addons/self/update`. Completely eliminates the `update_addon: HTTP Error 404: Not Found` error.
- **Edge Self-Healing Decoupling & Reboot Reset**: Decoupled edge self-healing from cloud AI Copilot autonomy level. On add-on startup or reboot, automatically resets `attempts = 0` and `exhausted = False` for all unmuted integrations to allow a clean retry cycle.
- **Automatic Recovery Reset Without Manual Intervention**: When an integration recovers and is verified healthy, automatically clears `exhausted` and resets `attempts = 0` without requiring an integrator to manually reset the state.
- **Autonomous Boot Slot Recovery**: Gateways running in Slot B attempt autonomous recovery back to Slot A up to 5 attempts; if all 5 attempts fail, recovery halts and runs in Slot B as designated recovery mode.

---

## [1.3.2] - 2026-10-22

### Changed
- **Slot B Recovery Mode Directive**: Enforced Gavasah architectural standard where Slot A is strictly Primary Operational and Slot B is designated as Recovery Fallback. Whenever any gateway enters Slot B, it is explicitly flagged as recovery mode (`is_recovery_mode = True`), and telemetry reports Slot B as `recovery (active)`.

---

## [1.3.1] - 2026-10-22

### Fixed
- **Exhausted Self-Healing HA Core Retry Unload**: When a subsystem reaches its strict 5-attempt limit, automatically unloads the failing config entries via HA Core REST API (`POST /core/api/config/config_entries/entry/{id}/unload`). This terminates Home Assistant Core's native background retry loop (`setup_retry`), completely halting infinite background socket connection attempts and eliminating error log storms.
- **Flapping Recovery Suppression & 300s Stabilization Window**: Introduced a 300-second probation period for recovering subsystems. Subsystems temporarily transitioning through setup or brief socket handshakes will no longer prematurely wipe their attempt counters to 0, preventing infinite self-healing retry restart loops.
- **Persistent Self-Healing State Cache**: Persisted `_healing_registry` to `/data/self_healing_registry.json`. Exhausted subsystems remain permanently locked across add-on reboots, supervisor container recycles, and gateway power cycles.
- **Thread-Safe Telemetry Concurrency**: Added a dedicated mutex lock (`_healing_lock`) across `run_autonomous_self_healing_engine`, preventing race conditions between the high-speed MQTT telemetry worker and the main heartbeat loop.

---

## [1.3.0] - 2026-10-20

### Added
- **High-Speed MQTT Telemetry & Pub/Sub Engine**: Integrated persistent MQTT client publishing lightweight performance metrics (CPU, RAM, Core/OS versions, subsystems, and RAUC slot health) every 30–60s to `gavasah/clients/{client_id}/telemetry`.
- **Zero-Latency Last Will & Testament (LWT)**: Automatic disconnect notification published to `gavasah/clients/{client_id}/status` upon connection drop.
- **Secure Password-Based Authentication**: Support for username (`client_id`) and password (`auth_key`) authentication to EMQX broker.
- **Instant Downlink Command Listener**: Direct command execution via `gavasah/clients/{client_id}/cmd` and `gavasah/global/cmd`, reducing execution latency from minutes to under 50ms.
- **Exhausted Self-Healing Alert Event Stream**: When local 5-attempt autonomous remediation fails, publishes immediate event to `gavasah/clients/{client_id}/events` to trigger server-side AI Copilot triage.

---

## [1.2.8] - 2026-10-16

### Added
- **Dynamic Muted/Disabled Integrations Support**: Synchronizes `unmonitored_integrations` list from the Dealer Hub on every heartbeat pulse and at startup.
- **Immediate Self-Healing Halt on Disable**: If an integration is disabled or muted from the Dealer Operations Portal, all active self-healing remediation routines for that subsystem immediately cease, attempts are reset to 0, and status is locked to `disabled` until re-activated by the dealer.

---

## [1.2.7] - 2026-10-16

### Fixed
- **Complete Ignored Integration Purge**: Comprehensive suppression of all ignored (`source: "ignore"`, `state: "ignored"`) and user-disabled (`disabled_by`) integrations across HA Core config entries, Lutron bridges, CoolMaster HVAC, and ZHA discovery. Ignored integrations are completely excluded from telemetry and dashboard badges.
- **Strict 5-Attempt Self-Healing Cap & Counter Lock**: Autonomous self-healing now strictly stops after 5 attempts and dispatches a persistent alert notification to Home Assistant Core. In-memory attempt counter is permanently locked and will NEVER retry or reset during the add-on runtime; the counter only resets when the client gateway or add-on container restarts.

---

## [1.2.6] - 2026-10-16

### Fixed
- **Filter Ignored Zeroconf Discoveries & Disabled Entries**: Filtered out config entries marked with `source: 'ignore'` (such as ignored Zeroconf discoveries for adjacent/old bridges) and entries with `disabled_by` at the root of `get_ha_config_entries()`. Eliminates phantom subsystem reporting, false "degraded" counts (e.g. Lutron 1/2 Online), and spurious autonomous self-healing escalation loops.

---

## [1.2.5] - 2026-10-16

### Fixed
- **Live Home Assistant Core Integration State Telemetry**: Fixed `supervisor_get` to correctly process raw JSON list responses returned by Home Assistant Core REST API endpoints (`/core/api/config/config_entries/entry`), eliminating an `AttributeError` that previously forced fallback to static on-disk files.
- **CoolMaster Subsystem Diagnostics & Accurate Error Reporting**: Refactored CoolMaster detection to inspect live in-memory entry states (`setup_retry`, `setup_error`, `not_loaded`) and capture detailed failure reasons (e.g., `Unexpected status line format: ['No', 'UID']` from disconnected RS485 HVAC lines) instead of falsely reporting "online" based solely on raw TCP socket connectivity.
- **Generic Failed Integration Auditing**: Connected `failed_core_entries` to live Core API responses so that all broken or retrying integrations across the gateway fleet are immediately reported to the Central Hub.

---

## [1.2.4] - 2026-10-16

### Added
- **Autonomous External KNX IP Gateway Auto-Discovery**: Added automated discovery of external LAN KNX IP interfaces/routers (ABB, MDT, Weinzierl, GVS) directly from `/homeassistant/.storage/core.config_entries` in `entrypoint.sh`. Automatically provisions the local `socat` UDP bridge without requiring manual configuration in add-on options.

---

## [1.2.3] - 2026-10-16

### Added
- **Automated Zero-Touch WireGuard Mesh Tunnel**: Added automated WireGuard client uplink (`wg0`) in `entrypoint.sh` fetching client-specific mesh keys from `/api/wireguard_config` on startup. Includes dual-engine activation (native kernel `wg-quick` with automatic fallback to `wireguard-go` userspace daemon) and `10.42.0.0/16` routing.
- **Kernel Module & Network Capabilities**: Enabled `kernel_modules: true` and added `wireguard-tools`, `wireguard-go`, and `openresolv` in Alpine `Dockerfile` for seamless high-performance UDP tunneling for remote ETS KNX device programming.

---

## [1.2.2] - 2026-10-16

### Fixed
- **Missing `re` Module Import in Telemetry Engine**: Resolved critical `NameError: name 're' is not defined` crash in `heartbeat.py` triggered when `detect_all_technologies(opts)` and `auto_heal_ip_bans_and_proxy()` executed regular expression scans on config entries and IP patterns.
- **KNX Socat Forwarder Guard**: Guarded optional UDP/TCP bridge against empty or invalid `KNX_PORT` and `KNX_IP` values (`null`, `none`, `—`) preventing `xioopen_ipdgram_listen(): unknown address family 0` daemon exit.

---

## [1.2.1] - 2026-10-16

### Fixed
- **Entrypoint Bash Quoting SyntaxError**: Resolved `SyntaxError: invalid syntax. Perhaps you forgot a comma?` in `entrypoint.sh` caused by unescaped quotes in inline Python invocation. Replaced inline string with quoted heredoc (`python3 - << 'EOF'`) ensuring clean self-healing IP-ban purge and trusted proxy configuration on add-on startup.

---

## [1.2.0] - 2026-10-16

### Added
- **Autonomous Self-Healing Engine**: Integrated proactive multi-subsystem auto-remediation engine directly into `heartbeat.py`. Autonomously remediates offline/degraded subsystems (KNX, CoolMaster HVAC, Zigbee2MQTT, Lutron, Matter, and failing Core config entries) with up to 5 self-healing attempts and a 60-second cooldown before escalating alarms to Integrator, Dealer, or Manufacturer HQ.
- **Silent Recovery Telemetry**: Automatically detects successful self-remediations, logs silent recoveries, and reports full telemetry (`self_healing` object with attempt counter, action audit trail, and cooldown state) to the Central Cloud Hub.
- **Add-on Version & Self-Healing Sensors**: Native Home Assistant Core diagnostic sensors `sensor.gavasah_addon_version` and `sensor.gavasah_self_healing_status` registered directly into HA Core.
- **Automated Store Reload on Self-Update**: Remote command dispatcher triggers Supervisor add-on store refresh before applying self-updates to ensure latest git releases are immediately available.

---

## [1.1.3] - 2026-10-15

### Fixed
- **Loopback Quoted Key Ban Removal**: Fixed regex and prefix matching to purge quoted loopback keys (`'127.0.0.1':`, `"127.0.0.1":`) from `/config/ip_bans.yaml`.
- **Permanent Ban Disabling via `ip_ban_enabled: false`**: Automatically injects `ip_ban_enabled: false` into `http:` in `/config/configuration.yaml` so loopback reverse tunnels are never banned by failed authentication attempts.
- **Automatic Core Restart on Unban**: Dispatches `/core/restart` via Supervisor API whenever an unban command is received to immediately flush the in-memory banned IP list.
- **Heartbeat WAN Resilience**: Extended `urllib` socket timeout from 6s to 15s to eliminate timeout drops and chunked empty body 400 errors over high-latency WAN/cellular connections.

---

## [1.1.2] - 2026-10-14

### Added
- **Autonomous IP Ban Purge & Reverse Proxy Self-Healing**: Automatically scans and purges loopback IP bans (`127.0.0.1`, `::1`) from `/config/ip_bans.yaml` and provisions `trusted_proxies` in `/config/configuration.yaml` at startup and every 5 heartbeat cycles to prevent `403 Forbidden` and `400 Bad Request` tunnel lockout.
- **Central Dealer Command Execution**: Added bidirectional remote command dispatcher allowing the Dealer Central Hub to remotely trigger IP unbans, core reloads, core restarts, and add-on self-updates on demand.

---

## [1.1.1] - 2026-10-14

### Fixed
- **Phantom KNX Detection Elimination**: Strict reality checks prevent false/phantom KNX IP or port reporting on gateways running purely Zigbee, Lutron, or non-KNX stacks. Add-on options fallback is ignored unless verified by reachable ping or active core config entries.
- **Subsystem Health & Operational Diagnostics**: Added real-time operational status (Online, Offline, Degraded) and detailed failure reason reporting across all automation subsystems (KNX, Zigbee2MQTT, Lutron, and Matter).
- **Core Integrations Diagnostic Inspection**: Heartbeat inspects Home Assistant `core.config_entries` and reports any failing integrations with exact setup error details.

---

## [1.1.0] - 2026-10-08

### Added
- **Multi-Technology Protocol Stack Auto-Detection**: Autonomously inspects and detects multiple concurrent automation technologies on the client gateway:
  - **KNX**: IP Gateway, Routing & Tunneling connection detection.
  - **Zigbee (Multi-Instance Zigbee2MQTT)**: Scans and enumerates all installed Zigbee2MQTT add-on instances simultaneously (supporting multi-floor/multi-coordinator deployments) as well as native ZHA.
  - **Lutron**: Detects Caséta, RadioRA 2/3, and Homeworks QSX integrations from Home Assistant config entries.
  - **Matter**: Detects Matter Server add-on and native Matter integration state.
- **One-Click Backup & Snapshot Trigger**: Added automated Home Assistant Supervisor full backup creation via heartbeat command dispatch and automated `.tar` archive upload to central GAVASAH Cloud Hub for one-click downloading.
- **Snapshot Telemetry**: Gateway reports latest 10 local Supervisor snapshots with date, slug, and size.

---

## [1.0.9] - 2026-10-08

### Added
- **Onboard Loopback KNX Router Support**: Added local loopback `127.0.0.1:3671` probe support in auto-discovery watchdog for all-in-one controller hardware running integrated knxd services.

### Fixed
- **Localhost Probe Sanitization**: Resolved telemetry issue where `ping_knx_gateway` discarded `127.0.0.1` and `localhost` configurations as unconfigured.
- **Heartbeat Endpoint Prioritization**: Ensured HTTPS dealer API endpoint is tested first for rapid telemetry delivery without HTTP 308 redirect drops.

---

## [1.0.8] - 2026-10-08

### Added
- **Autonomous KNXnet/IP Zero-Config Discovery**: Agent autonomously inspects Home Assistant's `.storage/core.config_entries` and `configuration.yaml` to detect KNX integration, extracting the target IP gateway address and port without requiring manual dealer entry.
- **Heterogeneous Protocol Support (Non-KNX)**: Sites using Lutron, Zigbee, Z-Wave, or Matter are dynamically detected and reported as `non_knx`, suppressing spurious KNX gateway failure alerts.
- **Dynamic Port 80 & 8123 Detection**: Telemetry probe automatically checks both standard port 8123 and port 80 to verify local Home Assistant Core availability across diverse network deployments.

### Changed
- **Zero-Config Onboarding**: Removed mandatory KNX IP and Port configuration prompts from Dealer and Manufacturer site creation menus, making gateway commissioning fully autonomous.

---

## [1.0.7] - 2026-10-08

### Fixed
- **Symmetric RAUC A/B Slot Health**: Corrected false-positive recovery detection where normal system updates booting into Slot B were reported as recovery mode. Slot B is recognized as an active healthy operational partition unless RAUC explicitly flags a boot failure.
- **Sensor Status Accuracy**: Updated local binary sensor status and portal reporting to accurately reflect active slot health without spurious alerts.

---

## [1.0.6] - 2026-10-08

### Fixed
- **Container Permissions Hardening**: Set `apparmor: false` in `config.yaml` to permanently prevent container permission denials and enable unconstrained host socket & `/proc` metrics collection.
- **Graceful Storage Handling**: Eliminated `[Errno 13] Permission denied` log warnings during Home Assistant `.storage/core.config` external URL synchronization.
- **Multi-Endpoint SSH Key Registration**: Added robust TLS-unverified fallback endpoints (`https://`, port 3000, and dealer hub) to prevent OpenSSH `Permission denied (publickey)` upon gateway boot.
- **Strict Keyfile Permissions**: Enforced strict `0600` on private key identity and `0644` on public keys in persistent `/data/ssh`.

---

## [1.0.5] - 2026-10-07

### Added
- **Accurate System CPU & Memory Telemetry**: Direct `/proc/stat` delta jiffies calculation across all CPU cores and `/proc/meminfo` reading for exact real-time RAM usage.
- **Home Assistant Supervisor API Integration**: Fallback telemetry queries against Home Assistant Core `core/stats` via Supervisor token.
- **Strict SSH Connection Timeout**: Added `ConnectTimeout 5` and persistent keepalives to prevent hung AutoSSH background processes during network failovers.

### Fixed
- Fixed memory percentage calculation discrepancy between container cgroup and host operating system.
- Improved error handling during network reconnects and tunnel restarts.

---

## [1.0.4] - 2026-10-06

### Added
- **Multi-Tenant Dynamic Ingress**: Support for autonomous Caddy reverse proxy routing with custom client subdomains (`<client_id>.gavasah.com`).
- **Telemetry Heartbeat Pulse**: Real-time push telemetry every 60 seconds with offline detection and network health metrics.
- **Automatic External URL Configuration**: Automatic provisioning of Home Assistant external URL matching dealer-assigned domain.

---

## [1.0.3] - 2026-10-04

### Added
- **Dual Reverse Tunneling**: Dedicated tunnels for Home Assistant Web Dashboard (port 8123) and System Administration SSH (port 22).
- **AutoSSH Resiliency**: Automated tunnel watchdog with auto-healing and reconnection logic.

---

## [1.0.2] - 2026-10-02

### Added
- **KNXnet/IP Remote Diagnostic Relay**: Real-time KNX IP gateway discovery, telegram packet monitoring, and ETS programming relay.
- **RAUC A/B Dual Slot Support**: Boot slot state detection and recovery partition monitoring.

---

## [1.0.1] - 2026-09-28

### Added
- Initial deployment of GAVASAH Cloud Agent add-on for Home Assistant OS (HAOS) and Supervised installations.
- Ed25519 cryptographic key-based authentication with GAVASAH Cloud Hub.
