# Changelog

All notable changes to the **Gavasah Cloud Agent** Home Assistant Add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
