# Changelog

All notable changes to the **Gavasah Cloud Agent** Home Assistant Add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
