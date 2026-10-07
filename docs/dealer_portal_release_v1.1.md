# GAVASAH Cloud Multi-Tenant Architecture & Dealer Portal v1.1.0

## 1. Executive Summary & Capabilities

`dealer.gavasah.com` has been transformed from an open dashboard into a high-scale, secure, multi-tenant portal serving two distinct roles:
1. **Manufacturer (Master Owner)**: Complete centralized command and control over all partner dealers, enterprise fleet distribution, SSL certificates, and system security credentials.
2. **Authorized Dealers**: Scoped, isolated tenant dashboards with identical operational control over their assigned client gateways (onboarding, telemetry, remote access toggling, editing, diagnostics, and decommissioning).

---

## 2. Default Initial Credentials

| Role | Username | Initial Password | Scope / Permissions |
| :--- | :--- | :--- | :--- |
| **Manufacturer (Owner)** | `admin` | `gavasah2026!` | Full global control, dealer directory CRUD, fleet overview, account credential settings |
| **Sample Dealer 1** | `apex_dealer` | `apex123!` | Scoped to Apex Smart Automation client devices |
| **Sample Dealer 2** | `vajra_knx` | `vajra123!` | Scoped to Vajra KNX Solutions client devices |

> [!IMPORTANT]
> The manufacturer should log in upon first deployment and update their master credentials in the **Account Settings** tab. State is securely persisted to `/srv/gavasah-cloud/auth_state.json`.

---

## 3. UI Navigation & Interface Architecture

### Manufacturer (Owner) Console
Features a sleek left-hand navigation sidebar with five dedicated views:
- **📊 Overview & Summary**: High-level telemetry KPI cards displaying Total Registered Dealers, Total Active Clients, Online Gateways, and Lost Heartbeats, alongside a breakdown list detailing each dealer's client count and uptime percentage.
- **👥 Dealer Directory**: Complete management of partner dealers. Add new dealers (with company name, contact info, username, password), edit existing dealer credentials, or delete dealers (safely reassigning clients directly to the manufacturer).
- **🌐 Client Fleet**: Unified table showing all client gateways across all dealers with a dedicated **Dealer / Partner** badge column, real-time pulse indicator, RAUC slot status, remote ingress toggles, client edit modal, and diagnostic logs modal.
- **🔒 Edge SSL Certificates**: Live ACME RFC 9444 / RFC 8555 zero-touch Let's Encrypt status monitor.
- **⚙️ Account Settings**: Self-service change form for manufacturer username and master password.

### Dealer Portal
When a dealer logs in, the left sidebar is automatically hidden and the interface dynamically adapts into a focused dealer workstation:
- Displays only the clients assigned to that dealer.
- Includes client onboarding modal with automatic dealer ID association.
- Toggle switch for remote client ingress (instantly updates Caddy reverse proxy on CT 305).
- Full client editing, deletion, and terminal diagnostics.
- Top-right dealer account menu with option to change their own password or log out.

---

## 4. API Endpoints Specification

### Authentication & Self-Management
| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/me` | Public | Returns current session status and user profile |
| `POST` | `/api/login` | Public | Authenticates credentials, issues 7-day session token, sets `gavasah_session` cookie |
| `POST` | `/api/logout` | Authenticated | Clears current session token |
| `POST` | `/api/change_owner_credentials` | Manufacturer | Updates master manufacturer username and password |
| `POST` | `/api/change_dealer_password` | Dealer | Allows dealer to update their own account password |

### Dealer Management (Manufacturer Only)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/dealers` | Returns directory of all dealers with client counts and uptime metrics |
| `POST` | `/api/create_dealer` | Registers a new dealer account with name, username, password, contact details |
| `POST` | `/api/update_dealer` | Modifies dealer details or resets dealer password |
| `POST` | `/api/delete_dealer` | Removes dealer and reassigns clients to manufacturer direct |

### Client Fleet & Diagnostics
| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/fleet` | Authenticated | Returns clients (scoped to dealer if dealer; all clients if manufacturer) |
| `POST` | `/api/onboard` | Authenticated | Provisions a new client gateway with ports and AutoSSH Linux user |
| `POST` | `/api/update_client` | Authenticated | Updates client name, auth secret, KNX IP/port (or dealer assignment) |
| `POST` | `/api/toggle_remote` | Authenticated | Activates or suspends remote ingress in Caddy |
| `POST` | `/api/delete_site` | Authenticated | Decommissions site, purges Caddy blocks and SSL certificates |
| `GET` | `/api/logs` | Authenticated | Fetches diagnostic event log stream for a client site |
| `POST` | `/api/heartbeat` | Gateway Client | Uninterrupted hardware telemetry sync authenticated via `auth_key` |

---

## 5. Security & High-Scale Reliability Hardening
- **Cryptographic Protection**: SHA-256 salted password hashing (`secrets.token_hex(16)`) and constant-time string comparison (`secrets.compare_digest`).
- **Telemetry Separation**: Hardware gateway heartbeats (`POST /api/heartbeat`) use `auth_secret` and do not require browser cookies or session state.
- **Atomic Persistence**: Atomic write via temporary files (`.tmp.<pid>`) with `threading.RLock()` protects `clients_state.json` and `auth_state.json` against write corruption under concurrent multi-tenant loads.
- **Cross-Platform Resilience**: Linux subprocesses (`useradd`, `userdel`, `groupadd`) and Caddy SSH reloads gracefully detect OS environment, allowing seamless testing on Windows and native high-speed execution on Proxmox LXC.
