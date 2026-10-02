# GAVASAH Dealer Fleet Portal & Cloud Hub v1.1.0 Release Notes

**Deployment Target:** CT 150 (`192.168.6.150:3000`) & CT 305 (`192.168.6.170:443`)  
**Public Access:** [`https://dealer.gavasah.com`](https://dealer.gavasah.com)  
**Edge Proxy:** Caddy ACME ARI (RFC 9444 / RFC 8555)  
**Date:** October 2026

---

## 1. Autonomous SSL / TLS Lifecycle & Zero-Touch Renewal
- **Caddy ACME ARI Engine:** Certificates for `gavasah.com`, `dealer.gavasah.com`, and dynamic subdomains (`*.gavasah.com`) are managed directly by Caddy on CT 305 with Let's Encrypt CA.
- **Permanent Autonomous Renewal:** Certificates automatically renew 30 days prior to expiration without manual interaction via RFC 9444 Automated Renewal Information (ARI).
- **Automated Site Provisioning:** Onboarding a new client site dynamically inserts reverse proxy ingress routing into `Caddyfile.unified` and triggers instant certificate provisioning.
- **Complete SSL Purge Engine (`POST /api/delete_site`):** Deleting a client site permanently removes its ingress rule, purges all cryptographic certificates and private keys from `/data/caddy/certificates/*/{domain}`, cleans the OCSP cache, and reloads the Caddy engine.

---

## 2. Client Editing & Authentication Secret (`auth_key`)
- **Dual-Placement Edit Buttons:**
  - **Column 1 (`Client Site / Slug`):** `✏️ Edit` button positioned directly next to the client name, ensuring instant access across mobile and narrow screens.
  - **Actions Column:** Dedicated `✏️ Edit` button alongside Dashboard, SSH, and Delete.
- **Client Authentication Secret Management:**
  - Full in-place editing of the `auth_key`.
  - Password masking with an unmask toggle (`👁️` / `🙈`).
  - Cryptographically secure random secret generator (`🎲`, format: `gav_sec_<hex16>`).
  - One-click secret clipboard copy (`📋`).
- **Live Add-on Configuration Preview:** Generates the exact YAML options snippet for Home Assistant OS `gavasah-cloud-agent/config.yaml` with a single-click copy button (`📋 Copy Config`).
- **Sticky Footer & Scrollable Body:** Pinned sticky footer locks `Cancel` and `💾 Save Changes` so the action button is always visible on all viewport heights (no scrolling required to save).

---

## 3. High-Precision Heartbeat Telemetry & Outage Diagnostics
- **Active Gateways:** Displays `🟢 ONLINE` pulse badge, relative age (e.g. `⚡ Pulse: 14s ago`), and last signal timestamp.
- **Lost Heartbeat Gateways (>75s silence):** Displays `🔴 LOST HEARTBEAT` badge with:
  - **Lost Time:** Exact time of signal loss (`HH:MM:SS AM/PM`).
  - **Lost Date:** Exact calendar date (`DD Mon YYYY`).
  - **Elapsed Duration:** Relative downtime age (`e.g., 8h 52m ago`).
- **Edit Modal Outage Banner:** Top status banner dynamically displays real-time connection state or exact lost date and time.
- **Metric Cards:** Real-time counters for **Online Gateways** (`X / Total`) and **Lost Heartbeats**.

---

## 4. Responsive Viewport Architecture
- **Table Container (`.table-wrap`):** Configured with `overflow-x: auto` and custom sleek scrollbars, preventing horizontal clipping on standard laptop screens (~1042px width).
- **Sticky Actions Column:** Rightmost actions column (`🌐 Dash`, `💻 SSH`, `✏️ Edit`, `🗑️ Delete`) is pinned with `position: sticky; right: 0;` and a drop shadow, staying locked in place while scrolling through hardware telemetry.
