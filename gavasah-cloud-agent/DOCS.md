# Gavasah Cloud Agent

The **Gavasah Cloud Agent** links this Home Assistant installation to the central Gavasah Cloud Hub (`gavasah.com`), enabling:
1. **Remote Dashboard Access**: Access your Home Assistant instance at `https://<client-id>.gavasah.com` without port forwarding or dynamic DNS.
2. **System Health & RAUC Slot Monitoring**: Continuous health reporting of RAUC boot slots (Slot A vs Slot B), detecting fallback / recovery events instantly.
3. **Dealer Remote Diagnostics**: Secure reverse SSH tunnel allowing authorized Gavasah engineers to troubleshoot issues remotely.
4. **ETS KNX Bus Programming**: Bi-directional UDP relay linking ETS 5/6 programming software to your local Gavasah KNX-IP Gateway.

---

## Configuration Options

| Option | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `hub_host` | string | Yes | Central Gavasah Hub address (e.g. `122.175.49.35` or `hub.gavasah.com`) |
| `hub_ssh_port` | integer | Yes | Ingress SSH Port on Central Hub (default: `2222`) |
| `client_id` | string | Yes | Unique site slug assigned by Gavasah (e.g. `sharma-villa`) |
| `auth_key` | string | Yes | Authentication token / shared secret for telemetry verification |
| `remote_dashboard_port` | integer | Yes | Reverse port forwarding Home Assistant UI (e.g. `10001`) |
| `remote_ssh_port` | integer | Yes | Reverse port forwarding host SSH for dealer remote diagnostics (e.g. `22001`) |
| `knx_gateway_ip` | string | No | Local IP of Gavasah KNX-IP Gateway (e.g. `192.168.1.111`) |
| `knx_gateway_port` | integer | No | Port for KNXnet/IP UDP tunneling (default: `3671`) |
| `heartbeat_interval` | integer | No | Seconds between telemetry reports (default: `60`) |
| `auto_update_external_url` | boolean | No | Automatically provisions Home Assistant Internet URL to `https://<client-id>.gavasah.com` for instant mobile companion app onboarding (default: `true`) |

---

## Critical Requirement for Remote UI

For Home Assistant to accept reverse-proxied connections from the central hub, add this to your `configuration.yaml`:

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
    - ::1
```

Restart Home Assistant Core after adding this block.

---

## Native Home Assistant Diagnostic Entities

The Gavasah Cloud Agent automatically registers and updates the following diagnostic entities in your local Home Assistant instance:

| Entity ID | Type | Description |
| :--- | :--- | :--- |
| `sensor.gavasah_boot_slot` | Sensor | Active RAUC boot slot (`Slot A` or `Slot B`) |
| `binary_sensor.gavasah_recovery_mode` | Binary Sensor | `on` if system failed Slot A and fell back to recovery Slot B |
| `binary_sensor.gavasah_cloud_tunnel` | Binary Sensor | Ingress reverse tunnel connection status |
| `binary_sensor.gavasah_knx_gateway` | Binary Sensor | KNXnet/IP gateway UDP reachability |
| `sensor.gavasah_knx_latency` | Sensor | Live KNX bus ping latency in milliseconds |
| `sensor.gavasah_local_ip` | Sensor | Local network IP, MAC address, and default gateway |

