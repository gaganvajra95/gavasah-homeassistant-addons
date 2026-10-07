#!/usr/bin/env python3
"""
GAVASAH Cloud Agent - System Telemetry, RAUC Slot Health & KNX Bus Watchdog
Runs inside Home Assistant OS Add-on container with host_dbus & supervisor_api privileges.
"""

import os
import sys
import time
import json
import socket
import datetime
import urllib.request
import urllib.error

OPTIONS_PATH = "/data/options.json"
SSH_PUBKEY_PATH = "/data/ssh/id_ed25519.pub"
SUPERVISOR_URL = "http://supervisor"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")

def log(msg):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now} UTC] [Gavasah-Heartbeat] {msg}", flush=True)

def load_options():
    try:
        with open(OPTIONS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"Warning: Could not read {OPTIONS_PATH}: {e}")
        return {}

def get_public_key():
    if os.path.exists(SSH_PUBKEY_PATH):
        try:
            with open(SSH_PUBKEY_PATH, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            log(f"Notice: Could not read {SSH_PUBKEY_PATH}: {e}")
    return ""

def supervisor_get(endpoint):
    url = f"{SUPERVISOR_URL}/{endpoint}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("data", {})
    except Exception as e:
        return {"error": str(e)}

def update_ha_state(entity_id, state, attributes):
    """Publish sensor states directly to Home Assistant Core via Supervisor API."""
    if not SUPERVISOR_TOKEN:
        return
    url = f"{SUPERVISOR_URL}/core/api/states/{entity_id}"
    payload = json.dumps({"state": str(state), "attributes": attributes}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
        "Content-Type": "application/json"
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception as e:
        # Core might still be loading or endpoint busy
        pass

def ensure_external_url(opts):
    """
    Ensures Home Assistant's Internet URL (external_url) is automatically set to
    https://<client_id>.gavasah.com so mobile companion apps connect remotely
    immediately without manual user input.
    """
    if not opts.get("auto_update_external_url", True):
        return

    client_id = opts.get("client_id", "").strip()
    if not client_id or client_id in ["unconfigured", "client01"]:
        return

    target_url = f"https://{client_id}.gavasah.com"

    # 1. Check current configured external_url via Home Assistant Core REST API
    if SUPERVISOR_TOKEN:
        try:
            req = urllib.request.Request(
                f"{SUPERVISOR_URL}/core/api/config",
                headers={
                    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                    "Content-Type": "application/json"
                }
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
                current_url = data.get("external_url")
                if current_url == target_url:
                    return True
        except Exception:
            pass

    # 2. Update via Core WebSocket API (Live in-memory + UI instant update)
    ws_success = False
    if SUPERVISOR_TOKEN:
        try:
            import websocket
            ws = websocket.create_connection("ws://supervisor/core/websocket", timeout=5)
            init_msg = json.loads(ws.recv())
            if init_msg.get("type") == "auth_required":
                ws.send(json.dumps({"type": "auth", "access_token": SUPERVISOR_TOKEN}))
                auth_res = json.loads(ws.recv())
                if auth_res.get("type") == "auth_ok":
                    ws.send(json.dumps({
                        "id": 1,
                        "type": "config/core/update",
                        "external_url": target_url
                    }))
                    update_res = json.loads(ws.recv())
                    if update_res.get("success"):
                        log(f"[✓] [Network Auto-Sync] Successfully set Home Assistant Internet URL to {target_url} via WebSocket API!")
                        ws_success = True
                    else:
                        log(f"[!] WebSocket config/core/update response: {update_res}")
            ws.close()
        except Exception:
            pass

    if ws_success:
        return True

    # 3. Direct Storage Check & Update (.storage/core.config) + reload_core_config fallback
    storage_candidates = [
        "/homeassistant/.storage/core.config",
        "/config/.storage/core.config"
    ]
    for spath in storage_candidates:
        if os.path.exists(spath):
            try:
                with open(spath, "r", encoding="utf-8") as f:
                    cfg = json.load(f)

                curr = cfg.get("data", {}).get("external_url")
                if curr != target_url:
                    cfg.setdefault("data", {})["external_url"] = target_url
                    tmp_path = f"{spath}.tmp"
                    with open(tmp_path, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, indent=4)
                    os.replace(tmp_path, spath)
                    log(f"[✓] [Network Auto-Sync] Updated {spath} external_url to {target_url}")

                    # Trigger Home Assistant Core reload service
                    if SUPERVISOR_TOKEN:
                        try:
                            reload_url = f"{SUPERVISOR_URL}/core/api/services/homeassistant/reload_core_config"
                            r_req = urllib.request.Request(
                                reload_url,
                                data=b"{}",
                                headers={
                                    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                                    "Content-Type": "application/json"
                                },
                                method="POST"
                            )
                            with urllib.request.urlopen(r_req, timeout=4) as r_resp:
                                pass
                            log("[✓] [Network Auto-Sync] Reloaded Home Assistant Core configuration service!")
                        except Exception:
                            pass
                    return True
                else:
                    return True
            except (PermissionError, OSError):
                # Storage is protected or managed in-memory by Home Assistant Core
                pass
            except Exception:
                pass

    return False

def ensure_supervisor_toggles():
    """Ensure Supervisor auto_update and watchdog toggles are enabled for this add-on."""
    if not SUPERVISOR_TOKEN:
        return
    try:
        url = f"{SUPERVISOR_URL}/addons/self/info"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
            "Content-Type": "application/json"
        })
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode()).get("data", {})
            payload_dict = {}
            if not data.get("auto_update", False):
                payload_dict["auto_update"] = True
            if not data.get("watchdog", False):
                payload_dict["watchdog"] = True

            if payload_dict:
                opt_url = f"{SUPERVISOR_URL}/addons/self/options"
                payload = json.dumps(payload_dict).encode("utf-8")
                opt_req = urllib.request.Request(opt_url, data=payload, headers={
                    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                    "Content-Type": "application/json"
                }, method="POST")
                with urllib.request.urlopen(opt_req, timeout=4) as opt_resp:
                    log(f"[✓] [Supervisor] Successfully enabled toggles {list(payload_dict.keys())} for Gavasah Cloud Agent!")
    except Exception as e:
        log(f"[!] [Supervisor] Error setting toggles: {e}")

def ping_knx_gateway(ip, port=3671, timeout=2.0):
    if not ip or str(ip).strip() in ["", "127.0.0.1", "localhost", "none", "null"]:
        return {
            "configured": False,
            "reachable": False,
            "reason": "unconfigured",
            "gateway_ip": "",
            "gateway_port": port
        }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        start = time.time()
        # KNXnet/IP SEARCH_REQUEST (Header: 0x06, 0x10, 0x02, 0x01)
        search_pkt = bytes([
            0x06, 0x10, 0x02, 0x01, 0x00, 0x0E,
            0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ])
        s.sendto(search_pkt, (ip, port))
        try:
            data, _ = s.recvfrom(128)
            latency_ms = round((time.time() - start) * 1000, 2)
            s.close()
            return {"configured": True, "reachable": True, "latency_ms": latency_ms, "gateway_ip": ip, "gateway_port": port}
        except socket.timeout:
            s.close()
            return {"configured": True, "reachable": False, "error": "timeout", "gateway_ip": ip, "gateway_port": port}
    except Exception as e:
        return {"configured": True, "reachable": False, "error": str(e), "gateway_ip": ip, "gateway_port": port}

def check_tunnel_local_port(port=8123):
    import ssl
    # Check if HTTPS is available
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"https://127.0.0.1:{port}/")
        with urllib.request.urlopen(req, context=ctx, timeout=2) as r:
            return True, "https"
    except urllib.error.HTTPError:
        return True, "https"
    except Exception:
        pass

    # Check if HTTP is available
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/")
        with urllib.request.urlopen(req, timeout=2) as r:
            return True, "http"
    except urllib.error.HTTPError:
        return True, "http"
    except Exception:
        pass

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True, "http"
    except Exception:
        return False, "http"

# Previous CPU jiffies cache for real-time CPU % calculation
_prev_cpu_jiffies = None
_prev_cpu_time = None

def get_ha_main_cpu_and_memory():
    """
    Computes real-time Home Assistant Main CPU and RAM utilization.
    Reads:
    1. /proc/meminfo: Exact physical RAM usage of the Home Assistant host machine.
    2. /proc/stat: Exact CPU percentage of the Home Assistant host machine.
    3. Supervisor core/stats API: Fallback to Home Assistant Core engine stats.
    """
    global _prev_cpu_jiffies, _prev_cpu_time
    cpu_pct = None
    mem_pct = None

    # 1. Physical RAM via /proc/meminfo
    try:
        mem = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if ":" in line:
                    parts = line.split(":")
                    mem[parts[0].strip()] = int(parts[1].split()[0])
        tot = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", 0)
        if tot > 0 and avail > 0:
            mem_pct = round(((tot - avail) / tot) * 100.0, 1)
    except Exception:
        pass

    # 2. Main Host CPU via /proc/stat
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
            fields = [float(x) for x in line.strip().split()[1:]]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            total = sum(fields)
            now_t = time.time()

            if _prev_cpu_jiffies is not None and _prev_cpu_time is not None:
                p_idle, p_total = _prev_cpu_jiffies
                delta_total = total - p_total
                delta_idle = idle - p_idle
                if delta_total > 0:
                    cpu_pct = round(max(0.0, min(100.0, (1.0 - (delta_idle / delta_total)) * 100.0)), 1)
            else:
                # Initial sample: quick measurement over 200ms
                time.sleep(0.2)
                with open("/proc/stat", "r") as f2:
                    fields2 = [float(x) for x in f2.readline().strip().split()[1:]]
                    idle2 = fields2[3] + (fields2[4] if len(fields2) > 4 else 0)
                    total2 = sum(fields2)
                    d_tot = total2 - total
                    d_idle = idle2 - idle
                    if d_tot > 0:
                        cpu_pct = round(max(0.0, min(100.0, (1.0 - (d_idle / d_tot)) * 100.0)), 1)

            _prev_cpu_jiffies = (idle, total)
            _prev_cpu_time = now_t
    except Exception:
        pass

    # 3. Fallback / supplement with Home Assistant Core container stats via Supervisor API
    if cpu_pct is None or mem_pct is None:
        try:
            core_stats = supervisor_get("core/stats")
            if isinstance(core_stats, dict):
                if cpu_pct is None and "cpu_percent" in core_stats:
                    cpu_pct = round(float(core_stats["cpu_percent"]), 1)
                if mem_pct is None and "memory_percent" in core_stats:
                    mem_pct = round(float(core_stats["memory_percent"]), 1)
        except Exception:
            pass

    return cpu_pct if cpu_pct is not None else 0.0, mem_pct if mem_pct is not None else 0.0

def collect_telemetry(opts):
    os_info = supervisor_get("os/info")
    host_info = supervisor_get("host/info")
    net_info = supervisor_get("network/info")
    core_info = supervisor_get("core/info")

    boot_slot = os_info.get("boot", "Unknown")
    haos_version = os_info.get("version", "Unknown")
    board = os_info.get("board", "generic")

    # Detect recovery / fallback mode
    is_recovery = False
    if str(boot_slot).upper() == "B":
        # Slot B is the failover/recovery slot after Slot A failure in RAUC dual-slot
        is_recovery = True

    # Primary network interface extraction
    default_ip = "Unknown"
    default_gw = "Unknown"
    mac_addr = "Unknown"
    dns_list = []

    interfaces = net_info.get("interfaces", [])
    for iface in interfaces:
        if iface.get("primary", False) or iface.get("connected", False):
            ipv4 = iface.get("ipv4", {})
            if ipv4.get("address"):
                default_ip = ipv4["address"][0].split("/")[0] if ipv4["address"] else "Unknown"
                default_gw = ipv4.get("gateway", "Unknown")
                dns_list = ipv4.get("nameservers", [])
            mac_addr = iface.get("mac", "Unknown")
            if default_ip != "Unknown":
                break

    # Automatic socket hardware stack discovery fallback
    if default_ip in ["Unknown", "127.0.0.1", ""]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            default_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    # Gateway fallback via /proc/net/route
    if default_gw in ["Unknown", ""]:
        try:
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gw_hex = parts[2]
                        default_gw = socket.inet_ntoa(bytes.fromhex(gw_hex)[::-1])
                        break
        except Exception:
            pass

    # KNX Gateway Check
    knx_res = ping_knx_gateway(
        opts.get("knx_gateway_ip", ""),
        opts.get("knx_gateway_port", 3671)
    )

    ha_alive, ha_proto = check_tunnel_local_port(8123)
    pubkey = get_public_key()

    slot_a_state = "good (active)" if not is_recovery else "bad (failed boot, auto-fell back)"
    slot_b_state = "good (active fallback)" if is_recovery else "standby"

    # Real-time Home Assistant Main CPU & Memory calculation
    main_cpu_pct, main_mem_pct = get_ha_main_cpu_and_memory()

    payload = {
        "client_id": opts.get("client_id", "unconfigured"),
        "auth_key": opts.get("auth_key", ""),
        "ssh_public_key": pubkey,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "system": {
            "hostname": host_info.get("hostname", "homeassistant"),
            "haos_version": haos_version,
            "core_version": core_info.get("version", "Unknown"),
            "board": board,
            "boot_slot": boot_slot,
            "is_recovery_mode": is_recovery,
            "slot_a_status": slot_a_state,
            "slot_b_status": slot_b_state,
            "cpu_percent": main_cpu_pct,
            "memory_percent": main_mem_pct,
            "disk_free_gb": host_info.get("disk_free", 0),
            "disk_total_gb": host_info.get("disk_total", 0),
            "reboot_required": host_info.get("reboot_required", False)
        },
        "network": {
            "local_ipv4": default_ip,
            "gateway": default_gw,
            "mac_address": mac_addr,
            "nameservers": dns_list
        },
        "knx_status": knx_res,
        "tunnels": {
            "ha_core_local_8123": ha_alive,
            "ha_proto": ha_proto,
            "assigned_dashboard_port": opts.get("remote_dashboard_port", 10001),
            "assigned_ssh_port": opts.get("remote_ssh_port", 22001)
        }
    }
    return payload

def publish_local_entities(payload):
    """Register and update native Home Assistant diagnostic sensors."""
    sys_info = payload.get("system", {})
    net_info = payload.get("network", {})
    knx_info = payload.get("knx_status", {})
    tunnels = payload.get("tunnels", {})

    # 1. Active Boot Slot Sensor
    update_ha_state(
        "sensor.gavasah_boot_slot",
        f"Slot {sys_info.get('boot_slot', 'A')}",
        {
            "friendly_name": "Gavasah Active Boot Slot",
            "boot_slot": sys_info.get("boot_slot"),
            "slot_a_status": sys_info.get("slot_a_status"),
            "slot_b_status": sys_info.get("slot_b_status"),
            "haos_version": sys_info.get("haos_version"),
            "icon": "mdi:chip"
        }
    )

    # 2. Recovery Mode Binary Sensor
    is_rec = sys_info.get("is_recovery_mode", False)
    update_ha_state(
        "binary_sensor.gavasah_recovery_mode",
        "on" if is_rec else "off",
        {
            "friendly_name": "Gavasah System Recovery Mode",
            "device_class": "problem",
            "status_details": "Running on Fallback Slot B!" if is_rec else "System healthy on Slot A",
            "icon": "mdi:alert-octagon" if is_rec else "mdi:shield-check"
        }
    )

    # 3. KNX Gateway Binary Sensor & Latency
    knx_ok = knx_info.get("reachable", False)
    update_ha_state(
        "binary_sensor.gavasah_knx_gateway",
        "on" if knx_ok else "off",
        {
            "friendly_name": "Gavasah KNX Gateway Connectivity",
            "device_class": "connectivity",
            "gateway_ip": knx_info.get("gateway_ip"),
            "gateway_port": knx_info.get("gateway_port"),
            "latency_ms": knx_info.get("latency_ms"),
            "icon": "mdi:transit-connection-variant"
        }
    )

    if knx_ok and "latency_ms" in knx_info:
        update_ha_state(
            "sensor.gavasah_knx_latency",
            knx_info["latency_ms"],
            {
                "friendly_name": "Gavasah KNX Latency",
                "unit_of_measurement": "ms",
                "state_class": "measurement",
                "icon": "mdi:speedometer"
            }
        )

    # 4. Local IP Sensor
    update_ha_state(
        "sensor.gavasah_local_ip",
        net_info.get("local_ipv4", "Unknown"),
        {
            "friendly_name": "Gavasah Local IP Address",
            "gateway": net_info.get("gateway"),
            "mac_address": net_info.get("mac_address"),
            "nameservers": net_info.get("nameservers"),
            "icon": "mdi:ip-network"
        }
    )

    # 5. Cloud Ingress Tunnel Status
    dash_port = tunnels.get("assigned_dashboard_port", 10001)
    cid = payload.get("client_id", "")
    ext_url = f"https://{cid}.gavasah.com" if (cid and cid not in ["unconfigured", "client01"]) else ""
    update_ha_state(
        "binary_sensor.gavasah_cloud_tunnel",
        "on" if tunnels.get("ha_core_local_8123") else "off",
        {
            "friendly_name": "Gavasah Cloud Fleet Tunnel",
            "device_class": "connectivity",
            "ingress_port": dash_port,
            "ssh_port": tunnels.get("assigned_ssh_port", 22001),
            "external_url": ext_url,
            "icon": "mdi:cloud-check"
        }
    )

def send_heartbeat(hub_host, payload):
    endpoints = [
        f"http://{hub_host}:3000/api/heartbeat",
        f"http://{hub_host}/api/heartbeat"
    ]
    data = json.dumps(payload).encode("utf-8")
    for ep in endpoints:
        req = urllib.request.Request(ep, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status in [200, 201]:
                    return True, resp.status
        except Exception:
            continue
    return False, "Failed to reach hub API endpoints"

def main():
    log("Starting Gavasah Cloud Agent Telemetry Engine v1.0.4...")
    opts = load_options()
    hub_host = opts.get("hub_host", "122.175.49.35")
    interval = int(opts.get("heartbeat_interval", 60))

    log(f"Configured Hub: {hub_host} | Client: {opts.get('client_id')} | Interval: {interval}s")

    # Initial sync of Home Assistant External Network URL & Supervisor Toggles (Auto-Update, Watchdog)
    ensure_external_url(opts)
    ensure_supervisor_toggles()

    loop_count = 0
    while True:
        try:
            opts = load_options()
            payload = collect_telemetry(opts)

            # 1. Update native Home Assistant UI entities
            publish_local_entities(payload)

            # 2. Maintain external_url & supervisor toggles synchronization every 5 cycles
            loop_count += 1
            if loop_count % 5 == 0:
                ensure_external_url(opts)
                ensure_supervisor_toggles()

            # 3. Transmit to central dealer hub
            success, status = send_heartbeat(hub_host, payload)
            slot = payload["system"]["boot_slot"]
            recovery = " [RECOVERY MODE ACTIVE!]" if payload["system"]["is_recovery_mode"] else ""
            if success:
                log(f"Heartbeat OK | Slot: {slot}{recovery} | IP: {payload['network']['local_ipv4']} | KNX: {payload['knx_status'].get('reachable')}")
            else:
                log(f"Heartbeat Hub Sync Notice: {status} | Local metrics captured successfully.")
        except Exception as e:
            log(f"Heartbeat loop exception: {e}")

        time.sleep(interval)

if __name__ == "__main__":
    main()
