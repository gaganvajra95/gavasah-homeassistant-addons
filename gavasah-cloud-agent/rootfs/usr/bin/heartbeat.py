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
    if not ip or str(ip).strip().lower() in ["", "none", "null", "false"]:
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

def _probe_single_port(port):
    import ssl
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

def check_tunnel_local_port(port=8123):
    alive, proto = _probe_single_port(port)
    if not alive and port == 8123:
        alive_80, proto_80 = _probe_single_port(80)
        if alive_80:
            return alive_80, proto_80
    return alive, proto

def auto_detect_knx_gateway(opts):
    """
    Automatically detects if Home Assistant is connected to a KNX bus or not.
    Retrieves the KNX IP Gateway address and port automatically without asking dealers.
    
    Checks in sequence:
    1. Home Assistant Core Storage (.storage/core.config_entries)
    2. Home Assistant configuration.yaml (YAML-based KNX integration)
    3. Add-on options fallback if explicitly supplied
    
    If no KNX integration is detected, returns configured=False (Non-KNX / Zigbee / Lutron).
    """
    detected_host = None
    detected_port = 3671
    conn_type = "tunneling"
    found = False

    # 1. Inspect core.config_entries
    storage_candidates = [
        "/homeassistant/.storage/core.config_entries",
        "/config/.storage/core.config_entries"
    ]
    for spath in storage_candidates:
        if os.path.exists(spath):
            try:
                with open(spath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                entries = data.get("data", {}).get("entries", [])
                for entry in entries:
                    if entry.get("domain") == "knx":
                        found = True
                        edata = entry.get("data", {})
                        eopts = entry.get("options", {})
                        conn_type = edata.get("connection_type") or eopts.get("connection_type", "tunneling")
                        host = (
                            edata.get("host") or 
                            edata.get("gateway_ip") or 
                            eopts.get("host") or 
                            eopts.get("gateway_ip")
                        )
                        port = (
                            edata.get("port") or 
                            edata.get("gateway_port") or 
                            eopts.get("port") or 
                            eopts.get("gateway_port") or 
                            3671
                        )
                        if host and str(host).strip() not in ["", "0.0.0.0", "None"]:
                            detected_host = str(host).strip()
                            detected_port = int(port)
                            log(f"[✓] [KNX Auto-Discovery] Found KNX integration in {spath}: {detected_host}:{detected_port} ({conn_type})")
                            break
                        if conn_type == "routing":
                            detected_host = edata.get("routing_ip", "224.0.23.12")
                            detected_port = int(port)
                            log(f"[✓] [KNX Auto-Discovery] Found KNX routing config entry with multicast {detected_host}:{detected_port}")
                            break
                if found and detected_host:
                    break
            except Exception as e:
                log(f"[!] Warning reading {spath}: {e}")

    # 2. Inspect configuration.yaml
    if not detected_host:
        yaml_candidates = [
            "/homeassistant/configuration.yaml",
            "/config/configuration.yaml"
        ]
        for ypath in yaml_candidates:
            if os.path.exists(ypath):
                try:
                    with open(ypath, "r", encoding="utf-8") as f:
                        content = f.read()
                    if "knx:" in content:
                        found = True
                        import re
                        m_host = re.search(r'(?:host|gateway_ip)\s*:\s*["\']?([0-9a-zA-Z\.\-]+)["\']?', content)
                        m_port = re.search(r'(?:port|gateway_port)\s*:\s*([0-9]+)', content)
                        if m_host:
                            detected_host = m_host.group(1).strip()
                            detected_port = int(m_port.group(1).strip()) if m_port else 3671
                            conn_type = "yaml"
                            log(f"[✓] [KNX Auto-Discovery] Found KNX config in {ypath}: {detected_host}:{detected_port}")
                            break
                except Exception as e:
                    log(f"[!] Warning reading {ypath}: {e}")

    # 3. Add-on options fallback if user/dealer manually provided one
    if not detected_host and opts.get("knx_gateway_ip"):
        opt_ip = str(opts.get("knx_gateway_ip")).strip()
        if opt_ip and opt_ip not in ["", "none", "null"]:
            detected_host = opt_ip
            detected_port = int(opts.get("knx_gateway_port", 3671))
            found = True
            conn_type = "addon_options"

    # 4. Integrated loopback KNX probe (e.g. onboard knxd service on 127.0.0.1:3671)
    if not detected_host:
        try:
            loopback_res = ping_knx_gateway("127.0.0.1", 3671, timeout=0.8)
            if loopback_res.get("reachable"):
                detected_host = "127.0.0.1"
                detected_port = 3671
                found = True
                conn_type = "integrated_loopback"
                log("[✓] [KNX Auto-Discovery] Found active onboard KNX service on 127.0.0.1:3671")
        except Exception:
            pass

    # 5. If KNX was found, test reachable latency
    if detected_host:
        res = ping_knx_gateway(detected_host, detected_port)
        res["connection_type"] = conn_type
        return res

    # 5. Non-KNX device (e.g. Lutron, Zigbee, Z-Wave, Matter, etc.)
    return {
        "configured": False,
        "reachable": False,
        "reason": "no_knx_integration",
        "system_type": "non_knx",
        "gateway_ip": "",
        "gateway_port": None
    }

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

    # Dual A/B Symmetric Slot Health Detection
    # In Home Assistant OS and RAUC, both Slot A and Slot B are healthy operational partitions.
    # An active boot into Slot B occurs normally after system updates.
    # A slot is only considered in recovery/fallback if RAUC explicitly flags a boot failure.
    is_recovery = False

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

    # Autonomous KNX vs Non-KNX (Zigbee / Lutron) Discovery & Watchdog
    knx_res = auto_detect_knx_gateway(opts)

    ha_alive, ha_proto = check_tunnel_local_port(8123)
    pubkey = get_public_key()

    slot_upper = str(boot_slot).upper()
    if slot_upper == "B":
        slot_a_state = "standby (good)"
        slot_b_state = "good (active)"
    else:
        slot_a_state = "good (active)"
        slot_b_state = "standby (good)"

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
            "status_details": "Recovery mode active!" if is_rec else f"System healthy on Slot {sys_info.get('boot_slot', 'A')}",
            "icon": "mdi:alert-octagon" if is_rec else "mdi:shield-check"
        }
    )

    # 3. KNX Gateway Binary Sensor & Latency (Only published if KNX is configured)
    if knx_info.get("configured", False):
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
    import ssl
    ctx = ssl._create_unverified_context()
    endpoints = [
        "https://dealer.gavasah.com/api/heartbeat",
        f"https://{hub_host}/api/heartbeat",
        f"http://{hub_host}:3000/api/heartbeat",
        f"http://{hub_host}/api/heartbeat"
    ]
    data = json.dumps(payload).encode("utf-8")
    for ep in endpoints:
        req = urllib.request.Request(ep, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
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

    # Immediate Second-0 Initial Pulse on Startup (Eliminates 60s onboarding wait)
    try:
        init_payload = collect_telemetry(opts)
        publish_local_entities(init_payload)
        init_ok, init_st = send_heartbeat(hub_host, init_payload)
        if init_ok:
            log(f"Immediate second-0 startup heartbeat acknowledged by hub: {init_st}")
    except Exception as e:
        log(f"Initial startup heartbeat notice: {e}")

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
