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

def ping_knx_gateway(ip, port=3671, timeout=2.0):
    if not ip:
        return {"configured": False, "reachable": False}
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
            return {"configured": True, "reachable": True, "latency_ms": latency_ms}
        except socket.timeout:
            s.close()
            return {"configured": True, "reachable": False, "error": "timeout"}
    except Exception as e:
        return {"configured": True, "reachable": False, "error": str(e)}

def check_tunnel_local_port(port=8123):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except Exception:
        return False

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
    if boot_slot.upper() == "B":
        # Slot B is usually fallback after Slot A fails
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

    # KNX Gateway Check
    knx_res = ping_knx_gateway(
        opts.get("knx_gateway_ip", ""),
        opts.get("knx_gateway_port", 3671)
    )

    ha_alive = check_tunnel_local_port(8123)

    payload = {
        "client_id": opts.get("client_id", "unconfigured"),
        "auth_key": opts.get("auth_key", ""),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "system": {
            "hostname": host_info.get("hostname", "homeassistant"),
            "haos_version": haos_version,
            "core_version": core_info.get("version", "Unknown"),
            "board": board,
            "boot_slot": boot_slot,
            "is_recovery_mode": is_recovery,
            "slot_a_status": "good" if not is_recovery else "degraded_or_fallback",
            "slot_b_status": "good" if is_recovery else "standby",
            "cpu_percent": host_info.get("cpu_percent", 0),
            "memory_percent": host_info.get("memory_percent", 0),
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
            "assigned_dashboard_port": opts.get("remote_dashboard_port", 10001),
            "assigned_ssh_port": opts.get("remote_ssh_port", 22001)
        }
    }
    return payload

def send_heartbeat(hub_host, payload):
    # Sends to port 3000 (Dealer API) or port 80/443
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
    log("Starting Gavasah Cloud Agent Telemetry Engine...")
    opts = load_options()
    hub_host = opts.get("hub_host", "122.175.49.35")
    interval = int(opts.get("heartbeat_interval", 30))

    log(f"Configured Hub: {hub_host} | Client: {opts.get('client_id')} | Interval: {interval}s")

    while True:
        try:
            opts = load_options()
            payload = collect_telemetry(opts)
            success, status = send_heartbeat(hub_host, payload)
            if success:
                slot = payload["system"]["boot_slot"]
                recovery = " [RECOVERY MODE!]" if payload["system"]["is_recovery_mode"] else ""
                log(f"Heartbeat OK | Slot: {slot}{recovery} | IP: {payload['network']['local_ipv4']} | KNX: {payload['knx_status'].get('reachable')}")
            else:
                log(f"Heartbeat delivery failed: {status}")
        except Exception as e:
            log(f"Heartbeat loop exception: {e}")

        time.sleep(interval)

if __name__ == "__main__":
    main()
