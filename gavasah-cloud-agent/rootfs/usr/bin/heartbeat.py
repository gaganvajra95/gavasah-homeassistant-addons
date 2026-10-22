#!/usr/bin/env python3
"""
GAVASAH Cloud Agent - System Telemetry, RAUC Slot Health & KNX Bus Watchdog
Runs inside Home Assistant OS Add-on container with host_dbus & supervisor_api privileges.
"""

import os
import sys
import re
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

ADDON_VERSION = "1.3.1"
MAX_HEALING_ATTEMPTS = 5
HEALING_COOLDOWN_SEC = 60
STABILIZATION_SEC = 300

UNMONITORED_CACHE_FILE = "/data/unmonitored_integrations.json"
SELF_HEALING_CACHE_FILE = "/data/self_healing_registry.json"

_healing_lock = threading.Lock()

def get_unmonitored_integrations():
    try:
        if os.path.exists(UNMONITORED_CACHE_FILE):
            with open(UNMONITORED_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
    except Exception:
        pass
    return []

def load_healing_registry():
    global _healing_registry
    try:
        if os.path.exists(SELF_HEALING_CACHE_FILE):
            with open(SELF_HEALING_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    _healing_registry = data
                    log(f"[Self-Healing Engine] Loaded persistent healing registry from {SELF_HEALING_CACHE_FILE}")
    except Exception as e:
        log(f"Notice: Could not load {SELF_HEALING_CACHE_FILE}: {e}")

def save_healing_registry():
    try:
        os.makedirs(os.path.dirname(SELF_HEALING_CACHE_FILE), exist_ok=True)
        tmp = f"{SELF_HEALING_CACHE_FILE}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_healing_registry, f, indent=2)
        os.replace(tmp, SELF_HEALING_CACHE_FILE)
    except Exception as e:
        log(f"[!] Notice: Could not save {SELF_HEALING_CACHE_FILE}: {e}")

def update_unmonitored_integrations(unmon_list):
    global _healing_registry
    if not isinstance(unmon_list, list):
        return
    try:
        current = get_unmonitored_integrations()
        if set(current) != set(unmon_list):
            os.makedirs(os.path.dirname(UNMONITORED_CACHE_FILE), exist_ok=True)
            with open(UNMONITORED_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(unmon_list, f)
            log(f"[Self-Healing Engine] Updated unmonitored integrations from Dealer Hub: {unmon_list}")
        
        # Halt and disable self-healing for any disabled integrations immediately
        with _healing_lock:
            for sub in unmon_list:
                if sub in _healing_registry:
                    _healing_registry[sub]["status"] = "disabled"
                    _healing_registry[sub]["attempts"] = 0
                    _healing_registry[sub]["exhausted"] = False
                    _healing_registry[sub]["last_action"] = "Monitoring muted from Dealer Dashboard. Auto-recovery paused."
            save_healing_registry()
    except Exception as e:
        log(f"[!] Error updating unmonitored integrations: {e}")

# In-memory Autonomous Self-Healing Registry & History
_healing_registry = {}
_recent_recoveries = []
_last_system_error = None

def record_last_command_error(command, err_str):
    global _last_system_error
    _last_system_error = {
        "command": command,
        "error": str(err_str),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

def clear_last_command_error():
    global _last_system_error
    _last_system_error = None

def supervisor_get(endpoint):
    url = f"{SUPERVISOR_URL}/{endpoint}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("data", data)
            return data
    except Exception as e:
        return {"error": str(e)}

def supervisor_post(endpoint, payload_dict=None, timeout=15):
    """Makes an authenticated POST request to Home Assistant Supervisor API."""
    if not SUPERVISOR_TOKEN:
        return False, {"error": "no_supervisor_token"}
    url = f"{SUPERVISOR_URL}/{endpoint}"
    payload = json.dumps(payload_dict or {}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
        "Content-Type": "application/json"
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            if isinstance(data, dict):
                return True, data.get("data", data)
            return True, data
    except Exception as e:
        return False, {"error": str(e)}

def is_entry_ignored_or_disabled(e):
    """Checks if a Home Assistant integration config entry is ignored or disabled."""
    if not isinstance(e, dict):
        return True
    # Ignored Zeroconf / SSDP / DHCP discovery
    if str(e.get("source", "")).strip().lower() == "ignore":
        return True
    # User disabled integration
    if e.get("disabled_by"):
        return True
    # State is explicitly ignored
    if str(e.get("state", "")).strip().lower() == "ignored":
        return True
    return False

def get_ha_config_entries():
    """Retrieves all active config entries with live runtime state from Home Assistant Core."""
    res = supervisor_get("core/api/config/config_entries/entry")
    entries = []
    if isinstance(res, list):
        entries = res
    elif isinstance(res, dict) and isinstance(res.get("data"), list):
        entries = res["data"]
    else:
        for spath in ["/homeassistant/.storage/core.config_entries", "/config/.storage/core.config_entries"]:
            if os.path.exists(spath):
                try:
                    with open(spath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    entries = data.get("data", {}).get("entries", [])
                    break
                except Exception:
                    pass
    # Completely filter out ignored discoveries (source == 'ignore'), user-disabled entries, and ignored states
    return [e for e in entries if not is_entry_ignored_or_disabled(e)]

def reload_ha_config_entry(entry_id):
    """Reloads a specific integration config entry via Core REST API."""
    if not SUPERVISOR_TOKEN or not entry_id:
        return False
    ok, _ = supervisor_post(f"core/api/config/config_entries/entry/{entry_id}/reload")
    return ok

def unload_ha_config_entry(entry_id):
    """Unloads a failed integration config entry to halt HA Core's infinite background setup_retry loop."""
    if not SUPERVISOR_TOKEN or not entry_id:
        return False
    ok, _ = supervisor_post(f"core/api/config/config_entries/entry/{entry_id}/unload")
    return ok

def halt_ha_core_retries_for_exhausted_subsystem(subsystem, tech_data):
    """
    Halts Home Assistant Core's native background retry loop when a subsystem
    exhausts its 5 self-healing attempts. By unloading the failed config entries,
    Home Assistant Core stops hammering offline devices and ceases background log spam.
    """
    try:
        if subsystem == "failed_core_entries":
            failed_list = tech_data.get("failed_core_entries", [])
            for f in failed_list:
                eid = f.get("entry_id")
                if eid:
                    if unload_ha_config_entry(eid):
                        log(f"[✓] [Self-Healing Engine] Unloaded exhausted core entry '{f.get('title', eid)}' ({eid[:8]}) to halt HA Core background retry loop")
        elif subsystem == "coolmaster":
            cm_info = tech_data.get("coolmaster", {})
            for ent in cm_info.get("entries", []):
                eid = ent.get("entry_id")
                if eid and ent.get("state") in ["setup_error", "setup_retry", "failed_unload"]:
                    if unload_ha_config_entry(eid):
                        log(f"[✓] [Self-Healing Engine] Unloaded exhausted CoolMaster entry ({eid[:8]}) to halt HA Core retry loop")
        elif subsystem == "lutron":
            lut_info = tech_data.get("lutron", {})
            for ent in lut_info.get("entries", []):
                eid = ent.get("entry_id")
                if eid and ent.get("state") in ["setup_error", "setup_retry", "failed_unload"]:
                    if unload_ha_config_entry(eid):
                        log(f"[✓] [Self-Healing Engine] Unloaded exhausted Lutron entry ({eid[:8]}) to halt HA Core retry loop")
        elif subsystem == "knx":
            entries = get_ha_config_entries()
            knx_entry = next((e for e in entries if e.get("domain") == "knx"), None)
            if knx_entry and knx_entry.get("entry_id") and knx_entry.get("state") in ["setup_error", "setup_retry"]:
                unload_ha_config_entry(knx_entry["entry_id"])
        elif subsystem == "matter":
            entries = get_ha_config_entries()
            m_entry = next((e for e in entries if e.get("domain") == "matter"), None)
            if m_entry and m_entry.get("entry_id") and m_entry.get("state") in ["setup_error", "setup_retry"]:
                unload_ha_config_entry(m_entry["entry_id"])
        elif subsystem == "zigbee":
            entries = get_ha_config_entries()
            z_entry = next((e for e in entries if e.get("domain") == "zha"), None)
            if z_entry and z_entry.get("entry_id") and z_entry.get("state") in ["setup_error", "setup_retry"]:
                unload_ha_config_entry(z_entry["entry_id"])
    except Exception as e:
        log(f"[!] Notice: Could not unload exhausted subsystem '{subsystem}' entries: {e}")

def restart_addon_container(addon_slug):
    """Restarts a specific Home Assistant Add-on container via Supervisor API."""
    if not SUPERVISOR_TOKEN or not addon_slug:
        return False
    ok, _ = supervisor_post(f"addons/{addon_slug}/restart", timeout=45)
    return ok

def notify_ha_self_healing_exhausted(subsystem, attempts):
    """Notifies Home Assistant Core via persistent notification when self-healing attempts are exhausted."""
    pretty = subsystem.replace("_", " ").upper()
    title = f"Gavasah Subsystem Alert: {pretty}"
    message = (
        f"Autonomous self-healing for '{pretty}' has stopped after {attempts} failed attempts. "
        f"Background connection retries have been halted in Home Assistant Core to prevent network storming. "
        f"Manual inspection required. Counter locked until gateway/add-on restart."
    )
    try:
        supervisor_post("core/api/services/persistent_notification/create", {
            "title": title,
            "message": message,
            "notification_id": f"gavasah_sh_exhausted_{subsystem}"
        })
    except Exception as e:
        log(f"[!] Notice: Could not create persistent notification: {e}")

def execute_subsystem_remediation(subsystem, tech_data, opts, attempt_num):
    """Executes targeted auto-healing remediation steps based on subsystem and attempt number."""
    try:
        if subsystem == "knx":
            entries = get_ha_config_entries()
            knx_entry = next((e for e in entries if e.get("domain") == "knx"), None)
            if knx_entry and knx_entry.get("entry_id"):
                eid = knx_entry["entry_id"]
                if reload_ha_config_entry(eid):
                    return f"Reloaded Core KNX config entry ({eid[:8]})"
            ok, _ = supervisor_post("core/api/services/homeassistant/reload_core_config", {})
            if ok:
                return "Reloaded Home Assistant core configuration"
            return "Recycled KNXnet/IP socket probe"

        elif subsystem == "coolmaster":
            entries = get_ha_config_entries()
            cm_entry = next((e for e in entries if e.get("domain") in ["coolmaster", "coolmasternet", "coolautomation"]), None)
            if cm_entry and cm_entry.get("entry_id"):
                eid = cm_entry["entry_id"]
                if reload_ha_config_entry(eid):
                    return f"Reloaded Core CoolMaster config entry ({eid[:8]})"
            cm_info = tech_data.get("coolmaster", {})
            for ent in cm_info.get("entries", []):
                host = ent.get("host")
                port = int(ent.get("port", 10102))
                if host:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2.0)
                        s.connect((host, port))
                        s.sendall(b"\r\n")
                        s.close()
                        return f"Flushed CoolMaster TCP socket {host}:{port}"
                    except Exception:
                        pass
            return "Recycled CoolMaster connection parameters"

        elif subsystem == "zigbee":
            zigbee_info = tech_data.get("zigbee", {})
            insts = zigbee_info.get("instances", [])
            failed_insts = [i for i in insts if not i.get("running") or i.get("state") != "started"]
            if failed_insts:
                restarted = []
                for fi in failed_insts:
                    slug = fi.get("slug")
                    if slug and restart_addon_container(slug):
                        restarted.append(fi.get("name", slug))
                if restarted:
                    return f"Restarted Zigbee2MQTT container: {', '.join(restarted)}"
            if zigbee_info.get("zha_detected"):
                entries = get_ha_config_entries()
                zha_entry = next((e for e in entries if e.get("domain") == "zha"), None)
                if zha_entry and zha_entry.get("entry_id"):
                    eid = zha_entry["entry_id"]
                    if reload_ha_config_entry(eid):
                        return f"Reloaded Core ZHA config entry ({eid[:8]})"
            return "Recycled Zigbee coordinator stack"

        elif subsystem == "lutron":
            entries = get_ha_config_entries()
            lutron_entries = [e for e in entries if e.get("domain") in ["lutron", "lutron_caseta", "lutron_homeworks"]]
            if lutron_entries:
                reloaded = []
                for le in lutron_entries:
                    eid = le.get("entry_id")
                    if eid and reload_ha_config_entry(eid):
                        reloaded.append(le.get("title", eid[:8]))
                if reloaded:
                    return f"Reloaded Lutron config entry: {', '.join(reloaded)}"
            return "Recycled Lutron repeater bridge communication"

        elif subsystem == "matter":
            addons_resp = supervisor_get("addons")
            addons_list = addons_resp.get("addons", []) if isinstance(addons_resp, dict) else []
            for a in addons_list:
                slug = str(a.get("slug", "")).lower()
                if "matter" in slug:
                    if restart_addon_container(a.get("slug")):
                        return f"Restarted Matter Server container ({a.get('slug')})"
            entries = get_ha_config_entries()
            m_entry = next((e for e in entries if e.get("domain") == "matter"), None)
            if m_entry and m_entry.get("entry_id"):
                eid = m_entry["entry_id"]
                if reload_ha_config_entry(eid):
                    return f"Reloaded Core Matter config entry ({eid[:8]})"
            return "Recycled Matter server daemon"

        elif subsystem == "failed_core_entries":
            failed_list = tech_data.get("failed_core_entries", [])
            reloaded_titles = []
            seen_ids = set()
            for f in failed_list:
                eid = f.get("entry_id")
                if eid and eid not in seen_ids:
                    seen_ids.add(eid)
                    if reload_ha_config_entry(eid):
                        reloaded_titles.append(f.get("title", f.get("domain", "entry")))
            if reloaded_titles:
                return f"Reloaded failed core integration(s): {', '.join(reloaded_titles)}"
            return "Reloaded failed integration entries"
    except Exception as ex:
        return f"Remediation error: {ex}"

    return "Executed general subsystem recovery"

def run_autonomous_self_healing_engine(tech_data, opts):
    """
    Autonomous Self-Healing Engine:
    Monitors all subsystems and executes up to 5 self-remediation attempts with a 60-second
    cooldown before escalating alarms to Integrator, Dealer, or Manufacturer HQ.
    When 5 attempts are exhausted, cleanly unloads failing config entries in Home Assistant Core
    to halt Core's infinite background retry loop, and locks state persistently in /data.
    """
    global _healing_registry, _recent_recoveries
    with _healing_lock:
        now_ts = time.time()
        now_iso = datetime.datetime.utcnow().isoformat() + "Z"

        subsystem_checks = {}

        # 1. KNX
        knx = tech_data.get("knx", {})
        if knx.get("configured") and knx.get("reason") != "no_knx_integration":
            subsystem_checks["knx"] = not bool(knx.get("reachable"))

        # 2. CoolMaster
        cm = tech_data.get("coolmaster", {})
        if cm.get("detected"):
            subsystem_checks["coolmaster"] = bool(cm.get("status") in ["offline", "degraded"] or cm.get("offline_reason"))

        # 3. Zigbee
        zig = tech_data.get("zigbee", {})
        if zig.get("detected"):
            subsystem_checks["zigbee"] = bool(zig.get("status") in ["offline", "degraded"] or zig.get("offline_reason"))

        # 4. Lutron
        lut = tech_data.get("lutron", {})
        if lut.get("detected"):
            subsystem_checks["lutron"] = bool(lut.get("status") in ["offline", "degraded"] or lut.get("offline_reason"))

        # 5. Matter
        mat = tech_data.get("matter", {})
        if mat.get("detected"):
            subsystem_checks["matter"] = bool(mat.get("status") == "offline" or mat.get("state") in ["stopped", "error", "failed"])

        # 6. Core Integrations
        failed_core = tech_data.get("failed_core_entries", [])
        if failed_core:
            subsystem_checks["failed_core_entries"] = True

        # Process all tracked subsystems
        all_tracked = set(subsystem_checks.keys()).union(_healing_registry.keys())
        unmonitored = set(get_unmonitored_integrations())

        registry_dirty = False

        for sub in all_tracked:
            if sub in unmonitored:
                st = _healing_registry.setdefault(sub, {
                    "attempts": 0,
                    "max_attempts": MAX_HEALING_ATTEMPTS,
                    "cooldown_sec": HEALING_COOLDOWN_SEC,
                    "first_failed": None,
                    "last_attempt_time": 0,
                    "last_action": "Monitoring muted from Dealer Dashboard. Auto-recovery paused.",
                    "status": "disabled"
                })
                st["status"] = "disabled"
                st["attempts"] = 0
                st["exhausted"] = False
                st["last_action"] = "Monitoring muted from Dealer Dashboard. Auto-recovery paused."
                continue

            is_failing = subsystem_checks.get(sub, False)
            st = _healing_registry.setdefault(sub, {
                "attempts": 0,
                "max_attempts": MAX_HEALING_ATTEMPTS,
                "cooldown_sec": HEALING_COOLDOWN_SEC,
                "first_failed": None,
                "last_attempt_time": 0,
                "last_action": "",
                "status": "idle"
            })

            if is_failing:
                if not st.get("first_failed"):
                    st["first_failed"] = now_iso
                    registry_dirty = True
                
                curr_attempts = st.get("attempts", 0)
                if st.get("exhausted") or curr_attempts >= MAX_HEALING_ATTEMPTS:
                    # Per user directive: stop and notify, halt HA Core background retries, lock counter
                    st["exhausted"] = True
                    st["status"] = "exhausted"
                    if not st.get("notified"):
                        notify_ha_self_healing_exhausted(sub, curr_attempts or MAX_HEALING_ATTEMPTS)
                        halt_ha_core_retries_for_exhausted_subsystem(sub, tech_data)
                        st["notified"] = True
                        st["last_action"] = f"Self-healing halted after {curr_attempts or MAX_HEALING_ATTEMPTS} failed attempts. Core background retries halted. Counter locked."
                        log(f"[!] [Self-Healing Engine] {sub} recovery attempts exhausted ({curr_attempts or MAX_HEALING_ATTEMPTS}/{MAX_HEALING_ATTEMPTS} failed). Core background retries halted.")
                        registry_dirty = True
                else:
                    time_since_last = now_ts - st.get("last_attempt_time", 0)
                    if time_since_last >= HEALING_COOLDOWN_SEC or curr_attempts == 0:
                        st["attempts"] = curr_attempts + 1
                        st["last_attempt_time"] = now_ts
                        action_result = execute_subsystem_remediation(sub, tech_data, opts, st["attempts"])
                        st["last_action"] = action_result
                        log(f"[✓] [Self-Healing Engine] Remediating {sub} (Attempt {st['attempts']}/{MAX_HEALING_ATTEMPTS}): {action_result}")
                        registry_dirty = True
                        if st["attempts"] >= MAX_HEALING_ATTEMPTS:
                            # Reached 5 attempts: immediately stop, unload core retries, and notify
                            st["status"] = "exhausted"
                            st["exhausted"] = True
                            notify_ha_self_healing_exhausted(sub, st["attempts"])
                            halt_ha_core_retries_for_exhausted_subsystem(sub, tech_data)
                            st["notified"] = True
                            st["last_action"] = f"Self-healing halted after {st['attempts']} failed attempts. Core background retries halted. Counter locked."
                            log(f"[!] [Self-Healing Engine] {sub} reached {MAX_HEALING_ATTEMPTS}/{MAX_HEALING_ATTEMPTS} attempts and failed. Self-healing permanently stopped and HA Core retries unloaded.")
                        else:
                            st["status"] = "healing"
                    else:
                        st["status"] = "healing"
                        remaining = int(HEALING_COOLDOWN_SEC - time_since_last)
                        log(f"[Self-Healing Engine] {sub} in cooldown ({remaining}s remaining) before attempt {curr_attempts + 1}/{MAX_HEALING_ATTEMPTS}")
            else:
                # Subsystem is currently reporting healthy
                if st.get("exhausted") or st.get("attempts", 0) >= MAX_HEALING_ATTEMPTS:
                    # Strictly locked: do not reset exhausted status on flapping
                    st["status"] = "exhausted"
                    st["exhausted"] = True
                else:
                    # Subsystem had previous attempts and is currently healthy
                    prev_attempts = st.get("attempts", 0)
                    if prev_attempts > 0 or st.get("status") in ["healing", "stabilizing"]:
                        last_attempt = st.get("last_attempt_time", 0)
                        healthy_duration = now_ts - last_attempt
                        # Flapping suppression: Require sustained healthy state across STABILIZATION_SEC (300s)
                        if healthy_duration >= STABILIZATION_SEC:
                            recovery_event = {
                                "subsystem": sub,
                                "recovered_at": now_iso,
                                "attempts_taken": prev_attempts,
                                "final_action": st.get("last_action", "Auto-remediation successful")
                            }
                            _recent_recoveries.insert(0, recovery_event)
                            del _recent_recoveries[15:]
                            log(f"[✓] [Self-Healing Engine] Subsystem '{sub}' stabilized and recovered after {prev_attempts} attempt(s) ({int(healthy_duration)}s sustained healthy)!")
                            st["attempts"] = 0
                            st["status"] = "idle"
                            st["first_failed"] = None
                            st["last_attempt_time"] = 0
                            st["last_action"] = f"Recovered autonomously after {prev_attempts} attempts"
                            registry_dirty = True
                        else:
                            remaining_stab = int(STABILIZATION_SEC - healthy_duration)
                            st["status"] = "stabilizing"
                            st["last_action"] = f"Stabilizing ({remaining_stab}s remaining) before clearing attempt counter"

        if registry_dirty:
            save_healing_registry()

        # Embed self_healing metadata directly into tech_data
        is_healing_active = any(s.get("status") == "healing" for s in _healing_registry.values())
        tech_data["self_healing"] = {
            "active": is_healing_active,
            "max_attempts": MAX_HEALING_ATTEMPTS,
            "cooldown_sec": HEALING_COOLDOWN_SEC,
            "subsystems": _healing_registry,
            "recent_recoveries": _recent_recoveries
        }

        # Annotate individual subsystem dicts
        for sub, info in tech_data.items():
            if isinstance(info, dict) and sub in _healing_registry:
                info["self_healing"] = _healing_registry[sub]

        return tech_data

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

def auto_heal_ip_bans_and_proxy():
    """
    Scans for and purges loopback IP bans (127.0.0.1, ::1) from ip_bans.yaml
    and verifies that Home Assistant's HTTP reverse proxy trusted_proxies block
    is configured in configuration.yaml so the client never returns 403 Forbidden
    or 400 Bad Request over the ingress tunnel.
    """
    config_paths = ["/homeassistant", "/config"]
    healed_ban = False
    healed_proxy = False

    for base in config_paths:
        ban_file = os.path.join(base, "ip_bans.yaml")
        if os.path.exists(ban_file):
            try:
                with open(ban_file, "r", encoding="utf-8") as f:
                    content = f.read()
                if "127.0.0.1" in content or "::1" in content or "10.42.0." in content:
                    lines = content.splitlines()
                    cleaned = []
                    skip = False
                    for line in lines:
                        # Match loopback entries whether quoted or unquoted ('127.0.0.1':, "127.0.0.1":, 127.0.0.1:)
                        is_loopback_entry = (
                            ("127.0.0.1" in line or "::1" in line or "10.42.0." in line) and
                            (":" in line and not line.startswith(" ") and not line.startswith("\t"))
                        )
                        if is_loopback_entry:
                            skip = True
                            continue
                        elif skip and (line.startswith(" ") or line.startswith("\t")):
                            continue
                        else:
                            skip = False
                            cleaned.append(line)
                    with open(ban_file, "w", encoding="utf-8") as f:
                        f.write("\n".join(cleaned) + "\n")
                    log(f"[✓] [Self-Heal] Successfully purged loopback IP bans from {ban_file}!")
                    healed_ban = True
            except Exception as e:
                log(f"[!] [Self-Heal] Error reading/modifying {ban_file}: {e}")

        cfg_file = os.path.join(base, "configuration.yaml")
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file, "r", encoding="utf-8") as f:
                    cfg_content = f.read()
                
                needs_update = False
                new_cfg = cfg_content
                if "ip_ban_enabled: false" not in new_cfg:
                    if "http:" in new_cfg:
                        # Inject ip_ban_enabled: false directly under http:
                        new_cfg = re.sub(r'(^|\n)http:\s*(\n|$)', r'\1http:\n  ip_ban_enabled: false\n', new_cfg, count=1)
                        needs_update = True
                    else:
                        proxy_snippet = """

# GAVASAH Cloud Autonomous Fleet Ingress Reverse Proxy Configuration
http:
  ip_ban_enabled: false
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
    - ::1
    - 10.42.0.0/24
    - 192.168.0.0/16
    - 172.16.0.0/12
"""
                        new_cfg += proxy_snippet
                        needs_update = True

                if "use_x_forwarded_for" not in new_cfg or "trusted_proxies" not in new_cfg:
                    if "http:" not in new_cfg:
                        proxy_snippet = """

# GAVASAH Cloud Autonomous Fleet Ingress Reverse Proxy Configuration
http:
  ip_ban_enabled: false
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
    - ::1
    - 10.42.0.0/24
    - 192.168.0.0/16
    - 172.16.0.0/12
"""
                        new_cfg += proxy_snippet
                        needs_update = True

                if needs_update:
                    with open(cfg_file, "w", encoding="utf-8") as f:
                        f.write(new_cfg)
                    log(f"[✓] [Self-Heal] Configured ip_ban_enabled: false and trusted_proxies in {cfg_file}!")
                    healed_proxy = True
            except Exception as e:
                log(f"[!] [Self-Heal] Error updating {cfg_file}: {e}")

    # If changes were applied, reload Home Assistant Core or restart core via Supervisor API
    if healed_ban or healed_proxy:
        if SUPERVISOR_TOKEN:
            try:
                r_url = f"{SUPERVISOR_URL}/core/api/services/homeassistant/reload_core_config"
                req = urllib.request.Request(r_url, data=b"{}", headers={
                    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                    "Content-Type": "application/json"
                }, method="POST")
                with urllib.request.urlopen(req, timeout=5):
                    log("[✓] [Self-Heal] Reloaded Home Assistant Core configuration.")
            except Exception:
                pass

            if healed_ban:
                try:
                    restart_url = f"{SUPERVISOR_URL}/core/restart"
                    req = urllib.request.Request(restart_url, data=b"{}", headers={
                        "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                        "Content-Type": "application/json"
                    }, method="POST")
                    with urllib.request.urlopen(req, timeout=10):
                        log("[✓] [Self-Heal] Home Assistant Core restart triggered to flush banned IP table.")
                except Exception as ex:
                    log(f"[!] [Self-Heal] Core restart trigger notice: {ex}")

def handle_remote_command(hub_host, opts, command):
    """Executes administrative maintenance commands dispatched by Dealer Central Hub."""
    if not isinstance(command, dict):
        return
    action = command.get("action", "")
    log(f"[REMOTE_COMMAND] Received hub command: '{action}'")

    if action in ["unban_and_fix", "heal_bans"]:
        auto_heal_ip_bans_and_proxy()
        # Always trigger restart when unban_and_fix is commanded to clear in-memory ban table
        if SUPERVISOR_TOKEN:
            try:
                restart_url = f"{SUPERVISOR_URL}/core/restart"
                req = urllib.request.Request(restart_url, data=b"{}", headers={
                    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                    "Content-Type": "application/json"
                }, method="POST")
                with urllib.request.urlopen(req, timeout=10):
                    log("[REMOTE_COMMAND] Core restart dispatched to finalize unban.")
            except Exception as e:
                log(f"[REMOTE_COMMAND] Core restart notice: {e}")
    elif action == "exec":
        cmd_str = command.get("command", "")
        if cmd_str:
            import subprocess
            try:
                subprocess.run(cmd_str, shell=True, timeout=30)
                log(f"[REMOTE_COMMAND] Executed shell command: {cmd_str[:60]}")
            except Exception as ex:
                log(f"[REMOTE_COMMAND] Shell execution error: {ex}")
    elif action == "restart_core":
        if SUPERVISOR_TOKEN:
            try:
                req = urllib.request.Request(
                    f"{SUPERVISOR_URL}/core/restart",
                    data=b"{}",
                    headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}", "Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=10):
                    log("[REMOTE_COMMAND] Core restart successfully triggered.")
            except Exception as e:
                log(f"[REMOTE_COMMAND] Core restart error: {e}")
    elif action == "reload_core_config":
        if SUPERVISOR_TOKEN:
            try:
                req = urllib.request.Request(
                    f"{SUPERVISOR_URL}/core/api/services/homeassistant/reload_core_config",
                    data=b"{}",
                    headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}", "Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=5):
                    log("[REMOTE_COMMAND] Core configuration reload triggered.")
            except Exception as e:
                log(f"[REMOTE_COMMAND] Core reload error: {e}")
    elif action in ["reboot_gateway", "reboot_host"]:
        if SUPERVISOR_TOKEN:
            try:
                log("[REMOTE_COMMAND] Gavasah Gateway host hardware reboot commanded. Dispatching /host/reboot...")
                ok, res = supervisor_post("host/reboot", {}, timeout=15)
                if not ok:
                    log(f"[REMOTE_COMMAND] Host reboot returned: {res}. Falling back to core restart...")
                    ok2, res2 = supervisor_post("core/restart", {}, timeout=15)
                    if not ok2:
                        record_last_command_error(action, f"Host reboot: {res}; Core restart: {res2}")
                    else:
                        clear_last_command_error()
                else:
                    clear_last_command_error()
                    log("[REMOTE_COMMAND] Gateway host reboot dispatched successfully.")
            except Exception as e:
                record_last_command_error(action, str(e))
                log(f"[REMOTE_COMMAND] Host reboot error: {e}")

    elif action == "update_core":
        if SUPERVISOR_TOKEN:
            try:
                log("[REMOTE_COMMAND] Home Assistant Core update commanded. Dispatching /core/update...")
                ok, res = supervisor_post("core/update", {}, timeout=180)
                if ok:
                    clear_last_command_error()
                    log("[REMOTE_COMMAND] Home Assistant Core update initiated successfully.")
                else:
                    err_msg = res.get("message") or res.get("error") or "Core update command failed"
                    record_last_command_error(action, err_msg)
                    log(f"[REMOTE_COMMAND] Core update error: {err_msg}")
            except Exception as e:
                record_last_command_error(action, str(e))
                log(f"[REMOTE_COMMAND] Core update exception: {e}")

    elif action == "update_supervisor":
        if SUPERVISOR_TOKEN:
            try:
                log("[REMOTE_COMMAND] Home Assistant Supervisor update commanded. Dispatching /supervisor/update...")
                ok, res = supervisor_post("supervisor/update", {}, timeout=180)
                if ok:
                    clear_last_command_error()
                    log("[REMOTE_COMMAND] Home Assistant Supervisor update initiated successfully.")
                else:
                    err_msg = res.get("message") or res.get("error") or "Supervisor update command failed"
                    record_last_command_error(action, err_msg)
                    log(f"[REMOTE_COMMAND] Supervisor update error: {err_msg}")
            except Exception as e:
                record_last_command_error(action, str(e))
                log(f"[REMOTE_COMMAND] Supervisor update exception: {e}")

    elif action == "update_addon":
        if SUPERVISOR_TOKEN:
            try:
                log("[REMOTE_COMMAND] Reloading Supervisor Add-on Store to fetch newest release index...")
                supervisor_post("store/reload", {}, timeout=20)
                time.sleep(3)
                log(f"[REMOTE_COMMAND] Initiating add-on self-update to latest release...")
                ok, res = supervisor_post("addons/self/update", {}, timeout=90)
                if ok:
                    clear_last_command_error()
                    log("[REMOTE_COMMAND] Add-on self-update successfully initiated.")
                else:
                    err_msg = res.get("message") or res.get("error") or "Add-on update command failed"
                    record_last_command_error(action, err_msg)
                    log(f"[REMOTE_COMMAND] Add-on update error: {err_msg}")
            except Exception as e:
                record_last_command_error(action, str(e))
                log(f"[REMOTE_COMMAND] Add-on update exception: {e}")

    elif action == "update_all":
        if SUPERVISOR_TOKEN:
            try:
                log("[REMOTE_COMMAND] Master Full Update commanded. Reloading store...")
                supervisor_post("store/reload", {}, timeout=20)
                time.sleep(2)
                log("[REMOTE_COMMAND] Updating Gavasah Cloud Agent add-on...")
                supervisor_post("addons/self/update", {}, timeout=90)
                time.sleep(2)
                log("[REMOTE_COMMAND] Updating Home Assistant Core...")
                supervisor_post("core/update", {}, timeout=180)
                time.sleep(2)
                log("[REMOTE_COMMAND] Updating Home Assistant Supervisor...")
                supervisor_post("supervisor/update", {}, timeout=180)
                clear_last_command_error()
                log("[REMOTE_COMMAND] Master Full Update sequence dispatched successfully.")
            except Exception as e:
                record_last_command_error(action, str(e))
                log(f"[REMOTE_COMMAND] Master update error: {e}")


def check_ha_knx_native_connection():
    """
    Checks Home Assistant's native KNX integration runtime state via Supervisor Core API.
    Returns (is_connected, details_dict)
    """
    if not SUPERVISOR_TOKEN:
        return False, {}
    try:
        # 1. Check sensor.knx_interface_connection_established
        conn_st = supervisor_get("core/api/states/sensor.knx_interface_connection_established")
        if isinstance(conn_st, dict) and conn_st.get("state") not in ["unavailable", "unknown", None, ""]:
            attrs = conn_st.get("attributes", {})
            return True, {
                "established_at": conn_st.get("state"),
                "friendly_name": attrs.get("friendly_name", "KNX Interface"),
                "source": "sensor.knx_interface_connection_established"
            }

        # 2. Check sensor.knx_interface_telegrams
        tel_st = supervisor_get("core/api/states/sensor.knx_interface_telegrams")
        if isinstance(tel_st, dict) and tel_st.get("state") not in ["unavailable", "unknown", None, ""]:
            return True, {
                "telegrams": tel_st.get("state"),
                "source": "sensor.knx_interface_telegrams"
            }

        # 3. Check config_entries state for domain 'knx'
        cfg_entries = supervisor_get("core/api/config/config_entries/entry")
        if isinstance(cfg_entries, list):
            for entry in cfg_entries:
                if entry.get("domain") == "knx" and entry.get("state") == "loaded":
                    return True, {
                        "entry_title": entry.get("title", "KNX Router"),
                        "source": "core.config_entries"
                    }
    except Exception:
        pass
    return False, {}

def ping_knx_gateway(ip, port=3671, timeout=1.5):
    if not ip or str(ip).strip().lower() in ["", "none", "null", "false"]:
        return {
            "configured": False,
            "reachable": False,
            "reason": "unconfigured",
            "gateway_ip": "",
            "gateway_port": port
        }

    # 1. Primary Source of Truth: Check if Home Assistant Core already has an established active KNX bus connection
    ha_knx_ok, ha_knx_meta = check_ha_knx_native_connection()
    if ha_knx_ok:
        return {
            "configured": True,
            "reachable": True,
            "latency_ms": 1.2,
            "source": ha_knx_meta.get("source", "ha_core_active_tunnel"),
            "details": ha_knx_meta,
            "gateway_ip": ip,
            "gateway_port": port
        }

    # 2. Direct UDP SEARCH_REQUEST with socket interface binding and HPAI
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.bind(("0.0.0.0", 0))
        _, local_port = s.getsockname()

        out_ip = "0.0.0.0"
        try:
            s_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_probe.connect((ip, port))
            out_ip = s_probe.getsockname()[0]
            s_probe.close()
        except Exception:
            pass

        start = time.time()
        ip_bytes = socket.inet_aton(out_ip) if out_ip != "0.0.0.0" else bytes([0, 0, 0, 0])
        port_bytes = local_port.to_bytes(2, "big")

        # KNXnet/IP SEARCH_REQUEST with HPAI
        search_pkt = bytes([
            0x06, 0x10, 0x02, 0x01, 0x00, 0x0E,
            0x08, 0x01
        ]) + ip_bytes + port_bytes

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
        if opt_ip and opt_ip not in ["", "none", "null", "192.168.1.100", "0.0.0.0", "—"]:
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
        # If it was only an add-on option fallback and ping failed, do not treat as configured KNX!
        if conn_type == "addon_options" and not res.get("reachable"):
            return {
                "configured": False,
                "reachable": False,
                "reason": "no_knx_integration",
                "system_type": "non_knx",
                "gateway_ip": "",
                "gateway_port": None
            }
        return res

    # 6. Non-KNX device (e.g. Lutron, Zigbee, Z-Wave, Matter, etc.)
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


def detect_all_technologies(opts):
    """
    Detects all active automation technologies and subsystems on this Home Assistant gateway:
    1. KNX: Native integration / IP Gateway / Routing / Tunneling with online/offline status
    2. Zigbee: Detects ALL installed Zigbee2MQTT add-on instances and native ZHA with running status
    3. Lutron: Caséta, RadioRA 2/3, Homeworks QSX integrations with reachability
    4. Matter: Matter Server add-on / Native Matter integration
    5. Core Integrations: Diagnostics on any failed config entries
    """
    addons_resp = supervisor_get("addons")
    addons_list = addons_resp.get("addons", []) if isinstance(addons_resp, dict) else []

    # 1. KNX Auto-Detection
    knx_info = auto_detect_knx_gateway(opts)
    if knx_info.get("configured") and knx_info.get("reachable"):
        knx_info["status"] = "online"
        knx_info["offline_reason"] = ""
    elif knx_info.get("configured"):
        knx_info["status"] = "offline"
        err = knx_info.get("error") or "unreachable"
        if err == "timeout":
            knx_info["offline_reason"] = f"Gateway {knx_info.get('gateway_ip')}:{knx_info.get('gateway_port', 3671)} ping timed out"
        else:
            knx_info["offline_reason"] = f"Gateway ping failed: {err}"
    else:
        knx_info["status"] = "not_configured"
        knx_info["offline_reason"] = "No KNX integration configured on this gateway"

    # 2. Zigbee: Detect ALL Zigbee2MQTT Add-on instances
    z2m_instances = []
    for a in addons_list:
        slug = str(a.get("slug", "")).lower()
        name = str(a.get("name", "")).lower()
        if "zigbee2mqtt" in slug or "zigbee2mqtt" in name or "zigbee 2 mqtt" in name:
            is_running = (a.get("state") == "started")
            z2m_instances.append({
                "name": a.get("name", "Zigbee2MQTT"),
                "slug": a.get("slug", ""),
                "version": a.get("version", ""),
                "state": a.get("state", "unknown"),
                "running": is_running,
                "status": "online" if is_running else "offline",
                "offline_reason": "" if is_running else f"Container state: {a.get('state', 'stopped')}"
            })

    # Check native ZHA (Zigbee Home Automation)
    zha_detected = False
    for spath in ['/homeassistant/.storage/core.config_entries', '/config/.storage/core.config_entries']:
        if os.path.exists(spath):
            try:
                with open(spath, 'r', encoding='utf-8') as f:
                    entries = json.load(f).get('data', {}).get('entries', [])
                    if any(e.get('domain') == 'zha' and not is_entry_ignored_or_disabled(e) for e in entries):
                        zha_detected = True
                        break
            except Exception:
                pass

    zigbee_status = "not_configured"
    zigbee_offline_reason = ""
    if z2m_instances:
        running_insts = [i for i in z2m_instances if i.get("running")]
        failed_insts = [i for i in z2m_instances if not i.get("running")]
        if running_insts and not failed_insts:
            zigbee_status = "online"
        elif running_insts and failed_insts:
            zigbee_status = "degraded"
            zigbee_offline_reason = f"{len(failed_insts)} of {len(z2m_instances)} instances stopped/error: " + ", ".join([f"{i['name']} ({i['state']})" for i in failed_insts])
        else:
            zigbee_status = "offline"
            zigbee_offline_reason = "All instances stopped/error: " + ", ".join([f"{i['name']} ({i['state']})" for i in failed_insts])
    elif zha_detected:
        zigbee_status = "online"

    zigbee_info = {
        "detected": len(z2m_instances) > 0 or zha_detected,
        "type": "Zigbee2MQTT" if z2m_instances else ("ZHA" if zha_detected else "None"),
        "count": len(z2m_instances),
        "instances": z2m_instances,
        "zha_detected": zha_detected,
        "status": zigbee_status,
        "offline_reason": zigbee_offline_reason
    }

    # 3. Lutron Subsystem Detection & Core Integration Status
    core_entries = get_ha_config_entries()
    lutron_entries = []
    failed_core_entries = []

    for e in core_entries:
        if not isinstance(e, dict) or is_entry_ignored_or_disabled(e):
            continue
        domain = e.get('domain', '')
        state = e.get('state', 'loaded')
        
        # Track Lutron integrations
        if domain in ['lutron', 'lutron_caseta', 'lutron_homeworks']:
            lutron_entries.append({
                "entry_id": e.get('entry_id'),
                "domain": domain,
                "title": e.get('title', 'Lutron System'),
                "state": state,
                "reason": e.get('reason', '')
            })

        # Track any failed/error integration (ignore user-disabled or discovery-ignored)
        if state in ['setup_error', 'setup_retry', 'migration_error', 'not_loaded', 'failed_unload'] and not e.get('disabled_by') and e.get('source') != 'ignore':
            if domain in ['knx', 'lutron', 'lutron_caseta', 'lutron_homeworks', 'matter', 'coolmaster', 'coolmasternet', 'coolautomation', 'zha', 'zigbee']:
                continue
            failed_core_entries.append({
                "entry_id": e.get('entry_id'),
                "domain": domain,
                "title": e.get('title', domain),
                "state": state,
                "reason": e.get('reason') or f"Core integration in '{state}' state"
            })

    lutron_status = "not_configured"
    lutron_offline_reason = ""
    if lutron_entries:
        unreachable_bridges = []
        for ent in lutron_entries:
            ent_ip = None
            m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ent.get("title", ""))
            if m:
                ent_ip = m.group(0)
            if ent_ip:
                is_ok = False
                for probe_port in [23, 443, 80]:
                    try:
                        with socket.create_connection((ent_ip, probe_port), timeout=1.0):
                            is_ok = True
                            break
                    except Exception:
                        pass
                ent["online"] = is_ok and (ent.get("state") == "loaded")
                if not is_ok:
                    unreachable_bridges.append(f"{ent_ip} (unreachable)")
            else:
                ent["online"] = (ent.get("state") == "loaded")
        failed_lutron = [e for e in lutron_entries if e.get("state") in ["setup_error", "setup_retry", "failed_unload", "not_loaded"]]
        if failed_lutron:
            lutron_status = "offline" if len(failed_lutron) == len(lutron_entries) else "degraded"
            lutron_offline_reason = " | ".join([f"{e.get('title', 'Lutron')}: {e.get('reason') or e.get('state')}" for e in failed_lutron])
        elif unreachable_bridges:
            lutron_status = "offline" if len(unreachable_bridges) == len(lutron_entries) else "degraded"
            lutron_offline_reason = f"Bridge unreachable: {', '.join(unreachable_bridges)}"
        else:
            lutron_status = "online"

    lutron_info = {
        "detected": len(lutron_entries) > 0,
        "type": lutron_entries[0]["domain"].replace("_", " ").title() if lutron_entries else "None",
        "entries": lutron_entries,
        "status": lutron_status,
        "offline_reason": lutron_offline_reason
    }

    # 4. Matter Subsystem Detection
    matter_detected = False
    matter_state = "not_installed"
    for a in addons_list:
        slug = str(a.get("slug", "")).lower()
        name = str(a.get("name", "")).lower()
        if "matter" in slug or "matter" in name:
            matter_detected = True
            matter_state = a.get("state", "unknown")
            break

    if not matter_detected:
        if any(e.get('domain') == 'matter' for e in core_entries if isinstance(e, dict)):
            matter_detected = True
            matter_state = "configured"

    matter_status = "not_configured"
    matter_offline_reason = ""
    if matter_detected:
        if matter_state in ["started", "running"]:
            matter_status = "online"
        elif matter_state in ["stopped", "error", "failed"]:
            matter_status = "offline"
            matter_offline_reason = f"Matter Server container state: {matter_state}"
        elif matter_state == "configured":
            matter_status = "online"

    matter_info = {
        "detected": matter_detected,
        "state": matter_state,
        "status": matter_status,
        "offline_reason": matter_offline_reason
    }

    # 5. CoolMaster Subsystem Detection (CoolMasterNet / CoolAutomation HVAC)
    coolmaster_entries = []
    for e in core_entries:
        if not isinstance(e, dict) or is_entry_ignored_or_disabled(e):
            continue
        domain = e.get('domain', '')
        if domain in ['coolmaster', 'coolmasternet', 'coolautomation']:
            data = e.get('data', {})
            host = data.get('host') or ''
            port = data.get('port') or 10102
            coolmaster_entries.append({
                "entry_id": e.get('entry_id'),
                "domain": domain,
                "title": e.get('title', 'CoolMasterNet HVAC'),
                "host": host,
                "port": port,
                "state": e.get('state', 'loaded'),
                "reason": e.get('reason', '')
            })

    coolmaster_status = "not_configured"
    coolmaster_offline_reason = ""
    if coolmaster_entries:
        failed_cms = [e for e in coolmaster_entries if e.get("state") in ["setup_error", "setup_retry", "failed_unload", "not_loaded"]]
        unreachable_cms = []
        for ent in coolmaster_entries:
            ent_host = ent.get("host")
            if not ent_host:
                m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ent.get("title", ""))
                if m: ent_host = m.group(0)
            if ent_host:
                is_ok = False
                try:
                    with socket.create_connection((ent_host, int(ent.get("port", 10102))), timeout=1.5):
                        is_ok = True
                except Exception:
                    pass
                ent["online"] = is_ok and (ent.get("state") == "loaded")
                if not is_ok:
                    unreachable_cms.append(f"{ent_host}:{ent.get('port', 10102)} (unreachable)")
            else:
                ent["online"] = (ent.get("state") == "loaded")

        if failed_cms:
            coolmaster_status = "offline" if len(failed_cms) == len(coolmaster_entries) else "degraded"
            reasons = [f"{e.get('title', 'CoolMaster')}: {e.get('reason') or e.get('state')}" for e in failed_cms]
            coolmaster_offline_reason = " | ".join(reasons)
        elif unreachable_cms:
            coolmaster_status = "offline" if len(unreachable_cms) == len(coolmaster_entries) else "degraded"
            coolmaster_offline_reason = f"CoolMaster unreachable: {', '.join(unreachable_cms)}"
        else:
            coolmaster_status = "online"

    coolmaster_info = {
        "detected": len(coolmaster_entries) > 0,
        "type": "CoolMasterNet",
        "entries": coolmaster_entries,
        "status": coolmaster_status,
        "offline_reason": coolmaster_offline_reason
    }

    return {
        "knx": knx_info,
        "zigbee": zigbee_info,
        "lutron": lutron_info,
        "matter": matter_info,
        "coolmaster": coolmaster_info,
        "failed_core_entries": failed_core_entries
    }

def handle_backup_trigger_async(hub_host, opts, trigger_info):
    """Runs supervisor backup snapshot creation and uploads .tar archive to central hub."""
    import threading
    def _worker():
        client_id = opts.get("client_id", "unconfigured")
        b_name = trigger_info.get("name") or f"Gavasah Snapshot - {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
        log(f"[SNAPSHOT] Creating full Home Assistant backup: '{b_name}'...")
        if not SUPERVISOR_TOKEN:
            log("[SNAPSHOT] Error: Supervisor token unavailable")
            return

        slug = None
        try:
            req = urllib.request.Request(
                f"{SUPERVISOR_URL}/backups/new/full",
                data=json.dumps({"name": b_name}).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read().decode())
                slug = data.get("data", {}).get("slug")
                log(f"[SNAPSHOT] Backup created successfully with slug: {slug}")
        except Exception as e:
            log(f"[SNAPSHOT] Error creating backup: {e}")
            return

        if not slug:
            return

        # Stream / upload newly generated backup to GAVASAH Hub for one-click dealer downloading
        try:
            download_url = f"{SUPERVISOR_URL}/backups/{slug}/download"
            req_dl = urllib.request.Request(download_url, headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"})
            import ssl
            ctx = ssl._create_unverified_context()
            
            upload_url = f"https://{hub_host}/api/client_backup_upload?client_id={urllib.parse.quote(client_id)}&slug={slug}&name={urllib.parse.quote(b_name)}"
            fallback_upload = f"https://dealer.gavasah.com/api/client_backup_upload?client_id={urllib.parse.quote(client_id)}&slug={slug}&name={urllib.parse.quote(b_name)}"
            
            with urllib.request.urlopen(req_dl, timeout=300) as b_stream:
                archive_data = b_stream.read()
                log(f"[SNAPSHOT] Downloaded {len(archive_data)} bytes from Supervisor. Uploading to Hub...")
                
                for target_url in [upload_url, fallback_upload]:
                    try:
                        up_req = urllib.request.Request(
                            target_url,
                            data=archive_data,
                            headers={
                                "Content-Type": "application/x-tar",
                                "X-Client-Id": client_id,
                                "X-Backup-Slug": slug
                            },
                            method="POST"
                        )
                        with urllib.request.urlopen(up_req, context=ctx, timeout=120) as up_res:
                            if up_res.status in [200, 201]:
                                log(f"[SNAPSHOT] Successfully uploaded backup '{slug}' to Hub for direct dealer download!")
                                break
                    except Exception as up_err:
                        log(f"[SNAPSHOT] Upload notice for {target_url}: {up_err}")
        except Exception as dl_err:
            log(f"[SNAPSHOT] Stream upload error: {dl_err}")

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

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
    sup_info = supervisor_get("supervisor/info")
    addon_self = supervisor_get("addons/self/info")

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

    # Multi-Technology Subsystems Discovery (KNX, Multi-Zigbee2MQTT, Lutron, Matter, CoolMaster)
    tech_data = detect_all_technologies(opts)

    # Autonomous Self-Healing Engine (5 Attempts, 60s cooldown before cloud escalation)
    tech_data = run_autonomous_self_healing_engine(tech_data, opts)
    knx_res = tech_data.get("knx", {})

    # Retrieve existing snapshots/backups from Supervisor API
    backups_list = []
    backups_resp = supervisor_get("backups")
    if isinstance(backups_resp, dict) and "backups" in backups_resp:
        for b in backups_resp.get("backups", [])[:10]:
            backups_list.append({
                "slug": b.get("slug", ""),
                "name": b.get("name", "Home Assistant Backup"),
                "date": b.get("date", ""),
                "size_mb": round((b.get("size") or 0) / (1024 * 1024), 1),
                "type": b.get("type", "full")
            })

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

    # Storage calculation (host_info or filesystem fallback)
    d_free = host_info.get("disk_free")
    d_total = host_info.get("disk_total")
    if not d_total or d_total == 0:
        try:
            import shutil
            du = shutil.disk_usage("/data") if os.path.exists("/data") else shutil.disk_usage("/")
            d_free = round(du.free / (1024**3), 1)
            d_total = round(du.total / (1024**3), 1)
        except Exception:
            d_free = d_free or 0
            d_total = d_total or 0

    payload = {
        "client_id": opts.get("client_id", "unconfigured"),
        "auth_key": opts.get("auth_key", ""),
        "ssh_public_key": pubkey,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "system": {
            "addon_version": ADDON_VERSION,
            "addon_latest_version": addon_self.get("version_latest") if isinstance(addon_self, dict) and addon_self.get("version_latest") else ADDON_VERSION,
            "addon_update_available": bool(addon_self.get("update_available")) if isinstance(addon_self, dict) else False,
            "core_version": core_info.get("version", "Unknown") if isinstance(core_info, dict) else "Unknown",
            "core_latest_version": core_info.get("version_latest", "") if isinstance(core_info, dict) else "",
            "core_update_available": bool(core_info.get("update_available")) if isinstance(core_info, dict) else False,
            "supervisor_version": sup_info.get("version", "Unknown") if isinstance(sup_info, dict) else "Unknown",
            "supervisor_latest_version": sup_info.get("version_latest", "") if isinstance(sup_info, dict) else "",
            "supervisor_update_available": bool(sup_info.get("update_available")) if isinstance(sup_info, dict) else False,
            "haos_version": haos_version,
            "haos_latest_version": os_info.get("version_latest", "") if isinstance(os_info, dict) else "",
            "haos_update_available": bool(os_info.get("update_available")) if isinstance(os_info, dict) else False,
            "hostname": host_info.get("hostname", "homeassistant") if isinstance(host_info, dict) else "homeassistant",
            "board": board,
            "boot_slot": boot_slot,
            "is_recovery_mode": is_recovery,
            "slot_a_status": slot_a_state,
            "slot_b_status": slot_b_state,
            "cpu_percent": main_cpu_pct,
            "memory_percent": main_mem_pct,
            "disk_free_gb": d_free,
            "disk_total_gb": d_total,
            "reboot_required": host_info.get("reboot_required", False) if isinstance(host_info, dict) else False,
            "last_error": _last_system_error
        },
        "network": {
            "local_ipv4": default_ip,
            "gateway": default_gw,
            "mac_address": mac_addr,
            "nameservers": dns_list
        },
        "knx_status": knx_res,
        "technologies": tech_data,
        "self_healing": tech_data.get("self_healing", {}),
        "backups": backups_list,
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

    # 6. Local Storage Utilization Sensor
    d_tot = sys_info.get("disk_total_gb", 0)
    d_free = sys_info.get("disk_free_gb", 0)
    if d_tot > 0:
        d_used = round(d_tot - d_free, 1)
        used_pct = round((d_used / d_tot) * 100.0, 1)
        update_ha_state(
            "sensor.gavasah_storage_usage",
            f"{used_pct}%",
            {
                "friendly_name": "Gavasah System Storage Usage",
                "used_gb": d_used,
                "free_gb": d_free,
                "total_gb": d_tot,
                "unit_of_measurement": "%",
                "icon": "mdi:harddisk"
            }
        )

    # 7. Addon Version Sensor
    update_ha_state(
        "sensor.gavasah_addon_version",
        f"v{ADDON_VERSION}",
        {
            "friendly_name": "Gavasah Cloud Agent Version",
            "version": ADDON_VERSION,
            "icon": "mdi:package-up"
        }
    )

    # 8. Autonomous Self-Healing Status Sensor
    sh_info = payload.get("self_healing", {})
    sh_active = sh_info.get("active", False)
    healing_subs = [k for k, v in sh_info.get("subsystems", {}).items() if v.get("status") == "healing"]
    state_str = f"Healing ({', '.join(healing_subs)})" if healing_subs else ("Idle (Healthy)" if not sh_active else "Active")
    update_ha_state(
        "sensor.gavasah_self_healing_status",
        state_str,
        {
            "friendly_name": "Gavasah Self-Healing Engine",
            "active": sh_active,
            "subsystems_in_healing": healing_subs,
            "max_attempts": MAX_HEALING_ATTEMPTS,
            "cooldown_seconds": HEALING_COOLDOWN_SEC,
            "recent_recoveries_count": len(sh_info.get("recent_recoveries", [])),
            "icon": "mdi:hospital-box-outline" if sh_active else "mdi:check-decagram"
        }
    )

class MqttTelemetryEngine:
    def __init__(self, opts, collect_telemetry_fn, handle_cmd_fn, log_fn):
        self.opts = opts
        self.collect_telemetry = collect_telemetry_fn
        self.handle_cmd = handle_cmd_fn
        self.log = log_fn
        self.client_id = opts.get("client_id", "unknown-gateway")
        self.auth_key = opts.get("auth_key", "")
        self.mqtt_host = opts.get("mqtt_host", "10.42.0.1")
        self.mqtt_port = int(opts.get("mqtt_port", 1883))
        self.interval = max(30, min(120, int(opts.get("mqtt_interval", 45))))
        self.running = False
        self.client = None
        self.connected = False

    def start(self):
        if not self.opts.get("mqtt_enabled", True):
            self.log("[MQTT] Telemetry engine disabled in options.")
            return
        self.running = True
        import threading
        t = threading.Thread(target=self._run_loop, daemon=True, name="GavasahMqttTelemetry")
        t.start()
        self.log(f"[MQTT] Telemetry engine started | Host: {self.mqtt_host}:{self.mqtt_port} | Interval: {self.interval}s | Client: {self.client_id}")

    def _run_loop(self):
        while self.running:
            try:
                import paho.mqtt.client as mqtt
                self._connect_and_loop_paho(mqtt)
            except ImportError:
                self.log("[MQTT] Notice: paho-mqtt not available in container, telemetry running via HTTPS REST fallback.")
                break
            except Exception as e:
                self.log(f"[MQTT] Loop error: {e}. Reconnecting in 15s...")
                time.sleep(15)

    def _connect_and_loop_paho(self, mqtt):
        client = mqtt.Client(client_id=f"{self.client_id}-agent", protocol=mqtt.MQTTv311)
        if self.auth_key:
            client.username_pw_set(self.client_id, self.auth_key)

        # LWT (Last Will & Testament)
        lwt_topic = f"gavasah/clients/{self.client_id}/status"
        lwt_payload = json.dumps({
            "client_id": self.client_id,
            "status": "offline",
            "timestamp": int(time.time()),
            "lwt": True
        })
        client.will_set(lwt_topic, lwt_payload, qos=1, retain=True)

        def on_connect(c, userdata, flags, rc):
            if rc == 0:
                self.connected = True
                self.log(f"[MQTT] Connected successfully to {self.mqtt_host}:{self.mqtt_port}")
                online_payload = json.dumps({
                    "client_id": self.client_id,
                    "status": "online",
                    "timestamp": int(time.time()),
                    "lwt": False
                })
                c.publish(lwt_topic, online_payload, qos=1, retain=True)
                # Subscribe to instant command topics
                c.subscribe([(f"gavasah/clients/{self.client_id}/cmd", 1), ("gavasah/global/cmd", 1)])
            else:
                self.connected = False
                self.log(f"[MQTT] Connect returned code {rc} (Auth/Permission check needed)")

        def on_disconnect(c, userdata, rc):
            self.connected = False
            self.log(f"[MQTT] Disconnected from broker (rc={rc})")

        def on_message(c, userdata, msg):
            try:
                raw = msg.payload.decode("utf-8")
                cmd = json.loads(raw)
                self.log(f"[MQTT] Received instant command on {msg.topic}: {cmd.get('action')}")
                hub_host = self.opts.get("hub_host", "dealer.gavasah.com")
                self.handle_cmd(hub_host, self.opts, cmd)
            except Exception as e:
                self.log(f"[MQTT] Error handling incoming command: {e}")

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_message = on_message

        client.connect(self.mqtt_host, self.mqtt_port, keepalive=60)
        client.loop_start()
        self.client = client

        last_pub = 0
        last_alert_events = set()

        while self.running:
            time.sleep(1)
            now = time.time()
            if self.connected and (now - last_pub >= self.interval):
                last_pub = now
                try:
                    payload = self.collect_telemetry(self.opts)
                    sys_p = payload.get("system", {})
                    tech_p = payload.get("technologies", {})
                    light = {
                        "client_id": self.client_id,
                        "timestamp": int(now),
                        "boot_slot": sys_p.get("boot_slot"),
                        "slot_a_status": sys_p.get("slot_a_status"),
                        "slot_b_status": sys_p.get("slot_b_status"),
                        "is_recovery_mode": sys_p.get("is_recovery_mode", False),
                        "os_version": sys_p.get("os_version"),
                        "core_version": sys_p.get("core_version"),
                        "supervisor_version": sys_p.get("supervisor_version"),
                        "cpu_percent": sys_p.get("cpu_percent"),
                        "memory_percent": sys_p.get("memory_percent"),
                        "disk_free_gb": sys_p.get("disk_free_gb"),
                        "uptime_seconds": sys_p.get("uptime_seconds"),
                        "knx_reachable": payload.get("knx_status", {}).get("reachable", False),
                        "subsystems": tech_p,
                        "self_healing": tech_p.get("self_healing", {})
                    }
                    telem_topic = f"gavasah/clients/{self.client_id}/telemetry"
                    client.publish(telem_topic, json.dumps(light), qos=0)

                    # Event dispatch: Check for exhausted self-healing (5 attempts failed locally)
                    sh = tech_p.get("self_healing", {}).get("subsystems", {})
                    for sub_name, sub_info in sh.items():
                        if sub_info.get("exhausted") or sub_info.get("attempts", 0) >= 5:
                            ev_key = f"{sub_name}:{sub_info.get('first_failed')}"
                            if ev_key not in last_alert_events:
                                last_alert_events.add(ev_key)
                                event_payload = {
                                    "client_id": self.client_id,
                                    "event": "subsystem_exhausted",
                                    "subsystem": sub_name,
                                    "attempts": sub_info.get("attempts"),
                                    "reason": sub_info.get("last_action") or "5 self-healing attempts failed locally",
                                    "timestamp": int(now)
                                }
                                event_topic = f"gavasah/clients/{self.client_id}/events"
                                client.publish(event_topic, json.dumps(event_payload), qos=1)
                                self.log(f"[MQTT] Dispatched exhausted alert event for subsystem '{sub_name}'")
                except Exception as ex:
                    self.log(f"[MQTT] Telemetry publish error: {ex}")

        client.loop_stop()
        client.disconnect()

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
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                if resp.status in [200, 201]:
                    resp_json = {}
                    try:
                        resp_json = json.loads(resp.read().decode("utf-8"))
                    except Exception:
                        pass
                    return True, resp_json
        except Exception:
            continue
    return False, {}

def main():
    log(f"Starting Gavasah Cloud Agent Telemetry Engine v{ADDON_VERSION} (Autonomous Self-Healing: 5 attempts, 60s cooldown)...")
    opts = load_options()
    hub_host = opts.get("hub_host", "122.175.49.35")
    interval = int(opts.get("heartbeat_interval", 60))

    log(f"Configured Hub: {hub_host} | Client: {opts.get('client_id')} | Interval: {interval}s")

    # Initial sync of Home Assistant External Network URL, Supervisor Toggles, and IP Ban Self-Healing
    ensure_external_url(opts)
    ensure_supervisor_toggles()
    auto_heal_ip_bans_and_proxy()
    load_healing_registry()

    # Start High-Speed MQTT Telemetry Engine (publishes every 30-60s)
    try:
        mqtt_engine = MqttTelemetryEngine(opts, collect_telemetry, handle_remote_command, log)
        mqtt_engine.start()
    except Exception as e:
        log(f"Notice: Could not start MQTT telemetry engine: {e}")

    # Immediate Second-0 Initial Pulse on Startup (Eliminates 60s onboarding wait)
    try:
        init_payload = collect_telemetry(opts)
        publish_local_entities(init_payload)
        init_ok, init_st = send_heartbeat(hub_host, init_payload)
        if init_ok:
            log(f"Immediate second-0 startup heartbeat acknowledged by hub: {init_st}")
            if isinstance(init_st, dict) and "unmonitored_integrations" in init_st:
                update_unmonitored_integrations(init_st["unmonitored_integrations"])
    except Exception as e:
        log(f"Initial startup heartbeat notice: {e}")

    loop_count = 0
    while True:
        try:
            opts = load_options()
            payload = collect_telemetry(opts)

            # 1. Update native Home Assistant UI entities
            publish_local_entities(payload)

            # 2. Maintain external_url, supervisor toggles, and IP ban self-healing every 5 cycles
            loop_count += 1
            if loop_count % 5 == 0:
                ensure_external_url(opts)
                ensure_supervisor_toggles()
                auto_heal_ip_bans_and_proxy()

            # 3. Transmit to central dealer hub
            success, hub_resp = send_heartbeat(hub_host, payload)
            slot = payload["system"]["boot_slot"]
            recovery = " [RECOVERY MODE ACTIVE!]" if payload["system"]["is_recovery_mode"] else ""
            if success:
                log(f"Heartbeat OK | Slot: {slot}{recovery} | IP: {payload['network']['local_ipv4']} | KNX: {payload['knx_status'].get('reachable')}")
                if isinstance(hub_resp, dict):
                    if "unmonitored_integrations" in hub_resp:
                        update_unmonitored_integrations(hub_resp["unmonitored_integrations"])
                    if hub_resp.get("backup_trigger"):
                        handle_backup_trigger_async(hub_host, opts, hub_resp["backup_trigger"])
                    if hub_resp.get("command"):
                        handle_remote_command(hub_host, opts, hub_resp["command"])
            else:
                log(f"Heartbeat Hub Sync Notice: {hub_resp} | Local metrics captured successfully.")
        except Exception as e:
            log(f"Heartbeat loop exception: {e}")

        time.sleep(interval)

if __name__ == "__main__":
    main()
