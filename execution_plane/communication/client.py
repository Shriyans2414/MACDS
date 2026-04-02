"""
MACDS Execution Plane communication client.
Sends attack logs to the Control Plane and polls for enforcement actions.

IMPORTANT: CONTROL_PLANE_URL must be the Mac's LAN IP, not localhost.
Set it before running: sudo CONTROL_PLANE_URL=http://<MAC_IP>:8000 python3 ...
"""

import os
import time
import subprocess
import threading

import requests

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000")
_MAX_RETRIES = 3
_RETRY_DELAY = 0.5


def send_log(attack_type: str, src_ip: str, packet_rate: float = 0.0,
             confidence: str = "MEDIUM", detail: str = ""):
    """Send an attack event to the Control Plane with retry logic."""
    url = f"{CONTROL_PLANE_URL}/api/logs"
    payload = {
        "timestamp": time.time(),
        "attack_type": attack_type,
        "source_ip": src_ip,
        "packet_rate": packet_rate,
        "confidence": confidence,
        "detail": detail[:500]
    }
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            resp = requests.post(url, json=payload, timeout=2)
            resp.raise_for_status()
            print(f"[CLIENT] Log sent: {attack_type} from {src_ip}")
            return
        except Exception as e:
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)
            else:
                print(f"[CLIENT ERROR] Failed after {_MAX_RETRIES} attempts: {e}")


def execute_action(action_data: dict):
    """Execute an iptables rule based on the control plane's decision."""
    action = action_data.get("action")
    target_ip = action_data.get("target_ip")

    if not target_ip:
        return

    if action == "block_ip":
        print(f"[CLIENT] Blocking {target_ip}")
        res = subprocess.run( # FIX: capture subprocess result
            ["iptables", "-I", "INPUT", "-s", target_ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, # FIX: capture stderr instead of devnull
        )
        if res.returncode != 0: # FIX: check for failure
            print(f"[CLIENT ERROR] iptables failed (not root?): {res.stderr.decode().strip()}") # FIX: print error
    elif action in ("unblock_ip", "recover_ip"):
        print(f"[CLIENT] Unblocking {target_ip}")
        res = subprocess.run( # FIX: capture subprocess result
            ["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, # FIX: capture stderr instead of devnull
        )
        if res.returncode != 0: # FIX: check for failure
            print(f"[CLIENT ERROR] iptables failed (not root?): {res.stderr.decode().strip()}") # FIX: print error
    elif action == "raise_alert":
        print(f"[CLIENT] ALERT raised for {target_ip} — no iptables change")


def poll_actions():
    """Poll Control Plane for enforcement actions every second."""
    url = f"{CONTROL_PLANE_URL}/api/action"
    print(f"[*] Polling {url} for actions")
    while True:
        try:
            resp = requests.get(url, timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                if data and data.get("action") not in (None, "none", "do_nothing"):
                    execute_action(data)
        except Exception:
            pass
        time.sleep(1.0)


def start_polling():
    """Start the polling loop in a background daemon thread."""
    threading.Thread(target=poll_actions, daemon=True).start()
