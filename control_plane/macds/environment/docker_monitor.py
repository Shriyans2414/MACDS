import json
import os
import time

# Path to the shared Mininet → Mac → MACDS bridge file
EVENT_FILE = os.path.expanduser("~/mininet_bridge/mininet_attack_event.json")

# Track last processed modification time
_last_processed_time = 0


def detect_attack():
    global _last_processed_time

    if not os.path.exists(EVENT_FILE):
        return None

    try:
        mtime = os.path.getmtime(EVENT_FILE)
        if mtime <= _last_processed_time:
            return None

        _last_processed_time = mtime

        with open(EVENT_FILE, "r") as f:
            event = json.load(f)

        # 🔥 Match IDS JSON format
        attack_type = event.get("attack_type")
        attacker_ip = event.get("source_ip")

        if not attack_type or attack_type == "none":
            return None

        return {
            "attack": attack_type,
            "source_ip": attacker_ip,
            "rate": 0.0,  # Not used currently
        }

    except Exception:
        return None
