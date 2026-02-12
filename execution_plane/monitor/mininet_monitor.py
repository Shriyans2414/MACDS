import time
import subprocess
import json
from collections import defaultdict

OUTPUT_FILE = "/tmp/mininet_attack_event.json"

PORTSCAN_THRESHOLD = 5
TIME_WINDOW = 20


def start_tcpdump():
    return subprocess.Popen(
        [
            "tcpdump",
            "-i", "any",          # IMPORTANT: capture across namespaces
            "-l",
            "-n",
            "tcp[tcpflags] & tcp-syn != 0"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )


def monitor():
    print("[*] Mininet IDS monitor started")

    port_history = defaultdict(list)
    proc = start_tcpdump()

    while True:
        line = proc.stdout.readline()
        if not line:
            continue

        now = time.time()

        # Example:
        # IP 10.0.0.3.45123 > 10.0.0.4.80: Flags [S]
        try:
            if "IP" not in line or ">" not in line:
                continue

            src = line.split()[1]
            dst = line.split()[3]

            src_ip = src.rsplit(".", 1)[0]
            dst_port = int(dst.rstrip(":").rsplit(".", 1)[1])
        except Exception:
            continue

        port_history[src_ip].append((dst_port, now))

        # Sliding window
        port_history[src_ip] = [
            (p, t) for p, t in port_history[src_ip]
            if now - t <= TIME_WINDOW
        ]

        unique_ports = set(p for p, _ in port_history[src_ip])

        if len(unique_ports) >= PORTSCAN_THRESHOLD:
            event = {
                "timestamp": time.time(),
                "attack": "portscan",
                "attacker_ip": src_ip,
                "unique_ports": len(unique_ports),
            }
            print("[ATTACK DETECTED]", event)

            with open(OUTPUT_FILE, "w") as f:
                json.dump(event, f)

            port_history[src_ip].clear()


if __name__ == "__main__":
    monitor()
