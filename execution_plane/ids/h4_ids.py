#!/usr/bin/env python3

import time
import threading
import subprocess
import os
import csv
import sys
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, ICMP, UDP, rdpcap

# =========================
# CONFIGURATION
# =========================

INTERFACE = "h4-eth0"

SHORT_WINDOW = 2.0
LONG_WINDOW  = 30.0
CHECK_INTERVAL = 1.0

ICMP_PPS_THRESHOLD = 300
TCP_SYN_PPS_THRESHOLD = 400
UDP_PPS_THRESHOLD = 500

PORTSCAN_THRESHOLD_FAST = 4
PORTSCAN_THRESHOLD_SLOW = 4
HORIZONTAL_SCAN_THRESHOLD = 3

LOG_DIR = "logs"
LOG_FILE = f"{LOG_DIR}/ids_events.csv"

# =========================
# SHARED STATE
# =========================

packet_buffer = deque()
buffer_lock = threading.Lock()

attack_state = {
    "ddos": False,
    "syn_flood": False,
    "udp_flood": False,
    "portscan": {},
    "horizontal_scan": {}
}

OFFLINE_MODE = False   # auto-enabled for PCAP mode

# =========================
# LOGGING
# =========================

def init_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow([
                "timestamp",
                "event_type",
                "attack_type",
                "src_ip"
            ])

def log_event(event, attack, src):
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([
            time.time(),
            event,
            attack,
            src
        ])

# =========================
# FIREWALL ACTIONS
# =========================

def block_ip(ip, attack):
    if OFFLINE_MODE:
        log_event("DEFENSE_APPLIED", attack, ip)
        return

    subprocess.run(
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[DEFENSE] Blocked IP {ip}")
    log_event("DEFENSE_APPLIED", attack, ip)

def unblock_ip(ip, attack):
    if OFFLINE_MODE:
        log_event("DEFENSE_REMOVED", attack, ip)
        return

    subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[RECOVERY] Unblocked IP {ip}")
    log_event("DEFENSE_REMOVED", attack, ip)

# =========================
# PACKET CAPTURE (LIVE)
# =========================

def on_packet(pkt):
    if IP in pkt:
        with buffer_lock:
            packet_buffer.append((time.time(), pkt))

# =========================
# HELPER: CURRENT TIME
# =========================

def current_time(packets):
    return max(ts for ts, _ in packets) if packets else 0

# =========================
# ATTACK DETECTION
# =========================

def detect_ddos(packets):
    now = current_time(packets)
    icmp_pps = sum(
        1 for ts, p in packets
        if ICMP in p and now - ts <= SHORT_WINDOW
    )
    attacker = "10.0.0.3"

    if icmp_pps >= ICMP_PPS_THRESHOLD and not attack_state["ddos"]:
        attack_state["ddos"] = True
        print("[ATTACK START] DDOS detected")
        log_event("ATTACK_START", "DDOS", attacker)
        log_event("ATTACK_DETECTED", "DDOS", attacker)
        block_ip(attacker, "DDOS")

    elif icmp_pps < ICMP_PPS_THRESHOLD and attack_state["ddos"]:
        attack_state["ddos"] = False
        print("[ATTACK END] DDOS ended")
        log_event("ATTACK_END", "DDOS", attacker)
        unblock_ip(attacker, "DDOS")

def detect_syn_flood(packets):
    now = current_time(packets)
    syn_counts = defaultdict(int)

    for ts, pkt in packets:
        if TCP in pkt and pkt[TCP].flags & 0x02 and now - ts <= 1.0:
            syn_counts[pkt[IP].src] += 1

    for src, count in syn_counts.items():
        if count >= TCP_SYN_PPS_THRESHOLD and not attack_state["syn_flood"]:
            attack_state["syn_flood"] = True
            print("[ATTACK START] TCP SYN FLOOD detected")
            log_event("ATTACK_START", "SYN_FLOOD", src)
            log_event("ATTACK_DETECTED", "SYN_FLOOD", src)
            block_ip(src, "SYN_FLOOD")

        elif count < TCP_SYN_PPS_THRESHOLD and attack_state["syn_flood"]:
            attack_state["syn_flood"] = False
            print("[ATTACK END] TCP SYN FLOOD ended")
            log_event("ATTACK_END", "SYN_FLOOD", src)
            unblock_ip(src, "SYN_FLOOD")

def detect_udp_flood(packets):
    now = current_time(packets)
    udp_counts = defaultdict(int)

    for ts, pkt in packets:
        if UDP in pkt and now - ts <= 1.0:
            udp_counts[pkt[IP].src] += 1

    for src, count in udp_counts.items():
        if count >= UDP_PPS_THRESHOLD and not attack_state["udp_flood"]:
            attack_state["udp_flood"] = True
            print("[ATTACK START] UDP FLOOD detected")
            log_event("ATTACK_START", "UDP_FLOOD", src)
            log_event("ATTACK_DETECTED", "UDP_FLOOD", src)
            block_ip(src, "UDP_FLOOD")

        elif count < UDP_PPS_THRESHOLD and attack_state["udp_flood"]:
            attack_state["udp_flood"] = False
            print("[ATTACK END] UDP FLOOD ended")
            log_event("ATTACK_END", "UDP_FLOOD", src)
            unblock_ip(src, "UDP_FLOOD")

def detect_portscan(packets):
    now = current_time(packets)
    fast_ports = defaultdict(set)
    slow_ports = defaultdict(set)

    for ts, pkt in packets:
        if TCP in pkt and pkt[TCP].flags & 0x02:
            src = pkt[IP].src
            dport = pkt[TCP].dport
            if now - ts <= SHORT_WINDOW:
                fast_ports[src].add(dport)
            if now - ts <= LONG_WINDOW:
                slow_ports[src].add(dport)

    for src in set(fast_ports) | set(slow_ports):
        detected = (
            len(fast_ports[src]) >= PORTSCAN_THRESHOLD_FAST or
            len(slow_ports[src]) >= PORTSCAN_THRESHOLD_SLOW
        )
        prev = attack_state["portscan"].get(src, False)

        if detected and not prev:
            attack_state["portscan"][src] = True
            print(f"[ATTACK START] PORTSCAN from {src}")
            log_event("ATTACK_START", "PORTSCAN", src)
            log_event("ATTACK_DETECTED", "PORTSCAN", src)
            block_ip(src, "PORTSCAN")

        elif not detected and prev:
            attack_state["portscan"][src] = False
            print(f"[ATTACK END] PORTSCAN from {src}")
            log_event("ATTACK_END", "PORTSCAN", src)
            unblock_ip(src, "PORTSCAN")

def detect_horizontal_scan(packets):
    now = current_time(packets)
    port_hits = defaultdict(set)

    for ts, pkt in packets:
        if TCP in pkt and pkt[TCP].flags & 0x02 and now - ts <= LONG_WINDOW:
            port_hits[pkt[IP].src].add(pkt[TCP].dport)

    for src, ports in port_hits.items():
        prev = attack_state["horizontal_scan"].get(src, False)

        if len(ports) >= HORIZONTAL_SCAN_THRESHOLD and not prev:
            attack_state["horizontal_scan"][src] = True
            print(f"[ATTACK START] HORIZONTAL SCAN from {src}")
            log_event("ATTACK_START", "HORIZONTAL_SCAN", src)
            log_event("ATTACK_DETECTED", "HORIZONTAL_SCAN", src)
            block_ip(src, "HORIZONTAL_SCAN")

        elif len(ports) < HORIZONTAL_SCAN_THRESHOLD and prev:
            attack_state["horizontal_scan"][src] = False
            print(f"[ATTACK END] HORIZONTAL SCAN from {src}")
            log_event("ATTACK_END", "HORIZONTAL_SCAN", src)
            unblock_ip(src, "HORIZONTAL_SCAN")

# =========================
# OFFLINE PCAP MODE
# =========================

def process_pcap(pcap_file):
    global OFFLINE_MODE
    OFFLINE_MODE = True

    print("[*] IDS running in OFFLINE PCAP mode")
    print(f"[*] Processing PCAP: {pcap_file}")

    packets = []
    base_time = None

    for pkt in rdpcap(pcap_file):
        if IP in pkt:
            if base_time is None:
                base_time = pkt.time
            packets.append((pkt.time - base_time, pkt))

    detect_ddos(packets)
    detect_syn_flood(packets)
    detect_udp_flood(packets)
    detect_portscan(packets)
    detect_horizontal_scan(packets)

    print("[*] PCAP analysis complete")

# =========================
# LIVE LOOP
# =========================

def detection_loop():
    while True:
        now = time.time()
        with buffer_lock:
            while packet_buffer and now - packet_buffer[0][0] > LONG_WINDOW:
                packet_buffer.popleft()
            packets = list(packet_buffer)

        detect_ddos(packets)
        detect_syn_flood(packets)
        detect_udp_flood(packets)
        detect_portscan(packets)
        detect_horizontal_scan(packets)

        time.sleep(CHECK_INTERVAL)

# =========================
# MAIN
# =========================

def main():
    init_logger()

    if len(sys.argv) == 3 and sys.argv[1] == "--pcap":
        process_pcap(sys.argv[2])
        return

    print("[*] IDS running inside h4 namespace")
    print("[*] Sniffing on interface h4-eth0")
    print("[*] Logging events to logs/ids_events.csv")
    print("[*] Multi-timescale detection enabled (fast + slow attacks)")

    threading.Thread(
        target=sniff,
        kwargs={"iface": INTERFACE, "prn": on_packet, "store": False},
        daemon=True
    ).start()

    detection_loop()

if __name__ == "__main__":
    main()
