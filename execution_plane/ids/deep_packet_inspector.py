import os
import sys
import re
import csv
import math
import time
import threading
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw # FIX: removed DNSQR from import

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from communication.client import send_log, start_polling
except ImportError:
    print("[ERROR] Cannot import communication.client.")
    print("        Run from the macds-main project root directory.")
    sys.exit(1)

INTERFACE = "s1-eth3"
LOG_DIR = "logs"
LOG_FILE = "logs/dpi_events.csv"
OFFLINE_MODE = False

def init_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp", "event_type", "attack_type", "src_ip", "detail", "confidence"])

def log_event(event: str, attack: str, src: str, detail: str = "", confidence: str = ""):
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([time.time(), event, attack, src, detail, confidence])

def send_alert(attack_type: str, src_ip: str, packet_rate: float = 0.0, confidence: str = "MEDIUM", detail: str = ""):
    if OFFLINE_MODE:
        return
    send_log(attack_type, src_ip, packet_rate=packet_rate, confidence=confidence, detail=detail)

def tcp_fingerprint(pkt):
    ttl = pkt[IP].ttl
    win = pkt[TCP].window
    opts = set()
    for opt in pkt[TCP].options:
        name = opt[0]
        if name in (2, "MSS"): opts.add("MSS")
        elif name in (4, "SAckOK"): opts.add("SACK")
        elif name in (8, "Timestamp"): opts.add("TS")
        elif name in (3, "WScale"): opts.add("WS")
        else: opts.add(str(name))
        
    if pkt[IP].id == 0 and (pkt[IP].flags & 0x2):
        return {"match": "SPOOFED", "suspicious": True, "reason": "IP ID=0 with DF bit — packet forging tool"}
    if win in (512, 1024) and "SACK" not in opts and "TS" not in opts:
        return {"match": "TOOL", "suspicious": True, "reason": f"Window={win} — hping3/nmap default, no real OS uses this"}
    if ttl == 255:
        return {"match": "RAW_SOCKET", "suspicious": True, "reason": "TTL=255 — raw socket, not a real hop"}
        
    required = {"MSS", "SACK", "TS", "WS"}
    
    if 60 <= ttl <= 65 and 28000 <= win <= 30000:
        if required.issubset(opts):
            return {"match": "Linux", "suspicious": False, "reason": "Looks like Linux"}
        else:
            return {"match": "Linux_PARTIAL", "suspicious": True, "reason": f"Looks like Linux but missing opts: {required - opts}"}
            
    if 120 <= ttl <= 130 and 64000 <= win <= 66000:
        if required.issubset(opts):
            return {"match": "Windows", "suspicious": False, "reason": "Looks like Windows"}
        else:
            return {"match": "Windows_PARTIAL", "suspicious": True, "reason": f"Looks like Windows but missing opts: {required - opts}"}
            
    if 62 <= ttl <= 65 and 65000 <= win <= 66000:
        if required.issubset(opts):
            return {"match": "macOS", "suspicious": False, "reason": "Looks like macOS"}
        else:
            return {"match": "macOS_PARTIAL", "suspicious": True, "reason": f"Looks like macOS but missing opts: {required - opts}"}
            
    if 62 <= ttl <= 65 and 14000 <= win <= 15000:
        if required.issubset(opts):
            return {"match": "Android", "suspicious": False, "reason": "Looks like Android"}
        else:
            return {"match": "Android_PARTIAL", "suspicious": True, "reason": f"Looks like Android but missing opts: {required - opts}"}
            
    return {"match": "UNKNOWN", "suspicious": True, "reason": f"Unknown fingerprint TTL={ttl} WIN={win} opts={opts}"}

def inspect_http(pkt):
    payload = bytes(pkt[Raw].load)
    http_methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
    if not payload.startswith(http_methods):
        return {"is_http": False, "is_real_browser": True, "reason": ""}
        
    lines = payload.split(b"\r\n")
    if not lines:
        return {"is_http": False, "is_real_browser": True, "reason": ""}
        
    if b"HTTP/1.0" in lines[0]:
        return {"is_http": True, "is_real_browser": False, "reason": "HTTP/1.0 — bot/tool, no real user sends this"}
        
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
            
    if b"user-agent" not in headers:
        return {"is_http": True, "is_real_browser": False, "reason": "Missing User-Agent"}
        
    ua = headers[b"user-agent"]
    valid_uas = (b"Mozilla/5.0", b"Chrome/", b"Firefox/", b"Safari/", b"Edge/", b"curl/", b"python-requests")
    if not any(v in ua for v in valid_uas):
        return {"is_http": True, "is_real_browser": False, "reason": f"Unknown UA: {ua[:60]}"}
        
    browser_signals = 0
    for k in headers:
        if k.startswith(b"sec-fetch-") or k in (b"accept-language", b"accept-encoding"):
            browser_signals += 1
            
    if browser_signals < 2:
        return {"is_http": True, "is_real_browser": False, "reason": "Missing browser headers (Sec-Fetch-*, Accept-Language) — bot"}
        
    return {"is_http": True, "is_real_browser": True, "reason": "Real browser"}

def inspect_dns(pkt):
    if pkt[DNS].qr != 0:
        return {"suspicious": False, "attack_type": None, "reason": ""}
    if getattr(pkt[DNS], "qdcount", 0) == 0 or not pkt[DNS].qd:
        return {"suspicious": False, "attack_type": None, "reason": ""}
        
    qname = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
    qtype = pkt[DNS].qd.qtype
    
    if qtype == 255:
        return {"suspicious": True, "attack_type": "DNS_AMPLIFICATION", "reason": f"ANY query for {qname} — amplification"}
    if qtype == 12:
        return {"suspicious": True, "attack_type": "DNS_SCAN", "reason": "PTR query — reverse DNS scanning"}
        
    label = qname.split(".")[0] if qname else ""
    if len(label) > 10:
        n = len(label)
        freq = {c: label.count(c) for c in set(label)}
        entropy = -sum((freq[c]/n)*math.log2(freq[c]/n) for c in set(label))
        if entropy > 3.8:
            return {"suspicious": True, "attack_type": "DNS_DGA", "reason": f"High-entropy domain (entropy={entropy:.2f}) — DGA malware"}
            
    return {"suspicious": False, "attack_type": None, "reason": ""}

PATTERNS = {
    "SQL_INJECTION": re.compile(rb"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|xp_cmdshell|information_schema)"),
    "XSS": re.compile(rb"(?i)(<script[^>]*>|on(load|click|mouseover|error|focus)\s*=|javascript:[^\s])"),
    "PATH_TRAVERSAL": re.compile(rb"(\.\./|\.\.\\|%2e%2e%2f)|((?i)/etc/passwd|/etc/shadow|/windows/system32)"),
    "LOG4SHELL": re.compile(rb"(?i)\$\{jndi\s*:(ldap|rmi|dns|iiop)s?://"),
    "SHELLSHOCK": re.compile(rb"\(\s*\)\s*\{[^}]*\}\s*;"),
    "CMD_INJECTION": re.compile(rb"(?i)(;|\||&&|\$\(|\`)\s*(ls|cat|id|whoami|wget|curl|bash|sh|cmd)"),
    "SSRF": re.compile(rb"(?i)(url|uri|dest|redirect|next|src)=[^&\s]*(127\.0\.0\.1|localhost|169\.254\.|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
}

def scan_payload(pkt):
    payload = bytes(pkt[Raw].load)
    if len(payload) < 4:
        return {"hit": False, "attack_type": None, "match": None}
        
    for name, pat in PATTERNS.items():
        m = pat.search(payload)
        if m:
            return {"hit": True, "attack_type": name, "match": m.group(0)[:80].decode(errors="replace")}
            
    return {"hit": False, "attack_type": None, "match": None}

ip_profiles = defaultdict(lambda: {
    "syn_ts": deque(maxlen=200),
    "ack_ts": deque(maxlen=200),
    "ports": set(),
    "timing_gaps": deque(maxlen=100),
    "last_ts": None,
    "last_seen": 0.0,
})
profiles_lock = threading.Lock()

def update_profile(pkt):
    now = time.time()
    src = pkt[IP].src
    with profiles_lock:
        p = ip_profiles[src]
        p["last_seen"] = now
        if p["last_ts"] is not None:
            p["timing_gaps"].append(now - p["last_ts"])
        p["last_ts"] = now
        if TCP in pkt:
            flags = pkt[TCP].flags
            if (flags & 0x02) and not (flags & 0x10):
                p["syn_ts"].append(now)
            if flags & 0x10:
                p["ack_ts"].append(now)
            p["ports"].add(pkt[TCP].dport)

def analyze_behavior(src_ip):
    with profiles_lock:
        if src_ip not in ip_profiles:
            return {"suspicious": False, "score": 0, "reasons": []}
        p = ip_profiles[src_ip]
        syn_ts = list(p["syn_ts"])
        ack_ts = list(p["ack_ts"])
        ports = set(p["ports"])
        gaps = list(p["timing_gaps"])
        
    score = 0
    reasons = []
    
    if len(syn_ts) > 5:
        ratio = len(ack_ts) / len(syn_ts)
        if ratio < 0.1:
            score += 3
            reasons.append(f"SYN/ACK ratio={ratio:.2f} — {len(syn_ts)} SYNs, only {len(ack_ts)} ACKs")
            
    if len(ports) > 10:
        score += 2
        reasons.append(f"Hit {len(ports)} unique destination ports")
        
    if len(gaps) > 20:
        mean = sum(gaps) / len(gaps)
        stddev = (sum((g - mean)**2 for g in gaps) / len(gaps))**0.5
        cv = stddev / (mean + 1e-9)
        if cv < 0.05 and mean < 0.01:
            score += 3
            reasons.append(f"Machine-regular timing CV={cv:.4f} mean={mean*1000:.2f}ms")
            
    now = time.time()
    recent_syns = sum(1 for ts in syn_ts if now - ts <= 2.0)
    if recent_syns > 30:
        score += 2
        reasons.append(f"{recent_syns} SYNs in last 2s")
        
    return {"suspicious": score >= 3, "score": score, "reasons": reasons}

def make_verdict(src, pkt, fp, http, dns, payload, behavior):
    if pkt[IP].src == pkt[IP].dst:
        return {"verdict": "ATTACK", "attack_type": "LAND_ATTACK", "confidence": "HIGH", "reasons": ["src==dst"]}
        
    if payload.get("hit"):
        return {"verdict": "ATTACK", "attack_type": payload["attack_type"], "confidence": "HIGH", "reasons": [f"Payload: {payload['match'][:60]}"]}
        
    if dns.get("suspicious"):
        return {"verdict": "ATTACK", "attack_type": dns["attack_type"], "confidence": "HIGH", "reasons": [dns["reason"]]}
        
    score = 0
    reasons = []
    
    if fp.get("suspicious"):
        score += 3
        reasons.append(fp["reason"])
    if http.get("is_http") and not http.get("is_real_browser"):
        score += 2
        reasons.append(http["reason"])
    if behavior.get("suspicious"):
        score += behavior["score"]
        reasons.extend(behavior["reasons"])
        
    if score >= 6:
        verdict = "ATTACK"
        confidence = "HIGH"
    elif score >= 3:
        verdict = "SUSPICIOUS"
        confidence = "MEDIUM"
    else:
        verdict = "LEGITIMATE"
        confidence = "LOW"
        
    attack_type = "ANOMALY"
    if score >= 3:
        is_syn_only = (TCP in pkt and pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10)
        has_http = (TCP in pkt and pkt[TCP].dport == 80)
        
        match_str = fp.get("match", "")
        if match_str.startswith("TOOL") or match_str in ("SPOOFED", "RAW_SOCKET", "UNKNOWN"):
            attack_type = "CRAFT_ATTACK"
        elif is_syn_only and has_http:
            attack_type = "HTTP_FLOOD"
        elif is_syn_only:
            attack_type = "SYN_FLOOD"
        elif ICMP in pkt:
            attack_type = "ICMP_FLOOD"
        elif UDP in pkt:
            attack_type = "UDP_FLOOD"
        elif any("unique destination ports" in r for r in reasons):
            attack_type = "PORT_SCAN"
            
    return {"verdict": verdict, "attack_type": attack_type, "confidence": confidence, "reasons": reasons}

attack_state = defaultdict(lambda: {"active": False, "type": None})
state_lock = threading.Lock()

def _handle_verdict(src_ip, verdict_result, pkt):
    v = verdict_result["verdict"]
    atype = verdict_result["attack_type"]
    conf = verdict_result["confidence"]
    reasons = verdict_result["reasons"]
    
    with state_lock:
        state = attack_state[src_ip]
        if v == "ATTACK" and not state["active"]:
            state["active"] = True
            state["type"] = atype
            detail_str = "|".join(reasons[:3])
            log_event("ATTACK_START", atype, src_ip, detail=detail_str, confidence=conf)
            send_alert(atype, src_ip, confidence=conf, detail=detail_str)
        elif v == "SUSPICIOUS" and not state["active"]:
            detail_str = "|".join(reasons[:3])
            log_event("SUSPICIOUS", atype, src_ip, detail=detail_str, confidence=conf)
        elif v == "LEGITIMATE" and state["active"]:
            state["active"] = False
            old_type = state["type"]
            log_event("ATTACK_END", old_type, src_ip, detail="Traffic normalized", confidence="HIGH")
            send_alert("none", src_ip, confidence="HIGH", detail="Traffic normalized")

def on_packet(pkt):
    if IP not in pkt:
        return
    try:
        update_profile(pkt)
        
        fp = {"suspicious": False}
        if TCP in pkt and (pkt[TCP].flags & 0x02):
            fp = tcp_fingerprint(pkt)
            
        http_r = {"is_http": False, "is_real_browser": True}
        if TCP in pkt and pkt[TCP].dport in (80, 443, 8080, 8443) and Raw in pkt:
            http_r = inspect_http(pkt)
            
        dns_r = {"suspicious": False}
        if UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53) and DNS in pkt:
            dns_r = inspect_dns(pkt)
            
        payload_r = {"hit": False}
        if Raw in pkt:
            payload_r = scan_payload(pkt)
            
        behavior = analyze_behavior(pkt[IP].src)
        
        v = make_verdict(pkt[IP].src, pkt, fp, http_r, dns_r, payload_r, behavior)
        _handle_verdict(pkt[IP].src, v, pkt)
    except Exception as e: # FIX: capture exception
        log_event("ERROR", "PARSE_ERROR", "", detail=str(e)[:200]) # FIX: log parse errors instead of silent pass

def cleanup_loop():
    while True:
        try:
            now = time.time()
            with profiles_lock:
                to_delete = [ip for ip, p in ip_profiles.items() if now - p["last_seen"] > 60]
                for ip in to_delete:
                    del ip_profiles[ip]
        except Exception:
            pass
        time.sleep(30)

def main():
    global OFFLINE_MODE
    init_logger()
    print("[*] MACDS DPI starting")
    print(f"[*] Sniffing interface: {INTERFACE}")
    print(f"[*] Log file: {LOG_FILE}")
    print("[*] DPI mode: TCP fingerprint / HTTP / DNS / Payload / Behavior")
    
    try:
        import requests
        cp_url = os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000")
        requests.get(f"{cp_url}/health", timeout=3)
        print(f"[*] Control plane reachable at {cp_url}")
        start_polling()
    except Exception:
        print("[!] Control plane unreachable — OFFLINE_MODE active (detection only, no enforcement)")
        OFFLINE_MODE = True
        
    threading.Thread(target=cleanup_loop, daemon=True).start()
    
    sniff(iface=INTERFACE, prn=on_packet, store=False)

if __name__ == "__main__":
    main()
