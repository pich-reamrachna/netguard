import re
import os
import sys
import datetime
import requests
from collections import defaultdict
from scapy.all import IP, TCP, UDP, DNS, DNSQR
from colors import red, yellow
from rules import SUSPICIOUS_DOMAIN_RE, SUSPICIOUS_PORTS, SUSPICIOUS_IPS, PRIVATE_IP


# ── Session state ────────────────────────────────

packet_count = 0
alert_count = 0
log_entries = []

# Per-IP behavioral tracker
ip_tracker = defaultdict(
    lambda: {
        "count": 0,
        "ports": set(),
        "first_seen": None,
        "alerted": set(),
        "pending_syns": {},  # (dst, dport) → timestamp; removed when ACK is seen
    }
)

# AbuseIPDB cache — avoids querying the same IP twice
_abuse_cache = {}
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


def reset_state():
    global packet_count, alert_count, log_entries
    packet_count = 0
    alert_count = 0
    log_entries = []
    ip_tracker.clear()
    _abuse_cache.clear()


# ── Alert helper ─────────────────────────────────


def _alert(msg, severity):
    global alert_count
    print(red(msg) if severity == "HIGH" else yellow(msg))
    log_entries.append(msg)
    alert_count += 1


# ── Layer 1: Rule-based detection ────────────────

def is_suspicious_domain(domain: str) -> bool:
    return bool(SUSPICIOUS_DOMAIN_RE.search(domain.lower().strip(".")))
    
def _check_dns(packet, timestamp):
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return
    try:
        domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
    except Exception:
        return
    if domain and is_suspicious_domain(domain):
        _alert(
            f"[{timestamp}] [MEDIUM] ALERT: Suspicious DNS query → {domain}", "MEDIUM"
        )

def _check_static_ip_list(ip, timestamp, direction):
    if ip in SUSPICIOUS_IPS:
        _alert(
            f"[{timestamp}] [HIGH] ALERT: Suspicious {direction} IP detected -> {ip}", "HIGH"
        )

def _check_ports(packet, timestamp, src, dst):
    if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
        return
    if packet.haslayer(TCP):
        layer = packet[TCP]
        proto = "TCP"
    else:
        layer = packet[UDP]
        proto = "UDP"

    both_private = bool(PRIVATE_IP.match(src) and PRIVATE_IP.match(dst))

    for port, reason in SUSPICIOUS_PORTS.items():
        if layer.dport == port:
            if both_private:
                _alert(
                    f"[{timestamp}] [HIGH] ALERT: Possible lateral movement on {proto} port {port} ({reason}) | {src} -> {dst}",
                    "HIGH",
                )
            else:
                _alert(
                    f"[{timestamp}] [HIGH] ALERT: Suspicious {proto} port {port} ({reason}) [TO SUSPICIOUS PORT] | {src} -> {dst}",
                    "HIGH",
                )

        elif layer.sport == port:
            _alert(
                f"[{timestamp}] [LOW] ALERT: Suspicious {proto} port {port} ({reason}) [FROM SUSPICIOUS PORT] | {src} -> {dst}",
                "LOW",
            )

    return layer, proto


# ── Layer 2: Behavioral detection ────────────────


def _check_behavior(src, dst, timestamp, layer=None, proto=None):
    tracker = ip_tracker[src]
    now = datetime.datetime.now()

    if tracker["first_seen"] is None:
        tracker["first_seen"] = now
    tracker["count"] += 1

    if layer is not None and proto == "TCP" and hasattr(layer, "flags"):
        flags = int(layer.flags)
        tracker["ports"].add(layer.dport)
        if flags == 0x02:
            # SYN only — record as pending, waiting for ACK
            tracker["pending_syns"][(dst, layer.dport)] = now
        elif flags & 0x10:
            # ACK seen — handshake completed, remove from pending
            tracker["pending_syns"].pop((dst, layer.dport), None)

    elapsed = (now - tracker["first_seen"]).total_seconds() or 1

    if "flood" not in tracker["alerted"] and tracker["count"] > 100 and elapsed < 5:
        _alert(
            f"[{timestamp}] [HIGH] BEHAVIORAL: Flood from {src} ({tracker['count']} packets in {elapsed:.1f}s)",
            "HIGH",
        )
        tracker["alerted"].add("flood")

    if (
        "portscan" not in tracker["alerted"]
        and len(tracker["ports"]) > 10
        and elapsed < 60
    ):
        _alert(
            f"[{timestamp}] [HIGH] BEHAVIORAL: Port scan from {src} ({len(tracker['ports'])} ports in {elapsed:.1f}s)",
            "HIGH",
        )
        tracker["alerted"].add("portscan")

    # SYN scan: SYNs with no ACK reply after 2 seconds = incomplete handshakes
    stale = 0
    for t in tracker["pending_syns"].values():
        if (now - t).total_seconds() > 2:
            stale += 1
    
    if "synscan" not in tracker["alerted"] and stale > 15 and elapsed < 60:
        _alert(
            f"[{timestamp}] [HIGH] BEHAVIORAL: SYN scan from {src} ({stale} unanswered SYNs in {elapsed:.1f}s)",
            "HIGH",
        )
        tracker["alerted"].add("synscan")


# ── Layer 3: Threat intelligence (AbuseIPDB) ─────


def _check_abuseipdb(ip, timestamp):
    if not ABUSEIPDB_KEY or PRIVATE_IP.match(ip):
        return
    if ip in _abuse_cache:
        score = _abuse_cache[ip]
    else:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=3,
            )
            score = resp.json()["data"]["abuseConfidenceScore"]
            _abuse_cache[ip] = score
        except Exception:
            return
    if score > 50:
        _alert(
            f"[{timestamp}] [HIGH] THREAT INTEL: Known malicious IP {ip} (AbuseIPDB score: {score}/100)",
            "HIGH",
        )


# ── Packet entry point ───────────────────────────


def check_packet(packet):
    global packet_count
    packet_count += 1
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    _check_dns(packet, timestamp)

    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
        result = _check_ports(packet, timestamp, src, dst)
        layer, proto = result if result else (None, None)
        _check_behavior(src, dst, timestamp, layer, proto)
        _check_static_ip_list(src, timestamp, "source")
        _check_static_ip_list(dst, timestamp, "destination")
        _check_abuseipdb(src, timestamp)

    if packet_count % 50 == 0:
        sys.stdout.write(
            f"  ... {packet_count} packets captured, {alert_count} alerts so far\r"
        )
        sys.stdout.flush()
