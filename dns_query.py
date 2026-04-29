#!/usr/bin/env python3
"""
NetGuard DNS Test Simulator
Sends suspicious DNS queries to demo NetGuard's DNS detection.
Run in a second terminal while NetGuard is monitoring.
Usage: python3 dns_query.py
"""

import time
import socket
from scapy.all import send, IP, UDP, DNS, DNSQR

DNS_SERVER = "8.8.8.8"

SUSPICIOUS_DOMAINS = [
    "xyz-malware.com",
    "botnet-c2-server.net",
    "c2-server.evil.com",
    "trojan.payload.net",
    "ratbot.attacker.com",
    "ransomware-drop.xyz",
    "shell.backdoor.io",
]


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.100"


LOCAL_IP = get_local_ip()

print("[*] NetGuard DNS Test Simulator")
print(f"[*] Local IP   : {LOCAL_IP}")
print(f"[*] DNS target : {DNS_SERVER}")
print(f"[*] Sending {len(SUSPICIOUS_DOMAINS)} suspicious DNS queries...\n")
time.sleep(1)

for domain in SUSPICIOUS_DOMAINS:
    print(f"  [>] Querying: {domain}")
    pkt = (
        IP(src=LOCAL_IP, dst=DNS_SERVER)
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )
    send(pkt, verbose=False)
    time.sleep(1.5)

print("\n[+] All DNS queries sent.")
print("[+] Check your NetGuard terminal for MEDIUM alerts.")
