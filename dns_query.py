#!/usr/bin/env python3
"""
NetGuard Test Traffic Simulator
Sends fake suspicious DNS packets so you can demo DNS alerts without real malware.
Run this in a second terminal while netguard.py is monitoring on en0.
Usage: sudo python3 test_traffic.py
"""

import time
import socket
from scapy.all import send, IP, UDP, DNS, DNSQR

# DNS packets go OUT to 8.8.8.8 — this forces them through en0
# NetGuard sniffs them as they leave your machine
DNS_SERVER = "8.8.8.8"


def get_local_ip():
    """Resolve the local Wi-Fi IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        print("ip")
        return ip

    except Exception:
        return "192.168.1.100"


LOCAL_IP = get_local_ip()

print("[*] NetGuard Traffic Simulator")
print(f"[*] Local Wi-Fi IP : {LOCAL_IP}")
print(f"[*] DNS target     : {DNS_SERVER}")
time.sleep(1)

tests = [
    ("Suspicious DNS query → xyz-malware.com", "xyz-malware.com"),
    ("Suspicious DNS query → botnet-c2-server.net", "botnet-c2-server.net"),
]

for label, domain in tests:
    print(f"  [>] Sending: {label}")

    # Outbound DNS query only.
    pkt = (
        IP(src=LOCAL_IP, dst=DNS_SERVER)
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )
    send(pkt, verbose=False)

    time.sleep(1.5)

print("\n[+] All test packets sent!")
print("[+] Check your NetGuard terminal for alerts.")
