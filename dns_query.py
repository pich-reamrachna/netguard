#!/usr/bin/env python3
"""
NetGuard Test Traffic Simulator
Sends fake suspicious packets so you can demo alerts without real malware.
Run this in a second terminal while netguard.py is monitoring on en0.
Usage: sudo python3 test_traffic.py
"""

import time
import socket
from scapy.all import send, IP, TCP, UDP, DNS, DNSQR

# DNS packets go OUT to 8.8.8.8 — this forces them through en0
# NetGuard sniffs them as they leave your machine
DNS_SERVER = "8.8.8.8"
HOST_IP = "192.168.56.1"  # VirtualBox host-only adapter IP on the host machine


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
    ("Suspicious DNS query → xyz-malware.com", "dns", "xyz-malware.com"),
    ("Suspicious DNS query → botnet-c2-server.net", "dns", "botnet-c2-server.net"),
]

for label, kind, value in tests:
    print(f"  [>] Sending: {label}")

    if kind == "dns":
        # Outbound DNS query → goes through en0, NetGuard catches it
        pkt = (
            IP(src=LOCAL_IP, dst=DNS_SERVER)
            / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname=value))
        )
        send(pkt, verbose=False)

    elif kind == "tcp":
        # Send from VM to host — host sees this as true inbound traffic
        pkt = IP(src=LOCAL_IP, dst=HOST_IP) / TCP(dport=value, flags="S")
        send(pkt, verbose=False)

    time.sleep(1.5)

print("\n[+] All test packets sent!")
print("[+] Check your NetGuard terminal for alerts.")
