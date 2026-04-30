# rules.py
import re

SUSPICIOUS_DOMAIN_RE = re.compile(
    r'\b(?:malware|botnet|phish|trojan|ransomware|exploit|payload|c2|cnc|shell)\b'
    r'|\brat',
    re.IGNORECASE
)

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor port",
    6667: "IRC (botnets)",
    31337: "Elite hacker port",
    9001: "Tor relay port",
    8080: "Alternate HTTP/proxy"
}

SUSPICIOUS_IPS = {
    "1.2.3.4",
}

PRIVATE_IP = re.compile(
    r"^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$"
)
