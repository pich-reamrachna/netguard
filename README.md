# NetGuard

A real-time network monitoring and threat detection tool built with Python. NetGuard sniffs network traffic and flags suspicious activity across three detection layers — rule-based matching, behavioral analysis, and live threat intelligence.

## Features

- **DNS Monitoring** — Detects queries to domains matching malware, botnet, ransomware, and similar patterns
- **Rule-Based Detection** — Matches known malicious IPs, dangerous ports, and suspicious domain regexes
- **Behavioral Analysis** — Identifies flood attacks, port scans, and SYN scans based on per-IP traffic patterns
- **Threat Intelligence** — Optional AbuseIPDB API integration for real-time IP reputation scoring
- **Encrypted Logs** — Alerts are stored with Fernet symmetric encryption; decrypted on demand
- **Cross-Platform** — Works on Windows (Npcap) and macOS/Linux (native capture)

## Requirements

- Python 3.8+
- On Windows: [Npcap](https://npcap.com) installed
- On macOS/Linux: run as root

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Setup

1. (Optional) Create a `.env` file for AbuseIPDB threat intelligence:

```env
ABUSEIPDB_API_KEY=your_api_key_here
```

   Without this key, Layer 3 threat intelligence is skipped automatically.

2. Encryption keys and logs are auto-generated on first run:
   - `netguard.key` — Fernet encryption key (keep this file to read past logs)
   - `netguard_log.enc` — Encrypted alert log

## Usage

**Windows** (Command Prompt as Administrator):
```
python pythonFinalOS.py
```

**macOS / Linux**:
```bash
sudo python3 pythonFinalOS.py
```

### Main Menu

| Option | Action |
|--------|--------|
| 1 | Start monitoring — select an interface and packet count |
| 2 | View saved alerts (decrypted from log) |
| 3 | Exit |

### Testing / Demo

While NetGuard is running, send crafted suspicious DNS queries from a second terminal:

```bash
python3 dns_query.py
```

This generates DNS packets that trigger MEDIUM-severity alerts so you can verify detection is working.

## Detection Layers

| Layer | Method | Severity |
|-------|--------|----------|
| DNS inspection | Regex patterns on queried domain names | MEDIUM |
| Rule-based | Known bad IPs, dangerous ports, domain patterns | HIGH |
| Behavioral | Flood detection, port scan, SYN scan (per-IP state) | HIGH |
| Threat intelligence | AbuseIPDB score > 50 | HIGH |

NetGuard tracks per-IP state (packet count, distinct ports, SYN flags, timestamps) and alerts once per threat type per IP to avoid duplicate noise.

## Alert Format

```
[YYYY-MM-DD HH:MM:SS] [SEVERITY] ALERT_TYPE: Details | Source -> Destination
```

## Project Structure

```
netguard/
├── pythonFinalOS.py   # Entry point: menu, interface selection, sniff loop
├── detector.py        # Detection engine (all three layers)
├── rules.py           # Static rules: domains, ports, IPs, private ranges
├── crypto.py          # Fernet encryption/decryption for log storage
├── interfaces.py      # Interface discovery and GUID-to-friendly-name mapping
├── colors.py          # ANSI color helpers for terminal output
├── dns_query.py       # Test utility: crafts suspicious DNS packets
└── requirements.txt
```

## Notes

- Packet capture requires elevated privileges on all platforms. NetGuard checks for admin/root on startup and exits if not satisfied.
- Deleting `netguard.key` makes existing `netguard_log.enc` entries unreadable.
- AbuseIPDB free tier allows 1,000 checks per day; the key is optional and safe to omit.
