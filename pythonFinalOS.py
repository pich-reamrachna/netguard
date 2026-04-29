#!/usr/bin/env python3
"""
NetGuard - Network Monitoring Tool
Final Project | Python Cybersecurity & Data Monitoring
Concepts used: Scapy (packet sniffing) + Regex (detection) + Cryptography (encryption)
Compatible: macOS and Windows
"""

import os
import platform
import datetime
import ctypes
from dotenv import load_dotenv
from scapy.all import sniff

load_dotenv()

from colors import red, yellow, green, cyan
from crypto import load_or_create_key, encrypt_and_save, decrypt_and_show
from interfaces import list_interfaces, auto_select_interface
import detector

IS_WINDOWS = platform.system() == "Windows"
ADMIN_HINT = (
    "Run this script as Administrator (right-click → Run as administrator)."
    if IS_WINDOWS
    else "Run this script with sudo: sudo python3 netguard.py"
)


# ── Monitoring session ───────────────────────────


def _pick_interface(pairs, auto_display, auto_scapy):
    iface_input = input(
        "\n[?] Press Enter to use auto-selected, or type interface name/number to override: "
    ).strip()

    if iface_input == "":
        print(green(f"[+] Using: {auto_display}"))
        return auto_scapy
    if iface_input.isdigit():
        idx = int(iface_input) - 1
        if 0 <= idx < len(pairs):
            print(green(f"[+] Selected: {pairs[idx][0]}"))
            return pairs[idx][1]
        print(yellow("[-] Invalid number. Falling back to auto-selected."))
        return auto_scapy
    print(green(f"[+] Using: {iface_input}"))
    return iface_input


def start_monitoring():
    detector.reset_state()

    pairs = list_interfaces()
    auto_display, auto_scapy = auto_select_interface(pairs)
    if auto_display:
        print(green(f"[+] Auto-selected: {auto_display}"))

    iface = _pick_interface(pairs, auto_display, auto_scapy)

    count_input = input(
        "[?] How many packets to capture? (0 = unlimited, Ctrl+C to stop): "
    ).strip()
    try:
        count = int(count_input)
    except ValueError:
        count = 0

    print(cyan("\n[*] Starting NetGuard... Press Ctrl+C to stop.\n"))
    print("-" * 55)

    sniff_kwargs = {
        "prn": detector.check_packet,
        "count": count if count > 0 else 0,
        "store": False,
    }
    if iface:
        sniff_kwargs["iface"] = iface

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(red(f"\n[-] Error: {e}"))
        print(yellow(f"    Tip: {ADMIN_HINT}"))
        print(yellow("    Also check that the interface name is correct."))
        if IS_WINDOWS:
            print(
                yellow(
                    "    Windows users: make sure Npcap is installed → https://npcap.com"
                )
            )
        return

    print("\n\n" + "=" * 55)
    print("              SESSION SUMMARY")
    print("=" * 55)
    print(f"  Total packets captured : {detector.packet_count}")
    print(f"  Total alerts generated : {detector.alert_count}")
    print("=" * 55)

    if detector.log_entries:
        key = load_or_create_key()
        detector.log_entries.insert(
            0, f"=== NetGuard Session | {datetime.datetime.now()} ==="
        )
        encrypt_and_save(detector.log_entries, key)
    else:
        print(green("[+] No suspicious activity detected. No log saved."))


# ── View log ─────────────────────────────────────


def view_log():
    key = load_or_create_key()
    decrypt_and_show(key)


# ── Main ─────────────────────────────────────────


def main():
    print("""
  _   _      _   ____                     _
 | \\ | | ___| |_/ ___|_   _  __ _ _ __ __| |
 |  \\| |/ _ \\ __| |  _| | | |/ _` | '__/ _` |
 | |\\  |  __/ |_| |_| | |_| | (_| | | | (_| |
 |_| \\_|\\___|\\__|\\____|\\__,_|\\__,_|_|  \\__,_|

  Network Monitoring Tool | Python Final Project
  Running on: {os} {arch}
    """.format(os=platform.system(), arch=platform.machine()))

    if IS_WINDOWS:
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(
                    yellow(
                        "[!] Warning: not running as Administrator. Packet capture may fail."
                    )
                )
                print(yellow(f"    → {ADMIN_HINT}\n"))
        except Exception:
            pass
    elif os.geteuid() != 0:
        print(yellow("[!] Warning: not running as root. Packet capture may fail."))
        print(yellow(f"    → {ADMIN_HINT}\n"))

    while True:
        print("\n--- MAIN MENU ---")
        print("  1. Start monitoring")
        print("  2. View encrypted log")
        print("  3. Exit")
        choice = input("\nChoose an option (1/2/3): ").strip()

        if choice == "1":
            start_monitoring()
        elif choice == "2":
            view_log()
        elif choice == "3":
            print(cyan("\n[*] Exiting NetGuard. Goodbye.\n"))
            break
        else:
            print(yellow("[-] Invalid option. Please enter 1, 2, or 3."))


if __name__ == "__main__":
    main()
