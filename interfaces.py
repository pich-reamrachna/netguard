import re
import platform
from scapy.all import get_if_list
from colors import cyan, green

IS_WINDOWS = platform.system() == "Windows"


def get_friendly_interfaces():
    raw = get_if_list()
    if not IS_WINDOWS:
        return [(r, r) for r in raw]
    try:
        from scapy.arch.windows import get_windows_if_list

        win_ifaces = {i["guid"]: i["name"] for i in get_windows_if_list()}
        pairs = []
        for r in raw:
            guid = re.search(r"\{(.+?)\}", r)
            friendly = win_ifaces.get("{" + guid.group(1) + "}" if guid else "", r)
            pairs.append((friendly, r))
        return pairs
    except Exception:
        return [(r, r) for r in raw]


def list_interfaces():
    pairs = get_friendly_interfaces()
    print(cyan("\n[*] Available network interfaces:"))
    for i, (display, _) in enumerate(pairs):
        print(f"    {i+1}. {display}")
    return pairs


def auto_select_interface(pairs):
    priority = [
        ["en0", "wi-fi", "wifi", "wlan0", "wlan"],
        ["en1", "en2", "eth0", "eth1", "ethernet"],
        ["lo0", "lo"],
    ]
    for keyword_list in priority:
        for kw in keyword_list:
            for display, scapy in pairs:
                if kw.lower() in display.lower() or kw.lower() in scapy.lower():
                    return display, scapy
    return pairs[0] if pairs else (None, None)
