import ipaddress
import netifaces
import requests
import argparse
import platform
import pyshark
import socket
import sys
import os

# ──────────────────────────────
# Colored ASCII Banner
# ──────────────────────────────
def print_banner():
    ascii_part = r"""
 _______ __   _ _____ _______ _______  ______  ______ _______ _______
 |______ | \  |   |   |______ |______ |  ____ |_____/ |_____| |  |  |
 ______| |  \_| __|__ |       |       |_____| |    \_ |     | |  |  |
    """
    title_part = """
                  🔍 Telegram STUN IP Sniffer
                      Developer: Yashi Singh 
    """
    print("\033[92m" + ascii_part + "\033[0m")   # Green ASCII
    print("\033[91m" + title_part + "\033[0m")    # Red title

# ──────────────────────────────
# IP/Whois Functions
# ──────────────────────────────

EXCLUDED_NETWORKS = [
    '91.108.13.0/24', '149.154.160.0/21', '149.154.160.0/22',
    '149.154.160.0/23', '149.154.162.0/23', '149.154.164.0/22',
    '149.154.164.0/23', '149.154.166.0/23', '149.154.168.0/22',
    '149.154.172.0/22', '185.76.151.0/24', '91.105.192.0/23',
    '91.108.12.0/22', '91.108.16.0/22', '91.108.20.0/22',
    '91.108.4.0/22', '91.108.56.0/22', '91.108.56.0/23',
    '91.108.58.0/23', '91.108.8.0/22', '95.161.64.0/20'
]

def get_my_ip():
    try:
        return requests.get('https://icanhazip.com').text.strip()
    except Exception as e:
        print(f"[!] Error fetching external IP: {e}")
        return None

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def is_excluded_ip(ip):
    for network in EXCLUDED_NETWORKS:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
            return True
    return False

def get_whois_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        hostname = get_hostname(ip)
        if hostname:
            print(f"[+] Hostname: {hostname}")
        return data
    except Exception as e:
        print(f"[!] Error fetching whois data: {e}")
        return None

def display_whois_info(data):
    if not data:
        print("[!] No WHOIS data found.")
        return
    print(f"[!] Country: {data.get('country', 'N/A')}")
    print(f"[!] Country Code: {data.get('countryCode', 'N/A')}")
    print(f"[!] Region: {data.get('region', 'N/A')}")
    print(f"[!] Region Name: {data.get('regionName', 'N/A')}")
    print(f"[!] City: {data.get('city', 'N/A')}")
    print(f"[!] Zip Code: {data.get('zip', 'N/A')}")
    print(f"[!] Latitude: {data.get('lat', 'N/A')}")
    print(f"[!] Longitude: {data.get('lon', 'N/A')}")
    print(f"[!] Time Zone: {data.get('timezone', 'N/A')}")
    print(f"[!] ISP: {data.get('isp', 'N/A')}")
    print(f"[!] Organization: {data.get('org', 'N/A')}")
    print(f"[!] AS: {data.get('as', 'N/A')}")

# ──────────────────────────────
# Capture & Interface
# ──────────────────────────────

def choose_interface():
    interfaces = netifaces.interfaces()
    print("[+] Available interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    choice = int(input("[+] Select interface number: "))
    return interfaces[choice - 1]

def extract_stun_xor_mapped_address(interface):
    print("[+] Capturing traffic... (Press Ctrl+C to stop)")
    if platform.system() == "Windows":
        interface = "\\Device\\NPF_" + interface
    cap = pyshark.LiveCapture(interface=interface, display_filter="stun")
    my_ip = get_my_ip()
    resolved, whois = {}, {}

    for packet in cap.sniff_continuously(packet_count=0):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if is_excluded_ip(src_ip) or is_excluded_ip(dst_ip):
                continue
            if src_ip not in resolved:
                resolved[src_ip] = f"{src_ip} ({get_hostname(src_ip)})"
            if dst_ip not in resolved:
                resolved[dst_ip] = f"{dst_ip} ({get_hostname(dst_ip)})"
            if src_ip not in whois:
                whois[src_ip] = get_whois_info(src_ip)
            if dst_ip not in whois:
                whois[dst_ip] = get_whois_info(dst_ip)

            if packet.stun:
                xor_ip = packet.stun.get_field_value('stun.att.ipv4')
                print(f"[+] STUN: {resolved[src_ip]} -> {resolved[dst_ip]} | XOR IP: {xor_ip}")
                if xor_ip and xor_ip != my_ip:
                    return xor_ip
    return None

# ──────────────────────────────
# Tshark Check & Main
# ──────────────────────────────

def check_tshark_availability():
    tshark_path = os.popen('which tshark').read().strip()
    if not os.path.isfile(tshark_path):
        print("[-] Tshark not found! Install it:\n    sudo apt install tshark -y")
        sys.exit(1)
    else:
        print("[+] Tshark is available.")

def parse_args():
    parser = argparse.ArgumentParser(description="Sniff Telegram STUN IP")
    parser.add_argument('-i', '--interface', help="Network interface to use")
    return parser.parse_args()

def main():
    try:
        print_banner()
        check_tshark_availability()
        args = parse_args()
        iface = args.interface if args.interface else choose_interface()
        ip = extract_stun_xor_mapped_address(iface)
        if ip:
            print(f"\n[+] Target IP Found: {ip}")
            whois = get_whois_info(ip)
            display_whois_info(whois)
        else:
            print("[-] No IP address found.")
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")

if __name__ == "__main__":
    main()
