from scapy.all import sniff, ARP, Ether, srp, IP
from collections import defaultdict
import socket
import time
import netifaces
import ipaddress
import subprocess

# Configuration réseau (modifiable dynamiquement)
NETWORK_INTERFACE = "wlp2s0"
IP_RANGE = "192.168.1.0/24"

stats = defaultdict(lambda: [0, 0])  # {IP: [upload, download]}
hostnames = {}
devices = []
active_ips = set()
bandwidth_limits = defaultdict(lambda: (None, None))  # {IP: (dl_limit, ul_limit)}
current_rates = defaultdict(lambda: [0, 0])  # {IP: [dl_rate, ul_rate]}
last_check = time.time()
last_stats = defaultdict(lambda: [0, 0])

def get_network_info():
    """Détection automatique de l'interface et plage IP"""
    global NETWORK_INTERFACE, IP_RANGE
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        interface = default_gateway[1]
        ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        NETWORK_INTERFACE = interface
        IP_RANGE = str(network)
        return interface, str(network)
    except Exception as e:
        print(f"Erreur détection automatique: {e}")
        return NETWORK_INTERFACE, IP_RANGE

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "inconnu"

def ping_sweep(ip_range):
    """Ping chaque IP de la plage pour réveiller les appareils silencieux"""
    for ip in ipaddress.IPv4Network(ip_range):
        try:
            subprocess.Popen(['ping', '-c', '1', '-W', '1', str(ip)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

def arp_scan():
    global devices, active_ips
    print(f"\nScan ARP en cours sur {IP_RANGE} via {NETWORK_INTERFACE}...")
    try:
        ping_sweep(IP_RANGE)
        time.sleep(2)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP_RANGE)
        ans, _ = srp(pkt, timeout=5, iface=NETWORK_INTERFACE, verbose=False)
        new_devices = []
        active_ips.clear()
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            active_ips.add(ip)
            new_devices.append({
                'ip': ip,
                'mac': mac,
                'hostname': hostnames.get(ip, resolve_hostname(ip))
            })
        devices = new_devices
        print(f"Scan terminé. {len(devices)} appareils trouvés.")
    except Exception as e:
        print(f"Échec du scan ARP: {e}")

def periodic_scan():
    while True:
        arp_scan()
        time.sleep(120)

def calculate_rates():
    global last_check, last_stats
    now = time.time()
    elapsed = now - last_check
    if elapsed >= 1:
        for ip in stats:
            dl_kbps = ((stats[ip][1] - last_stats[ip][1]) * 8 / 1000) / elapsed
            ul_kbps = ((stats[ip][0] - last_stats[ip][0]) * 8 / 1000) / elapsed
            current_rates[ip] = [dl_kbps, ul_kbps]
        last_stats = defaultdict(lambda: [0, 0], {k: [v[0], v[1]] for k, v in stats.items()})
        last_check = now

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        stats[src_ip][0] += packet_size  # Upload
        stats[dst_ip][1] += packet_size  # Download
        if src_ip not in hostnames:
            hostnames[src_ip] = resolve_hostname(src_ip)
        if dst_ip not in hostnames:
            hostnames[dst_ip] = resolve_hostname(dst_ip)
        calculate_rates()

def start_sniffing():
    print(f"\nDémarrage de la capture sur {NETWORK_INTERFACE}...")
    try:
        sniff(iface=NETWORK_INTERFACE, prn=process_packet, store=False)
    except Exception as e:
        print(f"Erreur capture paquets: {e}")