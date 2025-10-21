import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import logging
from netwacher.thirdparty.scapy import get_mac

logging.basicConfig(level=logging.DEBUG)

def _ping(ip, timeout_sec=1):
    system = platform.system().lower()
    if system.startswith('windows'):
        cmd = ['ping', '-n', '1', '-w', str(int(timeout_sec * 1000)), str(ip)]
    else:
        cmd = ['ping', '-c', '1', '-W', str(int(timeout_sec)), str(ip)]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # kalau returncode == 0 artinya ping berhasil
        return result.returncode == 0
    except Exception:
        return False

def get_local_network():
    """Deteksi network aktif dari interface non-loopback."""
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for link in addrs[netifaces.AF_INET]:
                ip = link.get('addr')
                netmask = link.get('netmask')
                if ip and not ip.startswith('127.'):
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        return str(network)
                    except Exception:
                        continue
    return None

def ping_sweep(workers=100):
    """Ping sweep otomatis berdasar jaringan lokal aktif."""
    network_cidr = get_local_network()
    if not network_cidr:
        raise RuntimeError("Tidak dapat mendeteksi network lokal aktif.")
    logging.info(f"Scanning network: {network_cidr}")
    
    net = ipaddress.ip_network(network_cidr, strict=False)
    alive = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_ping, ip): ip for ip in net.hosts()}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    mac = get_mac(str(ip))
                    alive.append({'ip': str(ip), 'mac': str(mac)})

            except Exception:
                pass
    return alive
