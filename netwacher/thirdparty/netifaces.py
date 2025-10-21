# netwacher/thirdparty/scan_net.py
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import logging
import time
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- utilities ----------
def get_local_network(prefer_ipv4=True):
    """Return network CIDR string like '192.168.43.0/24' for first non-loopback iface found."""
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for info in addrs[netifaces.AF_INET]:
                ip = info.get("addr")
                netmask = info.get("netmask")
                if ip and not ip.startswith("127."):
                    try:
                        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        return str(net)
                    except Exception:
                        continue
    return None

# ---------- ping ----------
def _ping(ip, timeout_sec=1):
    """Return True if ping replies. Cross-platform."""
    system = platform.system().lower()
    if system.startswith("windows"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), str(ip)]
    elif system.startswith("darwin"):
        # macOS: -c count, -t ttl (no -W). Use short timeout by relying on default small timeout.
        cmd = ["ping", "-c", "1", "-t", "1", str(ip)]
    else:
        # Linux: -c count, -W timeout (in seconds)
        cmd = ["ping", "-c", "1", "-W", str(int(timeout_sec)), str(ip)]

    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except FileNotFoundError:
        logger.warning("ping command not found on this system.")
        return False
    except Exception:
        return False

def ping_sweep(network_cidr, workers=100, timeout=1):
    """Return list of IP strings that replied to ping within network_cidr."""
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except Exception as e:
        logger.error("Invalid network_cidr %r: %s", network_cidr, e)
        return []

    hosts = list(net.hosts())
    if not hosts:
        return []

    workers = max(1, min(workers, len(hosts)))
    alive = []
    logger.info("Pinging %d hosts (workers=%d)...", len(hosts), workers)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_ping, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(str(ip))
            except Exception:
                logger.exception("Error while pinging %s", ip)
    return alive

# ---------- get mac ----------
def get_mac_from_arp_cache(ip):
    """Try to read OS ARP cache for given ip. Return MAC (normalized) or None."""
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None

    # flexible regex for IP and MAC
    # matches patterns like:
    # ? (192.168.43.1) at d2:8:70:4c:c4:f8 on en0 ...
    # or: 192.168.43.1 ether 00:11:22:33:44:55
    # or windows format: 192.168.43.1           00-11-22-33-44-55    dynamic
    # We'll normalize MAC to xx:xx:xx:xx:xx:xx
    pattern = re.compile(rf"({re.escape(ip)})[^\n\r]*?(([0-9A-Fa-f]{{1,2}}[:-]){{5}}[0-9A-Fa-f]{{1,2}})")
    m = pattern.search(out)
    if not m:
        # try windows dash-format
        pattern2 = re.compile(rf"{re.escape(ip)}\s+([0-9A-Fa-f]{{2}}(?:-[0-9A-Fa-f]{{2}})+)")
        m2 = pattern2.search(out)
        if m2:
            raw = m2.group(1).replace("-", ":").lower()
        else:
            return None
    else:
        raw = m.group(2).replace("-", ":").lower()

    octets = [o.zfill(2) for o in raw.split(":")]
    mac = ":".join(octets)
    if mac == "ff:ff:ff:ff:ff:ff":
        return None
    return mac

# optional scapy fallback (requires scapy installed and root)
def get_mac_with_scapy(ip, iface=None, timeout=1):
    try:
        from scapy.all import srp, Ether, ARP, conf
    except Exception:
        return None

    # if iface given, conf.iface = iface may be needed
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip))
    try:
        ans, _ = srp(pkt, timeout=timeout, verbose=False, iface=iface)
        if ans and len(ans) > 0:
            return ans[0][1].hwsrc.lower()
    except Exception:
        return None
    return None

# ---------- high-level scanner ----------
def scan_local_network(include_mac=True, workers=100, timeout=1, scapy_fallback=False):
    """Scan local network; return list of dicts: {'ip': ip, 'mac': mac or None}."""
    network = get_local_network()
    if not network:
        raise RuntimeError("Cannot detect local network")
    logger.info("Detected local network %s", network)

    alive_ips = ping_sweep(network, workers=workers, timeout=timeout)

    # give OS a tiny moment to populate ARP cache
    time.sleep(0.25)

    results = []
    for ip in alive_ips:
        mac = None
        if include_mac:
            mac = get_mac_from_arp_cache(ip)
            if not mac and scapy_fallback:
                mac = get_mac_with_scapy(ip, timeout=timeout)
        results.append({"ip": ip, "mac": mac})
    return results

# ---------- simple CLI test ----------
if __name__ == "__main__":
    print(scan_local_network(include_mac=True, workers=50, timeout=1, scapy_fallback=False))
