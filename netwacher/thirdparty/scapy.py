from scapy.all import srp, Ether, ARP, conf
import socket

def _get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_mac(ip):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=0)
    return ans[0][1].hwsrc

def scapy_arp_scan(timeout=2, iface=None):
    """
    Lakukan ARP scan ke /24 berdasarkan IP lokal. memerlukan root
    Return List of {'ip': ..., 'mac': ...}
    """
    conf.verb = 0
    try: 
        local_ip = _get_local_ip()
    except Exception:
        return []
    parts = local_ip.split('.')
    network = '.'.join(parts[:3]) + '.0/24'
    ans,_=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=timeout, iface=iface, inter=0.1)
    
    results = []
    for _, rcv in ans:
        results.append({'ip': rcv.psrc, 'mac': rcv.hwsrc})
    return results

if __name__ == "__main__":
    print(scapy_arp_scan())