# get_net.py
import netifaces as nf
import ipaddress

def get_iface_network():
    for iface in nf.interfaces():
        addrs = nf.ifaddresses(iface)
        if nf.AF_INET in addrs:
            for a in addrs[nf.AF_INET]:
                ip = a.get('addr')
                netmask = a.get('netmask')
                if ip and netmask and not ip.startswith('127.'):
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    return None

if __name__ == "__main__":
    print(get_iface_network())  # contoh: 192.168.1.0/24
