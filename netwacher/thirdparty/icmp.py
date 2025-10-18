# ping_sweep.py
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

def _ping(ip):
    param = '-n' if platform.system().lower().startswith('windows') else '-c'
    cmd = ['ping', param, '1', '-W', '1', str(ip)]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def ping_sweep(network_cidr, workers=100):
    net = ipaddress.ip_network(network_cidr, strict=False)
    alive = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_ping, ip): ip for ip in net.hosts()}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(str(ip))
            except Exception:
                pass
    return alive

if __name__ == "__main__":
    # contoh untuk /24
    print(ping_sweep('192.168.1.0/24'))
