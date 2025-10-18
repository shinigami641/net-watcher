import subprocess
import platform 
import re
def parse_arp_table():
    system = platform.system().lower()
    cmd = ['arp', '-a'] if system.startswith('windows') else ['arp', '-n']
    try:
        out = subprocess.check_output(cmd, universal_newlines=True)
    except Exception:
        return []
    results = []
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:-]{17}|[0-9a-fA-F:-]{14}).*")
        if m:
            ip = m.group(1)
            mac = m.group(2).replace('-', ':')
            results.append({'ip': ip, 'mac': mac})
    return results

if __name__ == "__main__":
    print(parse_arp_table())
    