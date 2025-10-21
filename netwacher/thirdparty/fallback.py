import subprocess
import platform 
import re
def parse_arp_table():
    system = platform.system().lower()
    cmd = ['arp', '-a'] if system.startswith('windows') else ['arp', '-a']
    try:
        out = subprocess.check_output(cmd, universal_newlines=True)
    except Exception:
        return []
    results = []
    pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}).*?((?:[0-9A-Fa-f]{1,2}[:\-]){5}[0-9A-Fa-f]{1,2})")
    for line in out.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        
        ip = m.group(1)
        mac = m.group(2).replace('-', ':')
        
        results.append({'ip': ip, 'mac': mac})
    return results

if __name__ == "__main__":
    print(parse_arp_table())
    