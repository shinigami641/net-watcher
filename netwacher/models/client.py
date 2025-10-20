from . import db 
import socket
import psutil
import importlib
from datetime import datetime
from netwacher.thirdparty.scapy import get_local_ip

class Info:
    def get_active_interface():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == ip:
                    return iface
        
        return None
    
    def get_ip_addr():
        try:
           return get_local_ip()
        except Exception:
            return "Ip Not Found!!"
        
    def scan_ip(module_name = "scapy"):
        try:
            module = importlib.import_module(f"thirdparty.{module_name}")
            if module == "scapy":
                func = "scapy_arp_scan"
            elif module == "falback":
                func = "parse_arp_table"
            elif module == "icmp":
                func = "ping_sweep"
            elif module == "netiface":
                func = "get_iface_network"
            
            return getattr(module, func)
        except (ModuleNotFoundError, AttributeError) as e:
            print(f"Error: {e}")
            return None