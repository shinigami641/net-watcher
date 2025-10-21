import socket
import psutil
import importlib
import logging
from datetime import datetime
from netwacher.thirdparty.scapy import get_local_ip

class Info:
    @staticmethod
    def get_active_interface():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception as e:
            logging.error(f"Gagal mendapatkan IP lokal: {e}")
            return None

        logging.debug(f"[DEBUG] IP lokal aktif: {ip}")

        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == ip:
                    logging.debug(f"[DEBUG] Interface aktif ditemukan: {iface}")
                    return iface

        logging.warning(f"Tidak ditemukan interface untuk IP {ip}")
        return None
    
    @staticmethod
    def get_ip_addr():
        try:
           return get_local_ip()
        except Exception:
            return None
    
    @staticmethod    
    def scan_ip(module_name = "scapy"):
        try:
            module = importlib.import_module(f"netwacher.thirdparty.{module_name}")
        except (ModuleNotFoundError, AttributeError) as e:
            print(f"Error: {e}")
            return None
        
        if module_name == "scapy":
            func = "scapy_arp_scan"
        elif module_name == "fallback":
            func = "parse_arp_table"
        elif module_name == "icmp":
            func = "ping_sweep"
        elif module_name == "netifaces":
            func = "scan_local_network"
        else:
            return None
        
        func_ref = getattr(module, func, None)
        result = func_ref()
        
        return result