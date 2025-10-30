import socket
import psutil
import importlib
import logging
from datetime import datetime
from netwacher.thirdparty.scapy_a import get_local_ip, get_gateway_ip, get_vendor_mac, get_hostname, os_fingerprint
from netwacher.thirdparty.scapyy import get_mac
from pathlib import Path
import subprocess
import sys
import json

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
        print("get_ip_addr")
        try:
           return get_local_ip()
        except Exception:
            return None
    
    @staticmethod
    def get_ip_gateway():
        try:
           return get_gateway_ip()
        except Exception:
            return None
    
    @staticmethod    
    def scan_ip_old(module_name = "scapy"):
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
    
    @staticmethod
    def scan_ip(module_name: str = "scapy"):
        """
        If module_name == 'scapy' -> execute netwacher/thirdparty/scapyy.py as subprocess
        and parse JSON list from stdout. Otherwise import module and call function as before.
        Returns list of {'ip','mac'} or None on failure.
        """
        if module_name != "scapy":
            try:
                module = importlib.import_module(f"netwacher.thirdparty.{module_name}")
            except (ModuleNotFoundError, AttributeError) as e:
                print(f"Error: {e}")
                return None

        # ---- scapy path: run external script scapyy.py ----
        if module_name == "scapy":
            # locate the scapyy.py file relative to this file
            this_file = Path(__file__).resolve()
            scapy_path = this_file.parent.parent / "thirdparty" / "scapyy.py"  # your filename
            if not scapy_path.exists():
                logging.debug(f"[scan_ip] scapyy.py not found at {scapy_path}")
                return None

            # build subprocess command using the same python interpreter
            cmd = [sys.executable, str(scapy_path)]
            
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                logging.debug("[scan_ip] scapyy subprocess timeout")
                return None
            except Exception as e:
                logging.debug(f"[scan_ip] subprocess.run failed: {e}")
                return None

            if proc.returncode != 0:
                print(f"Error executing {scapy_path}: {proc.stderr}")
                return None
        
            # Parse output (asumsi output adalah JSON atau eval-able Python literal)
            output = proc.stdout.strip()
            
            # Coba parse sebagai JSON dulu
            try:
                parsed_result = json.loads(output)
            except json.JSONDecodeError:
                # Jika bukan JSON, gunakan ast.literal_eval (lebih aman dari eval)
                import ast
                parsed_result = ast.literal_eval(output)
            
            return parsed_result


        # ---- non-scapy legacy path: call function in module directly ----
        if module_name == "fallback":
            func = "parse_arp_table"
        elif module_name == "icmp":
            func = "ping_sweep"
        elif module_name == "netifaces":
            func = "scan_local_network"
        else:
            return None

        func_ref = getattr(module, func, None)
        if func_ref is None:
            return None

        try:
            return func_ref()
        except Exception as e:
            logging.debug(f"[scan_ip] direct call failed: {e}")
            return None
        
    @staticmethod
    def get_info_detail_client(ip):
        try:
            hstname = get_hostname(ip)
            os = os_fingerprint(ip)
            vendor = get_vendor_mac(os.get("mac"))
            
            return {
                "vendor": vendor,
                "hostname": hstname,
                "os": os
            }
            
        except Exception as e:
            logging.debug(f"[get_info_detail_client] failed: {e}")
            return None