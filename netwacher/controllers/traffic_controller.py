from netwacher.socket_handlers import send_ws_tes
from netwacher.thirdparty.scapy_a import IPSniffer
from netwacher.models.client import Info
import time
import uuid

info = Info()

def traffict_scan_ip_test(payload: dict):
    if not payload or "ip" not in payload:
        return None

    ip = payload["ip"]
    client_id = payload.get("client_id")
    print(f"Scanning traffic for IP: {ip}")
    
    send_ws_tes("scan_status", {"status": f"Starting scan for {ip}"}, room=client_id)
    time.sleep(1)
    send_ws_tes("scan_status", {"status": f"Pinging {ip}..."}, room=client_id)
    time.sleep(1)
    send_ws_tes("scan_status", {"status": f"Port scanning {ip}..."}, room=client_id)
    time.sleep(1)
    send_ws_tes("scan_status", {"status": f"Completed scan for {ip}"}, room=client_id)
    
    return "Success"

# global registry simple: client_id -> sniffer instance
ACTIVE_SCANS: dict[str, IPSniffer] = {}

def traffict_scan_ip(payload: dict):
    if not payload or "ip" not in payload:
        return None

    ip = payload["ip"]
    client_id = payload.get("client_id")
    duration = payload.get("duration")
    pcap = payload.get("pcap_path")
    jsonl = payload.get("jsonl_path")
    interface = info.get_active_interface()
    
     # buat job id (jika client_id ada gunakan itu, tetapi lebih baik unique id)
    job_id = payload.get("job_id") or str(uuid.uuid4())
    
    room = client_id  # jika tidak ada maka akan broadcast ke seluruh channel
    
    send_ws_tes("scan_status", {"status": f"Starting scan for {ip}", "job": job_id}, room=room)
    
    def on_packet_callback(summary: dict):
        send_ws_tes(
            "scan_status",
            {"summary": summary, "job": job_id},
            room=room
        )


    # Jalankan sniffer untuk IP tersebut
    sniffer = IPSniffer(iface=interface, ips=[ip], pcap_path=pcap, jsonl_path=jsonl, bpf=True, on_packet=on_packet_callback)
    
    # Start Background
    t = sniffer.start(timeout=duration, background=True)
    
    # Simpan reference
    ACTIVE_SCANS[job_id] = {
        "sniffer": sniffer,
        "thread": t,
        "client_id": client_id,
        "ip": ip
    }
    
    send_ws_tes("scan_status", {"status": "Scan started", "job": job_id}, room=room)
    # 7) return job info for caller
    return True

def stop_scan_job(payload: dict):
    """
    Stop active scan job - IMPROVED VERSION
    """
    if not payload:
        return "missing payload"

    client_id = payload.get("client_id")

    if not client_id:
        return "missing client_id"

    # Find ALL jobs by client_id
    jobs_to_stop = []
    for jid, rec in list(ACTIVE_SCANS.items()):
        if rec.get("client_id") == client_id:
            jobs_to_stop.append((jid, rec))

    if not jobs_to_stop:
        print(f"[STOP] No active scan found for client {client_id}")
        return "no active scan for this client"

    stopped_count = 0
    
    for job_id, rec in jobs_to_stop:
        sniffer = rec.get("sniffer")
        thread = rec.get("thread")
        room = client_id

        print(f"[STOP] ========================================")
        print(f"[STOP] Stopping job {job_id} for client {client_id}")
        print(f"[STOP] Thread alive: {thread.is_alive() if thread else 'No thread'}")
        
        # Emit stopping status
        send_ws_tes("scan_status", {"status": "Stopping scan", "job": job_id}, room=room)

        # STEP 1: Set stop flag on sniffer
        if sniffer:
            try:
                print(f"[STOP] Setting stop flag on sniffer...")
                sniffer.stop_sniffing = True
                
                # Call stop method if exists
                if hasattr(sniffer, 'stop'):
                    sniffer.stop()
                    print(f"[STOP] Sniffer stop() method called")
                    
            except Exception as e:
                print(f"[ERROR] Error calling stop on sniffer: {e}")

        # STEP 2: Wait for thread to finish
        if thread:
            if thread.is_alive():
                print(f"[STOP] Thread is alive, waiting for it to finish...")
                
                # Wait with multiple attempts
                for attempt in range(3):
                    thread.join(timeout=2)
                    
                    if not thread.is_alive():
                        print(f"[STOP] Thread finished after {attempt + 1} attempt(s)")
                        break
                    else:
                        print(f"[STOP] Thread still alive after attempt {attempt + 1}, trying again...")
                        
                        # Force stop flag again
                        if sniffer:
                            sniffer.stop_sniffing = True
                
                # Final check
                if thread.is_alive():
                    print(f"[WARNING] Thread {job_id} still alive after all attempts!")
                    print(f"[WARNING] Thread will be left as daemon and will stop when app exits")
                    # Set as daemon so it won't block app exit
                    thread.daemon = True
                else:
                    print(f"[STOP] Thread successfully stopped")
            else:
                print(f"[STOP] Thread already finished")

        # STEP 3: Cleanup registry
        try:
            del ACTIVE_SCANS[job_id]
            stopped_count += 1
            print(f"[STOP] Removed job {job_id} from ACTIVE_SCANS")
        except Exception as e:
            print(f"[ERROR] Error removing from ACTIVE_SCANS: {e}")

        # STEP 4: Emit stopped confirmation
        send_ws_tes("scan_status", {"status": "Scan stopped", "job": job_id}, room=room)
        send_ws_tes("scan_stopped", {"job": job_id}, room=room)
        
        print(f"[STOP] Job {job_id} cleanup completed")
        print(f"[STOP] ========================================")

    print(f"[STOP] SUMMARY: Stopped {stopped_count}/{len(jobs_to_stop)} job(s) for client {client_id}")
    print(f"[STOP] Remaining active scans: {len(ACTIVE_SCANS)}")
    
    # Print remaining scans for debugging
    if ACTIVE_SCANS:
        print(f"[STOP] Still active:")
        for jid, rec in ACTIVE_SCANS.items():
            print(f"  - Job: {jid}, Client: {rec.get('client_id')}, Thread alive: {rec.get('thread').is_alive() if rec.get('thread') else False}")
    
    return True
