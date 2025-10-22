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
    duration = payload.get("duration") or 1
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
    payload should contain either:
      - "job": <job_id>
    or
      - "client_id": <client_id>  (if you stored scans keyed by client)
    """
    if not payload:
        return {"error": "missing payload"}, 400

    job_id = payload.get("job")
    client_id = payload.get("client_id")

    # prefer job_id; fallback to finding by client_id
    if not job_id and client_id:
        # find first job for this client_id
        found = None
        for jid, rec in list(ACTIVE_SCANS.items()):
            if rec.get("client_id") == client_id:
                found = jid
                break
        if found:
            job_id = found

    if not job_id:
        return "missing job or client_id"

    rec = ACTIVE_SCANS.get(job_id)
    if not rec:
        return "no active scan for job"

    sniffer = rec.get("sniffer")
    thread = rec.get("thread")
    room = rec.get("client_id")

    # emit stopping status
    send_ws_tes("scan_status", {"status": "Stopping scan", "job": job_id}, room=room)

    # signal stop
    try:
        sniffer.stop()
    except Exception as e:
        # log but continue attempt
        print("Error calling stop on sniffer:", e)

    # wait short time for thread to finish (non-blocking safe)
    if thread:
        thread.join(timeout=6)  # tunggu sampai 6 detik
        if thread.is_alive():
            # masih hidup — kita tetap remove from registry to avoid memory leak, but warn
            print(f"Warning: thread for job {job_id} still alive after join timeout")

    # cleanup registry
    try:
        ACTIVE_SCANS.pop(job_id, None)
    except Exception:
        pass

    # emit stopped confirmation
    send_ws_tes("scan_status", {"status": "Scan stopped", "job": job_id}, room=room)
    send_ws_tes("scan_stopped", {"job": job_id}, room=room)

    return True
