from netwacher.socket_handlers import send_ws_tes
import time

def traffict_scan_ip(payload: dict):
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