from flask import jsonify,Blueprint,request
from netwacher.controllers import *
from netwacher.utils.api_response import success_response, error_response, APP_ERROR_CODES
from netwacher.socket_handlers import send_ws_tes
import os
import signal

traffict_api = Blueprint("traffict", __name__)

@traffict_api.route("/scan-ip", methods=["POST"])
def scan_ip_api():
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Invalid or missing JSON payload", http_status=400, app_code=APP_ERROR_CODES["INVALID_INPUT"])
    data = scan_ip(payload)
    if data is None:
        return error_response("Scan failed", http_status=500, app_code=APP_ERROR_CODES["SCAN_FAILED"])
        
    return success_response(data=data, message="Scan Success", http_status=200)

@traffict_api.route("/list", methods=["POST"])
def traffic_scan():
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Invalid or missing JSON payload", http_status=400, app_code=APP_ERROR_CODES["INVALID_INPUT"])
    data = traffict_scan_ip(payload)
    if data is None:
        return error_response("Scan failed", http_status=500, app_code=APP_ERROR_CODES["SCAN_FAILED"])
    
    return success_response(data=data, message="Scan Success", http_status=200)
        

@traffict_api.route("/stop", methods=["POST"])
def traffic_stop():
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Invalid or missing JSON payload", http_status=400, app_code=APP_ERROR_CODES["INVALID_INPUT"])
    
    result = stop_scan_job(payload)
    
    # Check if result is error message (string)
    if isinstance(result, str):
        return error_response(result, http_status=500, app_code=APP_ERROR_CODES["SCAN_FAILED"])
    
    # Check if result is True (success)
    if result is True:
        return success_response(data={"stopped": True}, message="Scan stopped successfully", http_status=200)
    
    # Default error
    return error_response("Failed to stop scan", http_status=500, app_code=APP_ERROR_CODES["SCAN_FAILED"])

@traffict_api.route("/status", methods=["GET"])
def traffic_status():
    """Get all active scans (for debugging)"""
    active = []
    for job_id, rec in ACTIVE_SCANS.items():
        active.append({
            "job_id": job_id,
            "client_id": rec.get("client_id"),
            "ip": rec.get("ip"),
            "thread_alive": rec.get("thread").is_alive() if rec.get("thread") else False
        })

    return success_response(
        data={"active_scans": active, "count": len(active)},
        message="Active scans retrieved",
        http_status=200
    )
       
@traffict_api.route("/stop-all", methods=["POST"])  # Ubah ke POST
def traffic_stop_all():
    """Stop all active scans - IMPROVED VERSION"""
    
    print("[STOP_ALL] ========================================")
    print(f"[STOP_ALL] Stopping all {len(ACTIVE_SCANS)} active scans")
    
    stopped = []
    failed = []
    
    # Stop each scan
    for job_id, rec in list(ACTIVE_SCANS.items()):
        try:
            sniffer = rec.get("sniffer")
            thread = rec.get("thread")
            client_id = rec.get("client_id")
            
            print(f"[STOP_ALL] Stopping job {job_id}")
            
            # Stop sniffer
            if sniffer:
                sniffer.stop_sniffing = True
                if hasattr(sniffer, 'stop'):
                    sniffer.stop()
            
            # Wait for thread
            if thread and thread.is_alive():
                thread.join(timeout=3)
                if thread.is_alive():
                    thread.daemon = True  # Make daemon if still alive
                    print(f"[STOP_ALL] Thread {job_id} still alive, set as daemon")
            
            # Send notification
            if client_id:
                send_ws_tes("scan_stopped", {"job": job_id, "reason": "stop_all"}, room=client_id)
            
            stopped.append(job_id)
            print(f"[STOP_ALL] Job {job_id} stopped successfully")
            
        except Exception as e:
            print(f"[STOP_ALL] Error stopping job {job_id}: {e}")
            failed.append({"job_id": job_id, "error": str(e)})
    
    # Clear all
    ACTIVE_SCANS.clear()
    
    print(f"[STOP_ALL] Stopped: {len(stopped)}, Failed: {len(failed)}")
    print(f"[STOP_ALL] ACTIVE_SCANS cleared, remaining: {len(ACTIVE_SCANS)}")
    print("[STOP_ALL] ========================================")
    
    return success_response(
        data={
            "stopped": stopped,
            "failed": failed,
            "total": len(stopped) + len(failed)
        },
        message=f"Stopped {len(stopped)} scan(s), {len(failed)} failed",
        http_status=200
    )
    
@traffict_api.route("/emergency-stop", methods=["POST"])
def emergency_stop():
    """EMERGENCY: Force stop all threads and clear scans"""
    
    print("[EMERGENCY] Force stopping all scans and threads!")
    
    # Clear all scans
    count = len(ACTIVE_SCANS)
    ACTIVE_SCANS.clear()
    
    # Get all threads
    import threading
    threads_before = threading.active_count()
    
    print(f"[EMERGENCY] Cleared {count} scans")
    print(f"[EMERGENCY] Active threads: {threads_before}")
    
    # If you really need to kill the process (LAST RESORT)
    # os.kill(os.getpid(), signal.SIGTERM)
    
    return success_response(
        data={
            "cleared_scans": count,
            "active_threads": threads_before,
            "warning": "Threads may still be running in background"
        },
        message="Emergency stop executed",
        http_status=200
    )