from flask import jsonify,Blueprint,request
from netwacher.controllers.mitm_controller import arp_attack, arp_stop, stop_all_arp_attacks, arp_get_status, arp_get_all_active
from netwacher.utils.api_response import success_response, error_response, APP_ERROR_CODES

arp_api = Blueprint("arp", __name__)

@arp_api.route("/start", methods=["POST"])
def arp_start():
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Invalid or missing JSON payload", http_status=400, app_code=APP_ERROR_CODES["INVALID_INPUT"])
    
    res = arp_attack(payload)
    if res is None:
        return error_response("arp attack failed", http_status=500, app_code=APP_ERROR_CODES["ARP_FAILED"])
    if res["success"] is False:
        return error_response(res["message"], http_status=500, app_code=APP_ERROR_CODES["ARP_FAILED"])
    
    return success_response(data=res, message="Arp Success", http_status=200)

@arp_api.route("/stop", methods=["POST"])
def arp_shut():
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Invalid or missing JSON payload", http_status=400, app_code=APP_ERROR_CODES["INVALID_INPUT"])
    
    res = arp_stop(payload)
    if res is None:
        return error_response("arp shut failed", http_status=500, app_code=APP_ERROR_CODES["ARP_SHUT_FAILED"])
    if res["success"] is False:
        return error_response(res["message"], http_status=500, app_code=APP_ERROR_CODES["ARP_SHUT_FAILED"])
    
    return success_response(data=res, message="Arp Shut Success", http_status=200)
    

@arp_api.route("/stop-all", methods=["GET", "POST"])
def arp_stop_all():
    res = stop_all_arp_attacks()
    if res is None:
        return error_response("arp stop all failed", http_status=500, app_code=APP_ERROR_CODES["ARP_STOP_ALL_FAILED"])
    if res["success"] is False:
        return error_response(res["message"], http_status=500, app_code=APP_ERROR_CODES["ARP_STOP_ALL_FAILED"])
    
    return success_response(data=res, message="Arp Stop All Success", http_status=200)

@arp_api.route("/status", methods=["POST"])
def arp_status():
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Invalid or missing JSON payload", http_status=400, app_code=APP_ERROR_CODES["INVALID_INPUT"])
    
    res = arp_get_status(payload)
    if res is None:
        return error_response("arp status failed", http_status=500, app_code=APP_ERROR_CODES["ARP_STATUS_FAILED"])
    if res["success"] is False:
        return error_response(res["message"], http_status=500, app_code=APP_ERROR_CODES["ARP_STATUS_FAILED"])
    
    return success_response(data=res, message="Arp Status Success", http_status=200)

@arp_api.route("/all-active")
def arp_all_active():
    res = arp_get_all_active()
    if res is None:
        return error_response("arp all active failed", http_status=500, app_code=APP_ERROR_CODES["ARP_ALL_ACTIVE_FAILED"])
    
    return success_response(data=res, message="Arp All Active Success", http_status=200)