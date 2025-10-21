from flask import jsonify,Blueprint,request
from netwacher.controllers import *
from netwacher.utils.api_response import success_response, error_response, APP_ERROR_CODES


api = Blueprint('api', __name__)

@api.route("/active-interface")
def active_interface():
    data = get_active_interface_ctr()
    if data is None:
        return error_response("Interface not found", http_status=404, app_code=APP_ERROR_CODES["INTERFACE_NOT_FOUND"])
    return success_response(data=data, message="Interface Found", http_status=200)
    
@api.route("/ip-addr")
def ip_addr():
    data = get_ip_addr()
    if data is None:
        return error_response("Ip not found", http_status=404, app_code=APP_ERROR_CODES["IP_NOT_FOUND"])
    return success_response(data=data, message="Ip Found", http_status=200)

@api.route("/scan-ip", methods=["POST"])
def scan_ip_api():
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Invalid or missing JSON payload", http_status=400, app_code=APP_ERROR_CODES["INVALID_INPUT"])
    data = scan_ip(payload)
    if data is None:
        return error_response("Scan failed", http_status=500, app_code=APP_ERROR_CODES["SCAN_FAILED"])
        
    return success_response(data=data, message="Scan Success", http_status=200)