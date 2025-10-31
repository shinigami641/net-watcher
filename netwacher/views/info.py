from flask import jsonify,Blueprint,request
from netwacher.controllers import *
from netwacher.utils.api_response import success_response, error_response, APP_ERROR_CODES

info_api = Blueprint("info", __name__)

@info_api.route("/active-interface")
def active_interface():
    data = get_active_interface_ctr()
    if data is None:
        return error_response("Interface not found", http_status=404, app_code=APP_ERROR_CODES["INTERFACE_NOT_FOUND"])
    return success_response(data=data, message="Interface Found", http_status=200)
    
@info_api.route("/ip-addr")
def ip_addr():
    data = get_ip_addr()
    if data is None:
        return error_response("Ip not found", http_status=404, app_code=APP_ERROR_CODES["IP_NOT_FOUND"])
    return success_response(data=data, message="Ip Address Found", http_status=200)

@info_api.route("/ip-gateway")
def ip_gateway():
    data = get_ip_gateway()
    if data is None:
        return error_response("Ip Gateway not found", http_status=404, app_code=APP_ERROR_CODES["IP_GATEWAY_NOT_FOUND"])
    return success_response(data=data, message="Ip Gateway Found", http_status=200)

@info_api.route("/detail-client/<ip>")
def info_detail_client(ip):
    data = get_info_detail_client(ip)
    if data is None:
        return error_response("Info not found", http_status=404, app_code=APP_ERROR_CODES["INFO_NOT_FOUND"])
    return success_response(data=data, message="Info Found", http_status=200)