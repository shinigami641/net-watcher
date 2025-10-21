from flask import jsonify,Blueprint,request
from netwacher.controllers import *


api = Blueprint('api', __name__)

@api.route("/active-interface")
def active_interface():
    data = get_active_interface_ctr()
    return jsonify({
        "status": 1,
        "data": data
    })
    
@api.route("/ip-addr")
def ip_addr():
    return jsonify({
        "status": 1,
        "data": get_ip_addr()
    })

@api.route("/scan-ip", methods=["POST"])
def scan_ip_api():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({
            "status": 0,
            "data": "Invalid payload"
        })
    result = scan_ip(payload)
    if result is None:
        return jsonify({
            "status": 0,
            "data": "Scan failed"
        })
        
    return jsonify({
        "status": 1,
        "data": result
    })