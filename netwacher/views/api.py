from flask import jsonify,Blueprint,request
from netwacher.controllers import *


api = Blueprint('api', __name__)

@api.route("/active-interface")
def active_interface():
    return jsonify({
        "status": 1,
        "data": get_active_interface()
    })
    
@api.route("/ip-addr")
def ip_addr():
    return jsonify({
        "status": 1,
        "data": get_ip_addr
    })

@api.route("/scan-ip/<module_name>")
def scan_ip(module_name):
    return jsonify({
        "status": 1,
        "data": scan_ip(module_name)
    })