from flask import jsonify,Blueprint,request, current_app
from netwacher.controllers import *
from.info import info_api
from.traffict import traffict_api
from .arp import arp_api

api = Blueprint('api', __name__, url_prefix='/api')

api.register_blueprint(info_api, url_prefix='/info')
api.register_blueprint(traffict_api, url_prefix='/traffict')
api.register_blueprint(arp_api, url_prefix='/arp')

@api.route("/routes")
def list_routes():
    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({
            # "endpoint": rule.endpoint,
            # "methods": list(rule.methods),
            "route": str(rule)
        })
    return {"routes": routes}

def register_blueprints(app):
    """
    Fungsi ini menerima objek Flask `app`
    dan mendaftarkan semua blueprint ke dalamnya.
    """
    app.register_blueprint(api)
    return app
