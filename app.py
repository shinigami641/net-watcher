from flask import Flask
from netwacher.exstension import db, socketio
from netwacher.views.api import api
from config import Config
from netwacher.utils.api_response import error_response, APP_ERROR_CODES
from netwacher.socket_handlers import NotificationsNamespace
from flask_cors import CORS

def create_app(config_object=Config):
    app = Flask(__name__, static_folder='netwacher/static', template_folder='netwacher/templates')
    app.config.from_object(config_object)
    
    # aktifkan CORS untuk semua endpoint
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    @app.errorhandler(404)
    def not_found(e):
        return error_response("Not Found", http_status=404, app_code=APP_ERROR_CODES["NOT_FOUND"])

    @app.errorhandler(500)
    def server_error(e):
        # jangan leak exception detail di production
        return error_response("Internal server error", http_status=500, app_code=APP_ERROR_CODES["SERVER_ERROR"])
    
    # init exstension
    db.init_app(app)
    socketio.init_app(app)
    
    socketio.on_namespace(NotificationsNamespace('/notifications'))
    
    # register blueprint (route/view)
    app.register_blueprint(api, url_prefix='/api')
    
    return app
    
if __name__ == '__main__':
    app = create_app()
    # gunakan socketio.run agar WebSocket aktif
    socketio.run(app, debug=True, host='127.0.0.1', port=4000)