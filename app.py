from flask import Flask
from netwacher.exstension import db, socketio
from netwacher.views.api import api
from config import Config

def create_app(config_object=Config):
    app = Flask(__name__, static_folder='netwacher/static', template_folder='netwacher/templates')
    app.config.from_object(config_object)
    
    # init exstension
    db.init_app(app)
    socketio.init_app(app)
    
    # register blueprint (route/view)
    app.register_blueprint(api, url_prefix='/api')
    
    return app
    
if __name__ == '__main__':
    app = create_app()
    # gunakan socketio.run agar WebSocket aktif
    socketio.run(app, debug=True, host='127.0.0.1', port=4000)