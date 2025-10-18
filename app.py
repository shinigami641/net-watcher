from flask import Flask
from netwacher.exstension import db
from netwacher.views import api
from config import Config

def create_app(config_object=Config):
    app = Flask(__name__, static_folder='netwacher/static', template_folder='netwacher/templates')
    app.config.from_object(config_object)
    
    # init exstension
    db.init_app(app)
    
    # register blueprint (route/view)
    app.register_blueprint(api, url_prefix='/api')