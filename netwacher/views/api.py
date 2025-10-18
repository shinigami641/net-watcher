from flask import jsonify,Blueprint,request
from netwacher.controllers import *


api = Blueprint('api', __name__)
