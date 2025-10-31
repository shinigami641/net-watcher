from netwacher.exstension import socketio
from netwacher.socket_handlers import NotificationsNamespace
def init_socket(app):
    socketio.init_app(app)
    
    socketio.on_namespace(NotificationsNamespace('/notifications'))
    socketio.on_namespace(NotificationsNamespace('/arp-attack'))
