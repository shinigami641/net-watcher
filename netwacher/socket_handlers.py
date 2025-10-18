# netwatcher/views/socket_handlers.py  (atau di __init__.py views)
from flask_socketio import Namespace, emit

class NotificationsNamespace(Namespace):
    def on_connect(self):
        print('client connected')

    def on_disconnect(self):
        print('client disconnected')

    def on_client_message(self, data):
        print('received from client:', data)
        emit('server_response', {'ok': True})

# pendaftaran
from netwatcher.extensions import socketio
socketio.on_namespace(NotificationsNamespace('/notifications'))
