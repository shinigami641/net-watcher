# netwatcher/views/socket_handlers.py  (atau di __init__.py views)
from flask_socketio import Namespace, emit
from flask_socketio import join_room
from flask import request

class NotificationsNamespace(Namespace):
    
    def on_connect(self):
        client_id = request.args.get('client_id')
        join_room(client_id)
        print(f'Client {client_id} joined room')

    def on_disconnect(self):
        print('client disconnected')

    def on_client_message(self, data):
        print('received from client:', data)
        emit('server_response', {'ok': True})
        
    def on_join_room(self, data):
        room = data.get("room")
        if room:
            join_room(room)
            emit("joined", {"room": room})

def send_ws_tes(event_name, data=dict, namespace='/notifications', room=None):
    """Helper to emit Socket.IO events ensuring namespace format and optional room.

    - Ensures namespace starts with '/'
    - Emits to specific room when provided
    """
    from netwacher.exstension import socketio
    ns = namespace if str(namespace).startswith('/') else f'/{namespace}'
    try:
        socketio.emit(event_name, data, namespace=ns, room=room)
        # minimal debug to trace emissions
        print(f"[WS] Emit event='{event_name}' ns='{ns}' room='{room}' data_keys={list(data.keys())}")
    except Exception as e:
        print(f"[WS] Emit failed for event='{event_name}' ns='{ns}' room='{room}': {e}")