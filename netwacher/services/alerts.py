# netwatcher/services/alerts.py
from netwatcher.extensions import socketio

def send_alert(alert_obj):
    # broadcast ke semua client pada namespace default
    socketio.emit('network_alert', alert_obj)
    return