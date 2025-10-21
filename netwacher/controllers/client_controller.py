from netwacher.models.client import Info

info = Info()

ALLOWED_PAYLOAD_KEYS = {
    "module_name"
}

def get_active_interface_ctr():
    return info.get_active_interface()

def get_ip_addr():
    return info.get_ip_addr()

def scan_ip(payload: dict):
    if not isinstance(payload, dict):
        return None
    
    filtered = {k: payload[k] for k in payload.keys() & ALLOWED_PAYLOAD_KEYS }
    
    try:
        return info.scan_ip(**filtered)
    except Exception as e:
        return None