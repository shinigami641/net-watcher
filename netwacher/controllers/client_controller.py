from netwacher.models.client import Info

info = Info()

ALLOWED_PAYLOAD_KEYS = {
    "module_name"
}

def get_active_interface_ctr():
    return info.get_active_interface()

def get_ip_addr():
    return info.get_ip_addr()

def get_ip_gateway():
    return info.get_ip_gateway()

def get_info_detail_client(payload: dict):
    ip = payload.get("ip")
    mac = payload.get("mac")
    if not ip or not mac:
        return None
    return info.get_info_detail_client(ip, mac)

def scan_ip(payload: dict):
    if not isinstance(payload, dict):
        return None
    
    filtered = {k: payload[k] for k in payload.keys() & ALLOWED_PAYLOAD_KEYS }
    
    try:
        return info.scan_ip(**filtered)
    except Exception as e:
        return None