from netwacher.models.client import Info

info = Info()

def get_active_interface():
    return info.get_active_interface()

def get_ip_addr():
    return info.get_ip_addr()

def scan_ip(module_name):
    return info.scan_ip(module_name)