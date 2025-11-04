# netwatcher/utils/api_response.py
from flask import jsonify
from datetime import datetime
from typing import Any, Optional, Dict

# Optional: definisikan kode error aplikasi (kamu bisa tambah sesuai butuh)
APP_ERROR_CODES = {
    "INVALID_INPUT": 1001,
    "NOT_FOUND": 1002,
    "UNAUTHORIZED": 1003,
    "FORBIDDEN": 1004,
    "SERVER_ERROR": 1500,
    "MODULE_NOT_ALLOWED": 2001,
    "SCAN_FAILED": 3001,
    # ARP specific
    "ARP_FAILED": 3101,
    "ARP_SHUT_FAILED": 3102,
    "ARP_STOP_ALL_FAILED": 3103,
    "ARP_STATUS_FAILED": 3104,
    "ARP_ALL_ACTIVE_FAILED": 3105,
}

def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def success_response(
    data: Any = None,
    message: str = "OK",
    http_status: int = 200,
    meta: Optional[Dict] = None,
    extra: Optional[Dict] = None
):
    """
    Standard success response.
    - data: payload (list/dict/primitive)
    - message: human-friendly message
    - http_status: HTTP status code (default 200)
    - meta: optional metadata (pagination, counts)
    - extra: any extra fields to merge into top-level response
    """
    body = {
        "status": 1,
        "message": message,
        "timestamp": _now_iso(),
        "data": data if data is not None else {},
    }
    if meta:
        body["meta"] = meta
    if extra:
        body.update(extra)
    return jsonify(body), http_status

def error_response(
    message: str = "Error",
    http_status: int = 400,
    app_code: Optional[int] = None,
    details: Optional[Dict] = None,
    extra: Optional[Dict] = None
):
    """
    Standard error response.
    - message: human-friendly error message
    - http_status: HTTP status code (default 400)
    - app_code: optional application-specific error code (from APP_ERROR_CODES)
    - details: optional structured details (validation errors, trace id)
    - extra: extra top-level fields
    """
    body = {
        "status": 0,
        "message": message,
        "timestamp": _now_iso(),
    }
    if app_code is not None:
        body["code"] = app_code
    if details:
        body["details"] = details
    if extra:
        body.update(extra)
    return jsonify(body), http_status
