"""
APEXEYE MASTER — Security & Access Boundary Layer

Enforces strict isolation between Master Administration and Client-facing APIs:
1. MASTER_ADMIN: Restricted strictly to localhost / loopback interfaces (127.0.0.1, ::1).
   Remote LAN clients attempting to access Master UI or admin APIs receive 403 Forbidden.
2. PUBLIC_HEALTH: Unauthenticated connectivity check (/api/health).
3. CLIENT_AUTH: Device authentication endpoint (/api/devices/<id>/authenticate).
4. AUTHENTICATED_CLIENT: Device-scoped APIs (telemetry, events, heartbeat, host-info, logs)
   which require valid pairing credentials and only allow access to the caller's own device data.
"""

import ipaddress
import os
from functools import wraps
from typing import Callable, Set

from flask import request, jsonify, g, make_response

from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.security")

# Loopback string literals for quick checks
_LOOPBACK_STRINGS: Set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
    "testclient",
    "::ffff:127.0.0.1",
}


def is_loopback_address(ip_str: str | None) -> bool:
    """
    Robustly check whether an IP string is a loopback address.
    Handles IPv4, IPv6, and IPv4-mapped IPv6 forms.
    """
    if not ip_str:
        return False
    
    clean_ip = ip_str.strip().lower()
    if clean_ip in _LOOPBACK_STRINGS:
        return True

    # Strip port if present (e.g. 127.0.0.1:12345 or [::1]:12345)
    if clean_ip.startswith("[") and "]" in clean_ip:
        clean_ip = clean_ip[1:clean_ip.index("]")]
    elif ":" in clean_ip and clean_ip.count(":") == 1:
        clean_ip = clean_ip.split(":")[0]

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        return ip_obj.is_loopback
    except ValueError:
        return False


def is_master_admin_request() -> bool:
    """
    Determine if the current incoming request originates from the Master host (loopback).
    
    Security rule: Do NOT trust arbitrary X-Forwarded-For / X-Real-IP headers unless
    APEXEYE_TRUST_PROXY is explicitly enabled by the administrator.
    """
    remote_addr = request.remote_addr
    
    # Optional trusted proxy check (default: Disabled)
    if os.getenv("APEXEYE_TRUST_PROXY", "false").lower() in ("true", "1", "yes"):
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            remote_addr = forwarded.split(",")[0].strip()

    return is_loopback_address(remote_addr)


def require_admin(f: Callable) -> Callable:
    """
    Decorator for Master Administration routes.
    
    Strictly forbids access from any remote LAN or non-loopback IP address.
    Returns HTTP 403 Forbidden with Cache-Control: no-store.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_master_admin_request():
            client_ip = request.remote_addr or "unknown"
            logger.warning(
                "SECURITY ALERT: Blocked remote admin request to '%s' from IP '%s'",
                request.path,
                client_ip,
            )
            resp = make_response(
                jsonify({
                    "error": "Forbidden: Master administration and dashboard are restricted to Master localhost.",
                    "status": 403,
                }),
                403,
            )
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            return resp

        # Admin authorized (localhost)
        return f(*args, **kwargs)

    return decorated


def require_device_or_admin(device_id_param: str = "device_id") -> Callable:
    """
    Decorator for device-scoped read endpoints (e.g. GET /api/telemetry/latest/<device_id>).
    
    Allows access if:
    1. The request originates from Master Admin (localhost), OR
    2. The request is from an authenticated client whose authenticated identity
       (g.device_id via require_device_auth) matches the requested device_id.
       
    Prevents a client from querying other devices' data (returns 403 Forbidden).
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            requested_device_id = kwargs.get(device_id_param)

            # 1. Master Admin (localhost) always allowed
            if is_master_admin_request():
                return f(*args, **kwargs)

            # 2. Remote request — must authenticate as that specific device
            from master.app.api.auth_middleware import validate_device_credentials
            auth_success, auth_device_id, err_msg = validate_device_credentials()
            if not auth_success:
                logger.warning(
                    "Remote device access rejected: %s (path: %s, remote: %s)",
                    err_msg, request.path, request.remote_addr,
                )
                resp = make_response(jsonify({"error": err_msg}), 401)
                resp.headers["Cache-Control"] = "no-store"
                return resp

            if auth_device_id != requested_device_id:
                logger.warning(
                    "SECURITY VIOLATION: Device '%s' attempted to access data for device '%s' from %s",
                    auth_device_id, requested_device_id, request.remote_addr,
                )
                resp = make_response(
                    jsonify({"error": "Forbidden: Cannot access data belonging to another device."}),
                    403,
                )
                resp.headers["Cache-Control"] = "no-store"
                return resp

            # Caller is authenticated and accessing own device data
            g.device_id = auth_device_id
            return f(*args, **kwargs)

        return decorated
    return decorator
