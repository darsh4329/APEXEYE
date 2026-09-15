"""
APEXEYE MASTER — Authentication Middleware (Phase 2)

Provides a decorator for API endpoints that require
authenticated client requests.

Clients authenticate by sending:
  - X-Device-ID header: the device_id
  - X-Auth-Token header: the pairing token

The middleware:
  1. Validates that both headers are present
  2. Checks that the device exists and is paired
  3. Validates the token hash matches the stored credential
  4. Rejects unauthenticated requests with 401
  5. Logs authentication failures
"""

import hashlib
from functools import wraps

from flask import request, jsonify, g

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.auth.middleware")


def _hash_token(token: str) -> str:
    """One-way SHA-256 hash of a token for comparison."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_device_credentials() -> tuple[bool, str, str]:
    """
    Validate incoming device headers: X-Device-ID and X-Auth-Token.
    Returns: (is_valid: bool, device_id: str, error_message: str)
    """
    device_id = request.headers.get("X-Device-ID", "").strip()
    auth_token = request.headers.get("X-Auth-Token", "").strip()

    if not device_id:
        return False, "", "X-Device-ID header is required."

    if not auth_token:
        return False, "", "X-Auth-Token header is required."

    conn = get_connection()
    try:
        device = conn.execute(
            "SELECT device_id, authentication_status FROM devices "
            "WHERE device_id = ?;",
            (device_id,),
        ).fetchone()

        if not device:
            return False, device_id, "Device not found."

        if device["authentication_status"] != "paired":
            return False, device_id, f"Device is not paired (status: {device['authentication_status']})."

        token_hash = _hash_token(auth_token)
        auth_row = conn.execute(
            "SELECT id FROM device_auth "
            "WHERE device_id = ? AND credential_id = ? "
            "AND authentication_status = 'paired';",
            (device_id, token_hash),
        ).fetchone()

        if not auth_row:
            return False, device_id, "Invalid authentication token."

        return True, device_id, ""
    finally:
        conn.close()


def require_device_auth(f):
    """
    Decorator that requires a valid device authentication.

    Reads X-Device-ID and X-Auth-Token headers.
    Sets g.device_id on success for use by the endpoint.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        is_valid, device_id, err_msg = validate_device_credentials()
        if not is_valid:
            logger.warning("Auth rejected: %s (remote: %s)", err_msg, request.remote_addr)
            return jsonify({"error": err_msg}), 401

        # Authentication successful — set device_id in Flask's g context
        g.device_id = device_id
        return f(*args, **kwargs)

    return decorated

