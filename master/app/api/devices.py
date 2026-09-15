"""
APEXEYE MASTER — Device REST API (Phase 1)

Endpoints:
  GET    /api/devices              List all devices
  GET    /api/devices/<id>         Get device details
  POST   /api/devices              Register a new device
  PUT    /api/devices/<id>         Update device metadata
  DELETE /api/devices/<id>         De-register a device
  GET    /api/devices/summary      Dashboard summary counts
  POST   /api/devices/<id>/pair    Generate pairing credential
  POST   /api/devices/<id>/authenticate  Authenticate with token
  POST   /api/devices/<id>/revoke  Revoke credentials
  GET    /api/devices/<id>/auth    Get auth status
"""

from flask import Blueprint, request, jsonify

from master.app.api.security import require_admin, require_device_or_admin
from master.app.services.device_service import DeviceService, ValidationError
from master.app.services.rate_limiter import rate_limit
from master.app.auth import AuthService

devices_bp = Blueprint("devices", __name__)

_device_svc = DeviceService()
_auth_svc = AuthService()


# ── Summary (must be before /<device_id> route) ─────────────────

@devices_bp.route("/devices/summary", methods=["GET"])
@require_admin
def summary():
    return jsonify(_device_svc.get_summary())


# ── CRUD ─────────────────────────────────────────────────────────

@devices_bp.route("/devices", methods=["GET"])
@require_admin
def list_devices():
    with_telemetry = request.args.get("with_telemetry", "").lower() in ("true", "1", "yes")
    if with_telemetry:
        return jsonify(_device_svc.list_devices_with_telemetry())
    return jsonify(_device_svc.list_devices())


@devices_bp.route("/devices/<device_id>", methods=["GET"])
@require_device_or_admin("device_id")
def get_device(device_id: str):
    with_telemetry = request.args.get("with_telemetry", "").lower() in ("true", "1", "yes")
    device = _device_svc.get_device(device_id, with_telemetry=with_telemetry)
    if not device:
        return jsonify({"error": "Device not found."}), 404
    return jsonify(device)


@devices_bp.route("/devices", methods=["POST"])
@require_admin
def register_device():
    data = request.get_json(silent=True) or {}
    try:
        device = _device_svc.register(data)
        return jsonify(device), 201
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400


@devices_bp.route("/devices/<device_id>", methods=["PUT"])
@require_admin
def update_device(device_id: str):
    data = request.get_json(silent=True) or {}
    try:
        device = _device_svc.update_device(device_id, data)
        if not device:
            return jsonify({"error": "Device not found."}), 404
        return jsonify(device)
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400


@devices_bp.route("/devices/<device_id>", methods=["DELETE"])
@require_admin
def remove_device(device_id: str):
    removed = _device_svc.remove_device(device_id)
    if removed:
        return jsonify({"message": f"Device '{device_id}' removed."})
    return jsonify({"error": "Device not found."}), 404


# ── Authentication / Pairing ────────────────────────────────────

@devices_bp.route("/devices/<device_id>/pair", methods=["POST"])
@require_admin
@rate_limit(max_requests=15, window_seconds=60, scope="device_pair")
def pair_device(device_id: str):
    try:
        result = _auth_svc.generate_pairing_credential(device_id)
        return jsonify(result), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@devices_bp.route("/devices/<device_id>/authenticate", methods=["POST"])
@rate_limit(max_requests=20, window_seconds=60, scope="device_auth")
def authenticate_device(device_id: str):
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    if not token:
        return jsonify({"error": "Token is required."}), 400
    device_info = data.get("device_info") or data
    ok = _auth_svc.authenticate_device(device_id, token, device_info=device_info)
    if ok:
        return jsonify({
            "success": True,
            "authenticated": True,
            "message": "Device authenticated successfully.",
            "status": "paired",
            "authentication_status": "paired",
            "device_id": device_id,
        })
    return jsonify({"error": "Authentication failed."}), 401


@devices_bp.route("/devices/<device_id>/revoke", methods=["POST"])
@require_admin
def revoke_device(device_id: str):
    revoked = _auth_svc.revoke_device(device_id)
    return jsonify({"revoked": revoked})


@devices_bp.route("/devices/<device_id>/auth", methods=["GET"])
@require_admin
def auth_status(device_id: str):
    status = _auth_svc.get_auth_status(device_id)
    return jsonify(status)

