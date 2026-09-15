"""
APEXEYE MASTER — Client-Initiated Registration API

Endpoint for clients to self-register and receive a pairing token in one step.
"""

from flask import Blueprint, request, jsonify

from master.app.services.device_service import DeviceService, ValidationError
from master.app.services.rate_limiter import rate_limit
from master.app.auth import AuthService

client_api_bp = Blueprint("client_api", __name__)

_device_svc = DeviceService()
_auth_svc = AuthService()


@client_api_bp.route("/client/register", methods=["POST"])
@rate_limit(max_requests=20, window_seconds=60, scope="client_register")
def client_register():
    """
    Client-initiated self-registration and pairing.

    The Client sends its device info. The Master:
    1. Upserts the device record (creates if new, updates metadata if existing).
    2. Generates a fresh pairing credential.
    3. Returns the one-time pairing token to the Client.

    The Client then uses this token to authenticate immediately.
    """
    data = request.get_json(silent=True) or {}

    device_id = data.get("device_id", "").strip()
    if not device_id:
        return jsonify({"error": "device_id is required."}), 400

    # Upsert the device (creates or updates without duplicating)
    try:
        _device_svc.upsert_device(data, status="pending", auth_status="unauthenticated")
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    # Generate pairing credential
    try:
        pair_result = _auth_svc.generate_pairing_credential(device_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({
        "device_id": device_id,
        "token": pair_result["token"],
        "status": "pending",
        "message": "Device registered. Use the token to authenticate.",
    }), 201
