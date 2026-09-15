"""
APEXEYE MASTER — Heartbeat API Routes (Phase 2)

Endpoint for clients to POST heartbeat signals.

POST /api/heartbeat — Receive heartbeat, update device last_seen
"""

from flask import Blueprint, request, jsonify, g

from master.app.api.auth_middleware import require_device_auth
from master.app.services.heartbeat_service import HeartbeatService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.heartbeat")

heartbeat_bp = Blueprint("heartbeat_api", __name__)
_heartbeat_svc = HeartbeatService()


@heartbeat_bp.route("/heartbeat", methods=["POST"])
@require_device_auth
def receive_heartbeat():
    """
    Receive a heartbeat from an authenticated client.

    Expected payload:
    {
        "device_id": "...",
        "timestamp": "...",
        "client_status": "running"
    }
    """
    data = request.get_json(silent=True) or {}
    device_id = g.device_id

    try:
        result = _heartbeat_svc.process_heartbeat(device_id, data)
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Heartbeat processing error: %s", exc)
        return jsonify({"error": "Internal server error."}), 500
