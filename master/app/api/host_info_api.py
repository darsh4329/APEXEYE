"""
APEXEYE MASTER — Host Info API Routes (Phase 2)

Endpoint for clients to POST host/OS information.

POST /api/host-info — Receive and store host information
"""

from flask import Blueprint, request, jsonify, g

from master.app.api.auth_middleware import require_device_auth
from master.app.services.host_info_service import HostInfoService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.host_info")

host_info_bp = Blueprint("host_info_api", __name__)
_host_info_svc = HostInfoService()


@host_info_bp.route("/host-info", methods=["POST"])
@require_device_auth
def receive_host_info():
    """
    Receive host/OS information from an authenticated client.

    Expected payload:
    {
        "device_id": "...",
        "timestamp": "...",
        "hostname": "...",
        "operating_system": "Windows",
        "os_version": "...",
        ...
    }
    """
    data = request.get_json(silent=True) or {}
    device_id = g.device_id

    # Basic validation
    if not data.get("hostname") and not data.get("operating_system"):
        return jsonify({"error": "Host info payload is empty or malformed."}), 400

    try:
        result = _host_info_svc.store_host_info(device_id, data)
        return jsonify(result), 201
    except Exception as exc:
        logger.error("Host info storage error: %s", exc)
        return jsonify({"error": "Internal server error."}), 500
