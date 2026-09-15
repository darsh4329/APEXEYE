"""
APEXEYE MASTER — Telemetry API Routes (Phase 2)

Endpoint for clients to POST telemetry data.

POST /api/telemetry — Receive CPU, RAM, disk, network telemetry
"""

from flask import Blueprint, request, jsonify, g

from master.app.api.auth_middleware import require_device_auth
from master.app.api.security import require_admin, require_device_or_admin
from master.app.services.telemetry_service import TelemetryService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.telemetry")

telemetry_bp = Blueprint("telemetry", __name__)
_telemetry_svc = TelemetryService()


@telemetry_bp.route("/telemetry", methods=["POST"])
@require_device_auth
def receive_telemetry():
    """
    Receive telemetry data from an authenticated client.

    Expected payload:
    {
        "device_id": "...",
        "timestamp": "...",
        "cpu": { ... },
        "memory": { ... },
        "disk": { ... },
        "network": { ... }
    }
    """
    data = request.get_json(silent=True) or {}
    device_id = g.device_id

    # Validate payload has at least some telemetry
    if not any(k in data for k in ("cpu", "memory", "disk", "network")):
        return jsonify({"error": "Telemetry payload is empty or malformed."}), 400

    try:
        result = _telemetry_svc.ingest(device_id, data)
        return jsonify(result), 201
    except Exception as exc:
        logger.error("Telemetry ingestion error: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@telemetry_bp.route("/telemetry/history", methods=["GET"])
@require_admin
def get_telemetry_history():
    """
    Retrieve historical structured telemetry time-series.

    Query Params:
      - device_id: Filter by device ID
      - start_time: Starting timestamp (ISO or SQL datetime)
      - end_time: Ending timestamp
      - limit: Max records (default: 100, max: 500)
    """
    from master.app.services.log_service import LogService
    log_svc = LogService()
    device_id = request.args.get("device_id")
    start_time = request.args.get("start_time") or request.args.get("from")
    end_time = request.args.get("end_time") or request.args.get("to")
    limit = request.args.get("limit", 100)

    try:
        data = log_svc.get_telemetry_history(
            device_id=device_id,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
        return jsonify({"count": len(data), "telemetry": data}), 200
    except Exception as exc:
        logger.error("Error retrieving telemetry history: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@telemetry_bp.route("/telemetry/latest/<device_id>", methods=["GET"])
@require_device_or_admin("device_id")
def get_latest_telemetry(device_id: str):
    """Retrieve the single most recent telemetry record for a specific device."""
    try:
        latest = _telemetry_svc.get_latest(device_id)
        if not latest:
            return jsonify({"error": f"No telemetry found for device '{device_id}'."}), 404
        return jsonify(latest), 200
    except Exception as exc:
        logger.error("Error retrieving latest telemetry for %s: %s", device_id, exc)
        return jsonify({"error": "Internal server error."}), 500

