"""
APEXEYE MASTER — CCTV Management REST API (Phase 4)

Endpoints:
  GET    /api/cctv                  — List registered CCTV cameras
  POST   /api/cctv                  — Register new CCTV camera
  GET    /api/cctv/summary          — CCTV health summary counts
  GET    /api/cctv/<id>             — Get CCTV details
  PUT    /api/cctv/<id>             — Update CCTV config
  DELETE /api/cctv/<id>             — Remove CCTV device
  POST   /api/cctv/<id>/check       — Trigger immediate connectivity check
  POST   /api/cctv/<id>/enable      — Enable monitoring
  POST   /api/cctv/<id>/disable     — Disable monitoring
  GET    /api/cctv/<id>/telemetry   — Historical telemetry
"""

from flask import Blueprint, jsonify, request

from master.app.api.security import require_admin
from master.app.services.cctv_service import CCTVService, ValidationError
from master.app.services.cctv_monitor import cctv_monitor_engine
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.cctv")

cctv_bp = Blueprint("cctv_api", __name__)
_service = CCTVService()


@cctv_bp.route("/cctv", methods=["GET"])
@require_admin
def list_cctv():
    """List all registered CCTV devices."""
    try:
        devices = _service.list_cctv(include_secrets=False)
        return jsonify(devices), 200
    except Exception as exc:
        logger.error("Failed to list CCTV devices: %s", exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv", methods=["POST"])
@require_admin
def register_cctv():
    """Register a new CCTV / IP Camera / NVR endpoint."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    try:
        created = _service.register_cctv(data)
        return jsonify(created), 201
    except ValidationError as err:
        return jsonify({"error": str(err)}), 400
    except Exception as exc:
        logger.error("Failed to register CCTV device: %s", exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/summary", methods=["GET"])
@require_admin
def get_cctv_summary():
    """Get CCTV count summary for dashboard cards."""
    try:
        summary = _service.get_summary()
        return jsonify(summary), 200
    except Exception as exc:
        logger.error("Failed to get CCTV summary: %s", exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/<cctv_id>", methods=["GET"])
@require_admin
def get_cctv(cctv_id: str):
    """Get details for a single CCTV camera."""
    try:
        cctv = _service.get_cctv(cctv_id, include_secrets=False)
        if not cctv:
            return jsonify({"error": f"CCTV '{cctv_id}' not found"}), 404
        return jsonify(cctv), 200
    except Exception as exc:
        logger.error("Failed to get CCTV '%s': %s", cctv_id, exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/<cctv_id>", methods=["PUT"])
@require_admin
def update_cctv(cctv_id: str):
    """Update CCTV configuration."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    try:
        updated = _service.update_cctv(cctv_id, data)
        if not updated:
            return jsonify({"error": f"CCTV '{cctv_id}' not found"}), 404
        return jsonify(updated), 200
    except ValidationError as err:
        return jsonify({"error": str(err)}), 400
    except Exception as exc:
        logger.error("Failed to update CCTV '%s': %s", cctv_id, exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/<cctv_id>", methods=["DELETE"])
@require_admin
def delete_cctv(cctv_id: str):
    """Delete a CCTV device."""
    try:
        success = _service.delete_cctv(cctv_id)
        if not success:
            return jsonify({"error": f"CCTV '{cctv_id}' not found"}), 404
        return jsonify({"message": f"CCTV '{cctv_id}' deleted successfully"}), 200
    except Exception as exc:
        logger.error("Failed to delete CCTV '%s': %s", cctv_id, exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/<cctv_id>/check", methods=["POST"])
@require_admin
def check_cctv_now(cctv_id: str):
    """Trigger an immediate connectivity probe on a CCTV camera."""
    try:
        telemetry = cctv_monitor_engine.check_now(cctv_id)
        if not telemetry:
            return jsonify({"error": f"CCTV '{cctv_id}' not found"}), 404
        return jsonify(telemetry), 200
    except Exception as exc:
        logger.error("Failed to check CCTV '%s': %s", cctv_id, exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/<cctv_id>/enable", methods=["POST"])
@require_admin
def enable_cctv(cctv_id: str):
    """Enable monitoring for a CCTV device."""
    try:
        updated = _service.set_enabled(cctv_id, True)
        if not updated:
            return jsonify({"error": f"CCTV '{cctv_id}' not found"}), 404
        return jsonify(updated), 200
    except Exception as exc:
        logger.error("Failed to enable CCTV '%s': %s", cctv_id, exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/<cctv_id>/disable", methods=["POST"])
@require_admin
def disable_cctv(cctv_id: str):
    """Disable monitoring for a CCTV device."""
    try:
        updated = _service.set_enabled(cctv_id, False)
        if not updated:
            return jsonify({"error": f"CCTV '{cctv_id}' not found"}), 404
        return jsonify(updated), 200
    except Exception as exc:
        logger.error("Failed to disable CCTV '%s': %s", cctv_id, exc)
        return jsonify({"error": "Internal server error"}), 500


@cctv_bp.route("/cctv/<cctv_id>/telemetry", methods=["GET"])
@require_admin
def get_cctv_telemetry(cctv_id: str):
    """Get historical telemetry records for a CCTV camera."""
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        cctv = _service.get_cctv(cctv_id)
        if not cctv:
            return jsonify({"error": f"CCTV '{cctv_id}' not found"}), 404

        records = _service.get_recent_telemetry(cctv_id, limit=limit)
        return jsonify(records), 200
    except Exception as exc:
        logger.error("Failed to get telemetry for CCTV '%s': %s", cctv_id, exc)
        return jsonify({"error": "Internal server error"}), 500

