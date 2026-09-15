"""
APEXEYE MASTER — AI Analysis & Diagnostics API (Phase 8)

REST API endpoints for device-specific and fleet-wide AI analysis,
deterministic anomaly queries, actionable recommendations, and narrative summaries.
"""

from flask import Blueprint, request, jsonify
from master.app.api.security import require_admin, require_device_or_admin
from master.app.services.ai_service import AIService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.ai")

ai_api_bp = Blueprint("ai_api", __name__)
_ai_svc = AIService()


@ai_api_bp.route("/devices/<device_id>/ai/summary", methods=["GET"])
@require_device_or_admin("device_id")
def get_device_ai_summary(device_id: str):
    """Retrieve AI executive narrative and observations for a device."""
    start = request.args.get("start") or request.args.get("start_time")
    end = request.args.get("end") or request.args.get("end_time")
    try:
        res = _ai_svc.analyze_device(device_id, start_time=start, end_time=end)
        if not res.get("exists"):
            return jsonify({"error": res.get("error", "Device not found.")}), 404
        return jsonify({
            "device_id": device_id,
            "narrative": res["narrative"],
            "stats": res["stats"],
            "anomaly_count": res["anomaly_count"],
        }), 200
    except Exception as exc:
        logger.error("Error retrieving AI summary for %s: %s", device_id, exc)
        return jsonify({"error": "Internal server error."}), 500


@ai_api_bp.route("/devices/<device_id>/ai/analyze", methods=["POST"])
@require_device_or_admin("device_id")
def analyze_device_endpoint(device_id: str):
    """Execute on-demand deep AI analysis for a device with optional time window."""
    data = request.get_json(silent=True) or {}
    start = data.get("start_time") or request.args.get("start")
    end = data.get("end_time") or request.args.get("end")
    try:
        res = _ai_svc.analyze_device(device_id, start_time=start, end_time=end)
        if not res.get("exists"):
            return jsonify({"error": res.get("error", "Device not found.")}), 404
        return jsonify(res), 200
    except Exception as exc:
        logger.error("Error executing AI analysis for %s: %s", device_id, exc)
        return jsonify({"error": "Internal server error."}), 500


@ai_api_bp.route("/devices/<device_id>/ai/anomalies", methods=["GET"])
@require_device_or_admin("device_id")
def get_device_anomalies(device_id: str):
    """Retrieve detected deterministic anomalies for a device."""
    start = request.args.get("start")
    end = request.args.get("end")
    try:
        res = _ai_svc.analyze_device(device_id, start_time=start, end_time=end)
        if not res.get("exists"):
            return jsonify({"error": res.get("error", "Device not found.")}), 404
        return jsonify({
            "device_id": device_id,
            "anomalies": res["anomalies"],
            "count": len(res["anomalies"]),
        }), 200
    except Exception as exc:
        logger.error("Error retrieving anomalies for %s: %s", device_id, exc)
        return jsonify({"error": "Internal server error."}), 500


@ai_api_bp.route("/devices/<device_id>/ai/recommendations", methods=["GET"])
@require_device_or_admin("device_id")
def get_device_recommendations(device_id: str):
    """Retrieve prioritized actionable recommendations for a device."""
    start = request.args.get("start")
    end = request.args.get("end")
    try:
        res = _ai_svc.analyze_device(device_id, start_time=start, end_time=end)
        if not res.get("exists"):
            return jsonify({"error": res.get("error", "Device not found.")}), 404
        return jsonify({
            "device_id": device_id,
            "recommendations": res["recommendations"],
            "count": len(res["recommendations"]),
        }), 200
    except Exception as exc:
        logger.error("Error retrieving recommendations for %s: %s", device_id, exc)
        return jsonify({"error": "Internal server error."}), 500


@ai_api_bp.route("/ai/system-summary", methods=["GET"])
@require_admin
def get_system_ai_summary():
    """Retrieve system/fleet-wide AI narrative summary."""
    start = request.args.get("start")
    end = request.args.get("end")
    try:
        res = _ai_svc.analyze_system(start_time=start, end_time=end)
        return jsonify(res), 200
    except Exception as exc:
        logger.error("Error generating system AI summary: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@ai_api_bp.route("/ai/system-analysis", methods=["POST"])
@require_admin
def analyze_system_endpoint():
    """Execute comprehensive fleet or selected device analysis."""
    data = request.get_json(silent=True) or {}
    device_ids = data.get("device_ids")
    start = data.get("start_time")
    end = data.get("end_time")
    try:
        res = _ai_svc.analyze_system(device_ids=device_ids, start_time=start, end_time=end)
        return jsonify(res), 200
    except Exception as exc:
        logger.error("Error executing system AI analysis: %s", exc)
        return jsonify({"error": "Internal server error."}), 500
