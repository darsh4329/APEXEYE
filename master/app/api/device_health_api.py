"""
APEXEYE MASTER — Device Health & Risk Assessment API (Phase 6)

Endpoints:
  GET  /api/devices/<device_id>/health        — Full health score & assessment
  POST /api/devices/<device_id>/health/check  — Trigger fresh calculation & alert sync
  GET  /api/devices/<device_id>/health/trend  — Historical health score time-series
  GET  /api/devices/health/summary            — Fleet-wide health score summary
"""

from flask import Blueprint, jsonify, request

from master.app.api.security import require_device_or_admin, require_admin
from master.app.services.health_service import HealthService

health_api_bp = Blueprint("device_health_api", __name__)
_health_svc = HealthService()


@health_api_bp.route("/devices/<device_id>/health", methods=["GET"])
@require_device_or_admin("device_id")
def get_device_health(device_id: str):
    """
    Retrieve real-time health score, resource breakdown, explainable factors,
    and active alerts for a specific device.
    """
    health = _health_svc.evaluate_device_health(device_id, persist_alerts=False)
    if not health:
        return jsonify({"error": "Device not found."}), 404
    return jsonify(health), 200


@health_api_bp.route("/devices/<device_id>/health/check", methods=["POST"])
@require_device_or_admin("device_id")
def run_device_health_check(device_id: str):
    """
    Trigger a fresh live health calculation, sync alerts, and return detailed assessment.
    """
    health = _health_svc.evaluate_device_health(device_id, persist_alerts=True)
    if not health:
        return jsonify({"error": "Device not found."}), 404
    return jsonify(health), 200


@health_api_bp.route("/devices/<device_id>/health/trend", methods=["GET"])
@require_device_or_admin("device_id")
def get_device_health_trend(device_id: str):
    """
    Retrieve historical health score time-series for a device.
    """
    limit = request.args.get("limit", 10)
    try:
        limit_num = int(limit)
    except ValueError:
        limit_num = 10

    trend = _health_svc.get_health_trend(device_id, limit=limit_num)
    return jsonify({
        "device_id": device_id,
        "count": len(trend),
        "trend": trend,
    }), 200


@health_api_bp.route("/devices/health/summary", methods=["GET"])
@require_admin
def get_fleet_health_summary():
    """
    Retrieve fleet-wide health metrics overview.
    """
    summary = _health_svc.get_fleet_health_summary()
    return jsonify(summary), 200
