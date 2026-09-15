"""
APEXEYE MASTER — Centralized Logs & Activity API Routes (Phase 5)

REST API endpoints for centralized log ingestion, search, multi-field filtering,
pagination, and summary statistics.

Endpoints:
  - POST /api/logs          — Ingest batch logs/events (authenticated by agent)
  - GET  /api/logs          — Search/filter/paginate centralized logs
  - GET  /api/logs/summary  — Aggregated log count statistics
  - GET  /api/logs/<id>     — Retrieve single log event detail
"""

from flask import Blueprint, request, jsonify, g

from master.app.api.auth_middleware import require_device_auth
from master.app.api.security import require_admin, require_device_or_admin
from master.app.services.log_service import LogService, LogValidationError
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.logs")

logs_bp = Blueprint("logs_api", __name__)
_log_svc = LogService()


@logs_bp.route("/logs", methods=["POST"])
@require_device_auth
def ingest_logs():
    """
    Ingest a batch of centralized log/activity events from an authenticated agent.

    Headers:
      X-Device-ID: <device_id>
      X-Auth-Token: <auth_token>

    Payload:
      {
        "logs": [
          {
            "timestamp": "2026-08-25 10:30:00",
            "severity": "INFO",
            "category": "APPLICATION",
            "event_type": "APPLICATION_ACTIVE",
            "application_name": "Microsoft Word",
            "message": "Microsoft Word became active",
            "details": { ... }
          }
        ]
      }
    """
    data = request.get_json(silent=True) or {}
    device_id = g.device_id

    # Support either "logs" or "events" keys
    entries = data.get("logs") or data.get("events") or []
    if not isinstance(entries, list):
        return jsonify({"error": "Payload must contain a list of 'logs' or 'events'."}), 400

    if not entries:
        return jsonify({"device_id": device_id, "stored": 0}), 200

    try:
        stored_count = _log_svc.ingest_logs(device_id, entries)
        return jsonify({
            "device_id": device_id,
            "stored": stored_count,
            "status": "success",
        }), 201
    except LogValidationError as err:
        return jsonify({"error": str(err)}), 400
    except Exception as exc:
        logger.error("Failed to ingest logs for %s: %s", device_id, exc)
        return jsonify({"error": "Internal server error."}), 500


@logs_bp.route("/logs", methods=["GET"])
@require_admin
def search_logs():
    """
    Search and filter centralized logs with pagination.

    Query Params:
      - device_id: Filter by device ID
      - device_type: WINDOWS_PC, LINUX_PC, CCTV, etc.
      - severity: Filter by severity (comma-separated: INFO,WARNING,ERROR,CRITICAL)
      - category: Filter by category (APPLICATION,SYSTEM,SECURITY,NETWORK,AGENT,CCTV,OTHER)
      - event_type: Exact match event type (e.g. APPLICATION_ACTIVE, CPU_WARNING)
      - application: Case-insensitive substring search for application name
      - start_time: ISO or SQL datetime string
      - end_time: ISO or SQL datetime string
      - q: Search string in message, application_name, or event_type
      - limit: Max records (default: 50, max: 200)
      - offset: Record offset (default: 0)
    """
    device_id = request.args.get("device_id")
    device_type = request.args.get("device_type")
    severity = request.args.get("severity") or request.args.get("level")
    category = request.args.get("category")
    event_type = request.args.get("event_type")
    application_name = request.args.get("application") or request.args.get("app")
    start_time = request.args.get("start_time") or request.args.get("from")
    end_time = request.args.get("end_time") or request.args.get("to")
    query = request.args.get("q") or request.args.get("query")
    limit = request.args.get("limit", 50)
    offset = request.args.get("offset", 0)

    try:
        result = _log_svc.search_logs(
            device_id=device_id,
            device_type=device_type,
            severity=severity,
            category=category,
            event_type=event_type,
            application_name=application_name,
            start_time=start_time,
            end_time=end_time,
            query=query,
            limit=limit,
            offset=offset,
        )
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Error searching logs: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@logs_bp.route("/logs/summary", methods=["GET"])
@require_admin
def log_summary():
    """Return aggregated log metrics and category breakdown."""
    try:
        summary = _log_svc.get_log_summary()
        return jsonify(summary), 200
    except Exception as exc:
        logger.error("Error generating log summary: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@logs_bp.route("/logs/<int:log_id>", methods=["GET"])
@require_admin
def get_log_detail(log_id: int):
    """Retrieve a single log entry by primary key ID."""
    from master.app.database import get_connection
    import json
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM logs WHERE id = ?;", (log_id,)).fetchone()
        if not row:
            return jsonify({"error": f"Log with ID {log_id} not found."}), 404
        item = dict(row)
        if item.get("details"):
            try:
                item["details"] = json.loads(item["details"])
            except Exception:
                pass
        return jsonify(item), 200
    finally:
        conn.close()


@logs_bp.route("/logs/activity", methods=["GET"])
@require_admin
def get_all_activities():
    """Return latest foreground activity snapshot for all devices."""
    try:
        activities = _log_svc.get_all_current_activities()
        return jsonify({"activities": activities, "count": len(activities)}), 200
    except Exception as exc:
        logger.error("Error retrieving activities: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@logs_bp.route("/logs/activity/<device_id>", methods=["GET"])
@require_device_or_admin("device_id")
def get_device_activity(device_id: str):
    """Return latest foreground activity state for a specific device."""
    try:
        activity = _log_svc.get_device_current_activity(device_id)
        return jsonify(activity), 200
    except Exception as exc:
        logger.error("Error retrieving activity for %s: %s", device_id, exc)
        return jsonify({"error": "Internal server error."}), 500


@logs_bp.route("/logs/clear", methods=["POST", "DELETE"])
@require_admin
def clear_logs():
    """
    Clear development activity/event logs from the database.
    Preserves devices, device authentication, telemetry, and CCTV configs.
    """
    data = request.get_json(silent=True) or {}
    device_id = request.args.get("device_id") or data.get("device_id")

    try:
        deleted = _log_svc.clear_logs(device_id=device_id)
        return jsonify({
            "message": f"Successfully cleared {deleted} log record(s).",
            "deleted": deleted,
            "status": "success",
        }), 200
    except Exception as exc:
        logger.error("Error clearing logs: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@logs_bp.route("/logs/live-alerts", methods=["GET"])
@logs_bp.route("/alerts/live", methods=["GET"])
@require_admin
def get_live_critical_alerts():
    """
    Real-time emergency critical alert polling endpoint.
    Fast indexed query returning new critical events since `since_id`.
    """
    since_id_raw = request.args.get("since_id", "0")
    baseline = request.args.get("baseline", "").lower() in ("true", "1", "yes")

    try:
        since_id = int(since_id_raw)
    except ValueError:
        since_id = 0

    try:
        result = _log_svc.get_live_critical_alerts(since_id=since_id, baseline=baseline)
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Error fetching live critical alerts: %s", exc)
        return jsonify({"error": "Internal server error."}), 500



