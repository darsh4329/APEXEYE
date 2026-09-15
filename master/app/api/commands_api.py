"""
APEXEYE MASTER — Command Center REST API (Phase 10)

Provides secure, authenticated endpoints for administrative command execution,
status inspection, and audit history.
Protected by @require_admin (Master loopback interface only).
"""

from flask import Blueprint, request, jsonify, make_response
from master.app.api.security import require_admin
from master.app.services.command_service import CommandService, ALLOWED_COMMANDS
from master.app.services.rate_limiter import rate_limit
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.commands_api")

commands_bp = Blueprint("commands_bp", __name__, url_prefix="/api/commands")
_cmd_service = CommandService()


@commands_bp.route("/execute", methods=["POST"])
@require_admin
@rate_limit(max_requests=25, window_seconds=60, scope="commands")
def execute_command():
    """
    Dispatch an allowlisted administrative command to a target device.
    
    JSON Body:
      {
        "device_id": "DEV-001",
        "command_type": "RUN_HEALTH_CHECK",
        "parameters": { ... }
      }
    """
    body = request.get_json(silent=True) or {}
    device_id = body.get("device_id")
    command_type = body.get("command_type")
    parameters = body.get("parameters") or {}
    administrator = body.get("administrator") or "admin"

    if not device_id:
        return make_response(jsonify({"error": "device_id is required.", "status": 400}), 400)
    if not command_type:
        return make_response(jsonify({"error": "command_type is required.", "status": 400}), 400)

    try:
        res = _cmd_service.execute_command(
            device_id=device_id,
            command_type=command_type,
            parameters=parameters,
            administrator=administrator,
        )
        status_code = 200 if res.get("success") else (400 if res.get("status") == "REJECTED" else 200)
        return jsonify(res), status_code

    except ValueError as ve:
        err_msg = str(ve)
        code = 404 if "does not exist" in err_msg else 400
        return make_response(jsonify({"error": err_msg, "status": code}), code)
    except Exception as exc:
        logger.error("Command API execution error: %s", exc, exc_info=True)
        return make_response(jsonify({"error": f"Internal server error: {exc}", "status": 500}), 500)


@commands_bp.route("/history", methods=["GET"])
@require_admin
def get_command_history():
    """
    Retrieve filtered command execution history.
    Query Params: device_id, command_type, status, limit (default: 50).
    """
    device_id = request.args.get("device_id")
    command_type = request.args.get("command_type")
    status = request.args.get("status")
    limit = request.args.get("limit", default=50, type=int)

    try:
        history = _cmd_service.get_command_history(
            device_id=device_id,
            command_type=command_type,
            status=status,
            limit=min(max(limit, 1), 200),
        )
        return jsonify({"history": history, "count": len(history)}), 200
    except Exception as exc:
        logger.error("Command history query error: %s", exc, exc_info=True)
        return make_response(jsonify({"error": str(exc), "status": 500}), 500)


@commands_bp.route("/<command_id>", methods=["GET"])
@require_admin
def get_command_by_id(command_id: str):
    """Retrieve details for an individual command."""
    cmd = _cmd_service.get_command(command_id)
    if not cmd:
        return make_response(jsonify({"error": f"Command '{command_id}' not found.", "status": 404}), 404)
    return jsonify(cmd), 200


@commands_bp.route("/types", methods=["GET"])
@require_admin
def get_allowed_command_types():
    """Return available administrative command definitions."""
    return jsonify({
        "allowed_commands": sorted(list(ALLOWED_COMMANDS)),
        "definitions": {
            "RUN_HEALTH_CHECK": "Queries live metrics and recalculates authoritative device health score.",
            "REAUTHENTICATE_AGENT": "Re-authenticates selected Client Agent and renews session credentials.",
            "SYNCHRONIZE_TIME": "Synchronizes Client Agent clock with Master server.",
            "CONNECTIVITY_CHECK": "Performs authenticated communication and round-trip latency diagnostic.",
            "UPDATE_MONITORING_POLICY": "Configures approved telemetry and event scan intervals safely.",
        }
    }), 200
