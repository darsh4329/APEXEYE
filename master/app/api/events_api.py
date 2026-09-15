"""
APEXEYE MASTER — Events API Routes (Phase 2)

Endpoint for clients to POST process/application events.

POST /api/events — Receive process start/stop events
"""

from flask import Blueprint, request, jsonify, g

from master.app.api.auth_middleware import require_device_auth
from master.app.services.event_service import EventService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.events")

events_bp = Blueprint("events_api", __name__)
_event_svc = EventService()


@events_bp.route("/events", methods=["POST"])
@require_device_auth
def receive_events():
    """
    Receive process/application events from an authenticated client.

    Expected payload:
    {
        "device_id": "...",
        "events": [
            {
                "timestamp": "...",
                "event_type": "process_started",
                "process_name": "notepad.exe",
                "pid": 1234,
                "source": "process_monitor",
                "severity": "info",
                "message": "Application started: notepad.exe (PID 1234)"
            }
        ]
    }
    """
    data = request.get_json(silent=True) or {}
    device_id = g.device_id

    events = data.get("events", [])
    if not isinstance(events, list):
        return jsonify({"error": "events must be a list."}), 400

    if not events:
        return jsonify({"device_id": device_id, "stored": 0}), 200

    # Validate each event has required fields
    for i, event in enumerate(events):
        if not event.get("event_type"):
            return jsonify({
                "error": f"Event at index {i} is missing 'event_type'."
            }), 400

    try:
        result = _event_svc.ingest_events(device_id, events)
        return jsonify(result), 201
    except Exception as exc:
        logger.error("Event ingestion error: %s", exc)
        return jsonify({"error": "Internal server error."}), 500
