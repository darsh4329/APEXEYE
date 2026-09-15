"""
APEXEYE MASTER — Event Ingestion Service (Phase 2)

Receives process/application lifecycle events from Client agents
and stores them in the existing 'logs' table.

Process events are stored as log entries with:
  - level = severity (info/warning/error)
  - event_type = process_started / process_stopped
  - message = descriptive message (includes process name and PID)
  - source = process_monitor
"""

from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.event")


class EventService:
    """Receives and stores process/application events using the logs table."""

    def ingest_events(self, device_id: str, events: list[dict]) -> dict:
        """
        Store a batch of process/application events in the logs table.

        Each event should contain:
          - timestamp
          - event_type (process_started / process_stopped)
          - process_name
          - pid
          - source
          - severity
          - message
        """
        if not events:
            return {"device_id": device_id, "stored": 0}

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        stored = 0

        try:
            device_row = conn.execute(
                "SELECT device_type FROM devices WHERE device_id = ?;", (device_id,)
            ).fetchone()
            device_type = device_row["device_type"] if device_row else "OTHER"

            for event in events:
                raw_sev = str(event.get("severity", "INFO")).upper()
                severity = raw_sev if raw_sev in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO"
                app_name = event.get("application_name") or event.get("process_name")
                event_type = event.get("event_type", "unknown")
                category = event.get("category", "APPLICATION")
                evt_ts = event.get("timestamp", now)
                evt_msg = event.get("message", "")

                # Safe deduplication: skip if identical event was already recorded
                existing = conn.execute(
                    """SELECT id FROM logs
                       WHERE device_id = ? AND timestamp = ? AND event_type = ? AND message = ?
                       LIMIT 1;""",
                    (device_id, evt_ts, event_type, evt_msg),
                ).fetchone()
                if existing:
                    continue

                conn.execute(
                    """INSERT INTO logs
                       (device_id, device_type, timestamp, level, severity,
                        event_type, category, application_name, message, source, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        device_id,
                        device_type,
                        evt_ts,
                        severity,
                        severity,
                        event_type,
                        category,
                        app_name,
                        evt_msg,
                        event.get("source", "process_monitor"),
                        now,
                    ),
                )
                stored += 1

            # Update device status and last_seen
            conn.execute(
                "UPDATE devices SET status = 'online', last_seen = ?, updated_at = ? "
                "WHERE device_id = ?;",
                (now, now, device_id),
            )
            conn.commit()

            logger.info(
                "Stored %d event(s) for device %s", stored, device_id
            )
            return {"device_id": device_id, "stored": stored}

        except Exception as exc:
            conn.rollback()
            logger.error(
                "Failed to ingest events for %s: %s", device_id, exc
            )
            raise
        finally:
            conn.close()

    def get_recent_events(
        self, device_id: str, limit: int = 50
    ) -> list[dict]:
        """Return the most recent process events for a device."""
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM logs WHERE device_id = ? "
                "AND event_type IN ('process_started', 'process_stopped') "
                "ORDER BY timestamp DESC LIMIT ?;",
                (device_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
