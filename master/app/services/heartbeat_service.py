"""
APEXEYE MASTER — Heartbeat Service (Phase 2)

Processes heartbeat signals from Client agents.
Updates device last_seen and status.
"""

from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.heartbeat")


class HeartbeatService:
    """Processes heartbeat signals from Client agents."""

    def process_heartbeat(self, device_id: str, payload: dict) -> dict:
        """
        Process a heartbeat from a client.

        Updates:
          - Device last_seen timestamp
          - Device status to 'online'
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        client_status = payload.get("client_status", "unknown")
        client_timestamp = payload.get("timestamp", now)

        conn = get_connection()
        try:
            # Update device
            conn.execute(
                "UPDATE devices SET last_seen = ?, status = 'online', "
                "updated_at = ? WHERE device_id = ?;",
                (now, now, device_id),
            )
            conn.commit()

            logger.debug(
                "Heartbeat received from device %s (status: %s)",
                device_id, client_status,
            )

            return {
                "device_id": device_id,
                "status": "acknowledged",
                "server_time": now,
                "client_status": client_status,
            }

        except Exception as exc:
            conn.rollback()
            logger.error(
                "Failed to process heartbeat for %s: %s", device_id, exc
            )
            raise
        finally:
            conn.close()
