"""
APEXEYE MASTER — Telemetry Ingestion Service (Phase 2)

Receives and stores telemetry data from Client agents.
Stores summary metrics in the existing 'telemetry' table columns
and the full JSON payload in the 'details' column.
"""

import json
from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.telemetry")


class TelemetryService:
    """Receives and stores telemetry data from Client agents."""

    def ingest(self, device_id: str, payload: dict) -> dict:
        """
        Store a telemetry snapshot from a client.

        Writes summary metrics to the existing 'telemetry' table columns
        and the full JSON detail to the 'details' column.
        Also updates the device's last_seen and sets status to 'online'.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        timestamp = payload.get("timestamp", now)

        # Extract summary metrics
        cpu_data = payload.get("cpu", {})
        memory_data = payload.get("memory", {})
        disk_data = payload.get("disk", {})
        network_data = payload.get("network", {})

        cpu_usage = cpu_data.get("cpu_usage")
        memory_usage = memory_data.get("memory_usage_percent")
        disk_usage = disk_data.get("disk_usage_percent")
        network_sent = network_data.get("network_bytes_sent_mb")
        network_recv = network_data.get("network_bytes_recv_mb")
        network_usage = (network_sent or 0) + (network_recv or 0)

        # Structured telemetry values
        mem_total = memory_data.get("memory_total_gb")
        mem_used = memory_data.get("memory_used_gb")
        disk_total = disk_data.get("disk_total_gb")
        disk_free = disk_data.get("disk_free_gb")

        # Full detail as JSON in 'details' column
        details_json = json.dumps({
            "cpu": cpu_data,
            "memory": memory_data,
            "disk": disk_data,
            "network": network_data,
        })

        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO telemetry
                   (device_id, timestamp, cpu_usage, memory_usage,
                    disk_usage, network_usage, details,
                    memory_total_gb, memory_used_gb, disk_total_gb, disk_free_gb,
                    network_bytes_sent_mb, network_bytes_recv_mb)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    device_id, timestamp, cpu_usage, memory_usage,
                    disk_usage, network_usage, details_json,
                    mem_total, mem_used, disk_total, disk_free,
                    network_sent, network_recv,
                ),
            )

            # Check for high resource usage threshold warnings (> 90%)
            warning_logs = []
            if cpu_usage is not None and cpu_usage >= 90.0:
                warning_logs.append((
                    device_id, timestamp, "WARNING", "WARNING", "CPU_WARNING", "SYSTEM",
                    f"High CPU utilization alert: {cpu_usage:.1f}%",
                    json.dumps({"cpu_usage": cpu_usage}),
                ))
            if memory_usage is not None and memory_usage >= 90.0:
                warning_logs.append((
                    device_id, timestamp, "WARNING", "WARNING", "MEMORY_WARNING", "SYSTEM",
                    f"High RAM utilization alert: {memory_usage:.1f}% ({mem_used or 0:.1f} / {mem_total or 0:.1f} GB)",
                    json.dumps({"memory_usage_percent": memory_usage, "used_gb": mem_used, "total_gb": mem_total}),
                ))
            if disk_usage is not None and disk_usage >= 90.0:
                warning_logs.append((
                    device_id, timestamp, "WARNING", "WARNING", "DISK_WARNING", "SYSTEM",
                    f"High Disk utilization alert: {disk_usage:.1f}% ({disk_free or 0:.1f} GB free)",
                    json.dumps({"disk_usage_percent": disk_usage, "free_gb": disk_free}),
                ))

            for w in warning_logs:
                conn.execute(
                    """INSERT INTO logs
                       (device_id, timestamp, level, severity, event_type, category, message, details, source, created_at)
                       VALUES (?,?,?,?,?,?,?,'telemetry_monitor',?,?)""",
                    (w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], now),
                )

            # Update device status and last_seen
            conn.execute(
                "UPDATE devices SET status = 'online', last_seen = ?, "
                "updated_at = ? WHERE device_id = ?;",
                (now, now, device_id),
            )
            conn.commit()

            logger.info(
                "Telemetry ingested for device %s: CPU=%.1f%%, RAM=%.1f%%, Disk=%.1f%%",
                device_id,
                cpu_usage or 0,
                memory_usage or 0,
                disk_usage or 0,
            )

            return {
                "device_id": device_id,
                "timestamp": timestamp,
                "status": "stored",
            }

        except Exception as exc:
            conn.rollback()
            logger.error("Failed to ingest telemetry for %s: %s", device_id, exc)
            raise
        finally:
            conn.close()

    def get_latest(self, device_id: str) -> dict | None:
        """Return the most recent telemetry for a device."""
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM telemetry WHERE device_id = ? "
                "ORDER BY timestamp DESC LIMIT 1;",
                (device_id,),
            ).fetchone()
            if not row:
                return None

            result = dict(row)
            # Parse JSON details if present
            if result.get("details"):
                try:
                    result["details"] = json.loads(result["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            return result
        finally:
            conn.close()
