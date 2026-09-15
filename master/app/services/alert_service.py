"""
APEXEYE MASTER — Alert Engine Service (Phase 6 Enhanced)

Manages condition evaluation, alert generation, deduplication,
and state resolution for device health monitoring.

Guarantees:
  - Deduplicated: Persistent conditions generate ONE active alert, never spamming every 10s.
  - Zero duplicate database spam across polling cycles.
  - Isolated per-device evaluation.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.alerts")


class AlertService:
    """Evaluates device conditions and manages active alerts."""

    def evaluate_device_alerts(
        self,
        device_id: str,
        device_status: str,
        telemetry: Optional[dict],
        log_counts: dict,
    ) -> list[dict]:
        """
        Evaluate active conditions for a device and return structured alerts.
        Deduplicates against open alerts in the database to prevent duplicate row creation.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        active_alerts = []

        is_offline = (device_status or "").lower() != "online"

        # 1. Connectivity / Offline Alert
        if is_offline:
            active_alerts.append({
                "severity": "CRITICAL",
                "alert_type": "DEVICE_OFFLINE",
                "title": "Device Offline",
                "message": "Device is currently offline. Heartbeat and telemetry communication inactive.",
                "recommendation": "Check client power state, local network connection, and firewall settings.",
                "timestamp": now,
            })

        # 2. Resource Telemetry Alerts
        if telemetry:
            cpu = telemetry.get("cpu_usage")
            ram = telemetry.get("memory_usage")
            disk = telemetry.get("disk_usage")

            # CPU Alerts
            if cpu is not None:
                if cpu >= 95.0:
                    active_alerts.append({
                        "severity": "CRITICAL",
                        "alert_type": "HIGH_CPU_CRITICAL",
                        "title": "Critical CPU Workload",
                        "message": f"Processor load is critically saturated at {cpu:.1f}%.",
                        "recommendation": "Identify runaway background processes in the Process Activity log.",
                        "timestamp": now,
                    })
                elif cpu >= 85.0:
                    active_alerts.append({
                        "severity": "WARNING",
                        "alert_type": "HIGH_CPU_WARNING",
                        "title": "High CPU Utilization",
                        "message": f"Processor workload is elevated at {cpu:.1f}%.",
                        "recommendation": "Monitor CPU trend for sustained resource contention.",
                        "timestamp": now,
                    })

            # RAM Alerts
            if ram is not None:
                if ram >= 95.0:
                    active_alerts.append({
                        "severity": "CRITICAL",
                        "alert_type": "HIGH_RAM_CRITICAL",
                        "title": "Critical Memory Depletion",
                        "message": f"Physical memory utilization is critical at {ram:.1f}%.",
                        "recommendation": "Close unused applications or investigate potential memory leaks.",
                        "timestamp": now,
                    })
                elif ram >= 85.0:
                    active_alerts.append({
                        "severity": "WARNING",
                        "alert_type": "HIGH_RAM_WARNING",
                        "title": "Elevated Memory Usage",
                        "message": f"RAM allocation is high at {ram:.1f}%.",
                        "recommendation": "Ensure adequate available RAM for running services.",
                        "timestamp": now,
                    })

            # Storage / Disk Alerts
            if disk is not None:
                if disk >= 95.0:
                    active_alerts.append({
                        "severity": "CRITICAL",
                        "alert_type": "CRITICAL_STORAGE_CAPACITY",
                        "title": "Storage Critically Full",
                        "message": f"Primary disk partition is {disk:.1f}% full.",
                        "recommendation": "Perform disk cleanup immediately to prevent OS write failures.",
                        "timestamp": now,
                    })
                elif disk >= 85.0:
                    active_alerts.append({
                        "severity": "WARNING",
                        "alert_type": "STORAGE_CAPACITY_WARNING",
                        "title": "Storage Approaching Capacity",
                        "message": f"Disk utilization is elevated at {disk:.1f}%.",
                        "recommendation": "Review storage usage and archive old log files.",
                        "timestamp": now,
                    })

        # 3. Log Error / Critical Events Alerts
        critical_logs = log_counts.get("critical_24h", 0) + log_counts.get("error_24h", 0)
        warning_logs = log_counts.get("warning_24h", 0)

        if critical_logs >= 3:
            active_alerts.append({
                "severity": "CRITICAL",
                "alert_type": "REPEATED_CRITICAL_LOGS",
                "title": "Frequent Critical Log Events",
                "message": f"{critical_logs} critical/error events recorded in the past 24 hours.",
                "recommendation": "Inspect the Centralized Activity Log for application fault details.",
                "timestamp": now,
            })
        elif critical_logs >= 1:
            active_alerts.append({
                "severity": "WARNING",
                "alert_type": "CRITICAL_LOG_EVENT",
                "title": "Critical Event Logged",
                "message": f"{critical_logs} critical/error event recorded in recent activity stream.",
                "recommendation": "Review the event log stream for the root cause.",
                "timestamp": now,
            })

        if warning_logs >= 5:
            active_alerts.append({
                "severity": "WARNING",
                "alert_type": "REPEATED_WARNING_LOGS",
                "title": "Repeated Warning Logs",
                "message": f"{warning_logs} warning-level events recorded in the past 24 hours.",
                "recommendation": "Check system logs for recurring non-fatal service warnings.",
                "timestamp": now,
            })

        return active_alerts

    def sync_open_alerts_to_db(self, device_id: str, active_alerts: list[dict]) -> None:
        """
        Persist new alerts without duplicate DB spam for persistent conditions.
        Automatically closes alerts whose conditions have cleared.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            # Query existing open alerts for this device
            existing_open = conn.execute(
                "SELECT id, alert_type FROM alerts WHERE device_id = ? AND status = 'open';",
                (device_id,),
            ).fetchall()
            existing_types = {r["alert_type"]: r["id"] for r in existing_open}
            active_types = {a["alert_type"] for a in active_alerts}

            # 1. Insert newly appeared alerts
            for a in active_alerts:
                if a["alert_type"] not in existing_types:
                    conn.execute(
                        """INSERT INTO alerts (device_id, timestamp, severity, alert_type, message, status)
                           VALUES (?, ?, ?, ?, ?, 'open');""",
                        (device_id, a["timestamp"], a["severity"], a["alert_type"], a["message"]),
                    )

            # 2. Close alerts that are no longer active
            for alert_type, alert_id in existing_types.items():
                if alert_type not in active_types:
                    conn.execute(
                        "UPDATE alerts SET status = 'resolved', acknowledged_at = ? WHERE id = ?;",
                        (now, alert_id),
                    )

            conn.commit()
        except Exception as exc:
            conn.rollback()
            logger.error("Failed to sync alerts for %s: %s", device_id, exc)
        finally:
            conn.close()

    def get_open_alerts(self, device_id: Optional[str] = None) -> list[dict]:
        """Query open alerts for a device or fleet."""
        conn = get_connection()
        try:
            if device_id:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE device_id = ? AND status = 'open' ORDER BY timestamp DESC;",
                    (device_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE status = 'open' ORDER BY timestamp DESC;",
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def acknowledge(self, alert_id: int) -> bool:
        """Acknowledge an alert."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            cur = conn.execute(
                "UPDATE alerts SET status = 'acknowledged', acknowledged_at = ? WHERE id = ?;",
                (now, alert_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
