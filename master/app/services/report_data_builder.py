"""
APEXEYE MASTER — Report & Analysis Data Builder (Phase 8 & 9)

Extracts and structures isolated data for AI analysis and PDF report generation.
Enforces strict device data isolation (WHERE device_id = ?).
Does not modify any telemetry, logs, presence state, or configuration.
"""

import json
from datetime import datetime, timezone, timedelta
from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.report_data_builder")


class ReportDataBuilder:
    """Builds aggregated, structured data models for analysis and reporting."""

    def normalize_time_range(
        self,
        start_time: str | None = None,
        end_time: str | None = None,
        default_hours: int = 24,
    ) -> tuple[str, str]:
        """
        Normalize and validate start/end ISO/SQL datetime strings.
        Ensures start_time < end_time.
        """
        now = datetime.now(timezone.utc)
        if not end_time:
            end_dt = now
        else:
            try:
                end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                if end_dt.tzinfo is None:
                    end_dt = end_dt.replace(tzinfo=timezone.utc)
            except Exception:
                end_dt = now

        if not start_time:
            start_dt = end_dt - timedelta(hours=default_hours)
        else:
            try:
                start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                if start_dt.tzinfo is None:
                    start_dt = start_dt.replace(tzinfo=timezone.utc)
            except Exception:
                start_dt = end_dt - timedelta(hours=default_hours)

        if start_dt >= end_dt:
            start_dt = end_dt - timedelta(hours=default_hours)

        s_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        e_str = end_dt.strftime("%Y-%m-%d %H:%M:%S")
        return s_str, e_str

    def build_single_device_data(
        self,
        device_id: str,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict:
        """
        Extract telemetry history, event logs, lifecycle events, and metadata
        with strict per-device isolation (WHERE device_id = ?).
        """
        start_str, end_str = self.normalize_time_range(start_time, end_time)
        conn = get_connection()
        try:
            # 1. Device Metadata
            dev_row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?;",
                (device_id,),
            ).fetchone()

            if not dev_row:
                return {
                    "error": f"Device {device_id} not found",
                    "device_id": device_id,
                    "exists": False,
                }

            device = dict(dev_row)

            # 2. Telemetry History within range (strict isolation)
            tel_rows = conn.execute(
                """SELECT id, device_id, timestamp, cpu_usage, memory_usage,
                          disk_usage, network_usage, health_score
                   FROM telemetry
                   WHERE device_id = ? AND timestamp >= ? AND timestamp <= ?
                   ORDER BY timestamp ASC;""",
                (device_id, start_str, end_str),
            ).fetchall()
            telemetry_records = [dict(r) for r in tel_rows]

            # 3. Latest Telemetry Snapshot (for thermal / detailed metrics)
            latest_tel_row = conn.execute(
                """SELECT * FROM telemetry WHERE device_id = ?
                   ORDER BY timestamp DESC, id DESC LIMIT 1;""",
                (device_id,),
            ).fetchone()
            latest_telemetry = None
            if latest_tel_row:
                latest_telemetry = dict(latest_tel_row)
                if latest_telemetry.get("details"):
                    try:
                        latest_telemetry["details"] = json.loads(latest_telemetry["details"])
                    except Exception:
                        pass

            # 4. Logs & Events within range (strict isolation)
            log_rows = conn.execute(
                """SELECT id, device_id, timestamp, level, severity, event_type,
                          category, application_name, message, details, source
                   FROM logs
                   WHERE device_id = ? AND timestamp >= ? AND timestamp <= ?
                   ORDER BY timestamp ASC;""",
                (device_id, start_str, end_str),
            ).fetchall()
            logs = [dict(r) for r in log_rows]

            # 5. Open Alerts
            alert_rows = conn.execute(
                """SELECT id, device_id, timestamp, severity, alert_type, message, status
                   FROM alerts
                   WHERE device_id = ? AND status = 'open'
                   ORDER BY timestamp DESC;""",
                (device_id,),
            ).fetchall()
            active_alerts = [dict(r) for r in alert_rows]

            # 6. Aggregate Statistics
            cpu_vals = [t["cpu_usage"] for t in telemetry_records if t.get("cpu_usage") is not None]
            ram_vals = [t["memory_usage"] for t in telemetry_records if t.get("memory_usage") is not None]
            disk_vals = [t["disk_usage"] for t in telemetry_records if t.get("disk_usage") is not None]
            net_vals = [t["network_usage"] for t in telemetry_records if t.get("network_usage") is not None]

            stats = {
                "telemetry_count": len(telemetry_records),
                "log_count": len(logs),
                "cpu_avg": round(sum(cpu_vals) / len(cpu_vals), 1) if cpu_vals else None,
                "cpu_max": max(cpu_vals) if cpu_vals else None,
                "cpu_min": min(cpu_vals) if cpu_vals else None,
                "ram_avg": round(sum(ram_vals) / len(ram_vals), 1) if ram_vals else None,
                "ram_max": max(ram_vals) if ram_vals else None,
                "disk_avg": round(sum(disk_vals) / len(disk_vals), 1) if disk_vals else None,
                "disk_max": max(disk_vals) if disk_vals else None,
                "net_avg": round(sum(net_vals) / len(net_vals), 2) if net_vals else None,
                "critical_log_count": sum(1 for l in logs if l.get("severity") == "CRITICAL" or l.get("level") == "CRITICAL"),
                "warning_log_count": sum(1 for l in logs if l.get("severity") == "WARNING" or l.get("level") == "WARNING"),
                "error_log_count": sum(1 for l in logs if l.get("severity") == "ERROR" or l.get("level") == "ERROR"),
            }

            # 7. Application Lifecycle Summary
            apps_started = [l for l in logs if l.get("event_type") == "APPLICATION_STARTED"]
            apps_stopped = [l for l in logs if l.get("event_type") == "APPLICATION_STOPPED"]
            app_start_counts = {}
            for l in apps_started:
                app_name = l.get("application_name") or "Unknown"
                app_start_counts[app_name] = app_start_counts.get(app_name, 0) + 1

            app_summary = {
                "total_starts": len(apps_started),
                "total_stops": len(apps_stopped),
                "app_frequencies": app_start_counts,
                "recent_lifecycle": logs[-20:] if logs else [],
            }

            return {
                "exists": True,
                "device": device,
                "start_time": start_str,
                "end_time": end_str,
                "stats": stats,
                "telemetry": telemetry_records,
                "latest_telemetry": latest_telemetry,
                "logs": logs,
                "active_alerts": active_alerts,
                "app_summary": app_summary,
            }
        finally:
            conn.close()

    def build_multi_device_data(
        self,
        device_ids: list[str],
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict:
        """
        Build aggregated dataset for a selected set of devices.
        Preserves individual per-device datasets while providing fleet summaries.
        """
        start_str, end_str = self.normalize_time_range(start_time, end_time)
        devices_data = {}
        for did in device_ids:
            did_clean = str(did).strip()
            if did_clean:
                devices_data[did_clean] = self.build_single_device_data(did_clean, start_str, end_str)

        return {
            "scope": "selected_devices",
            "start_time": start_str,
            "end_time": end_str,
            "device_count": len(devices_data),
            "devices": devices_data,
        }

    def build_system_data(
        self,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict:
        """
        Build full system dataset covering all registered devices and system totals.
        """
        start_str, end_str = self.normalize_time_range(start_time, end_time)
        conn = get_connection()
        try:
            dev_rows = conn.execute("SELECT device_id FROM devices;").fetchall()
            all_ids = [r["device_id"] for r in dev_rows]

            # CCTV summary
            cctv_rows = conn.execute("SELECT * FROM cctv_devices;").fetchall()
            cctvs = [dict(r) for r in cctv_rows]
        finally:
            conn.close()

        devices_data = {}
        for did in all_ids:
            devices_data[did] = self.build_single_device_data(did, start_str, end_str)

        return {
            "scope": "system",
            "start_time": start_str,
            "end_time": end_str,
            "total_devices": len(all_ids),
            "devices": devices_data,
            "cctv_devices": cctvs,
            "aws_cloud": self.build_aws_data(),
        }

    def build_aws_data(self) -> dict:
        """
        Build isolated dataset of discovered AWS EC2 instances and recent metrics.
        Never includes secrets or credentials.
        """
        conn = get_connection()
        try:
            cfg = conn.execute(
                "SELECT credential_mode, region, account_id, connection_status, last_tested_at "
                "FROM aws_config ORDER BY id DESC LIMIT 1;"
            ).fetchone()
            inst_rows = conn.execute(
                "SELECT * FROM aws_instances ORDER BY name ASC, instance_id ASC;"
            ).fetchall()
            instances = [dict(r) for r in inst_rows]
            return {
                "source": "AWS EC2",
                "config": dict(cfg) if cfg else None,
                "instance_count": len(instances),
                "instances": instances,
            }
        except Exception:
            return {"source": "AWS EC2", "instance_count": 0, "instances": []}
        finally:
            conn.close()

