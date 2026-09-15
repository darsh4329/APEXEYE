"""
APEXEYE MASTER — Device Health Score & Risk Assessment Service (Phase 6)

Computes a deterministic, explainable, and real-data-backed Health Score (0–100)
for client devices based on:
  - Resource Health (40%): CPU, RAM, Disk utilization
  - Log / Error Health (30%): Frequency and recency of Warning / Error / Critical logs
  - Connectivity Health (20%): Online presence and communication stability
  - Trend / Stability (10%): Telemetry variance and sustained workload trajectory

States:
  🟢 GOOD: 80–100
  🟡 WARNING: 50–79
  🔴 CRITICAL: 0–49

Mandatory Safety Rules:
  - OFFLINE OVERRIDE: If device is offline, final score is capped at 49 and status is CRITICAL.
  - Zero presence system modification: Reads presence state only.
  - Zero fake values: Real thermal data if present, else marked 'Not available'.
  - Strict device data isolation: Client A only evaluates Client A's logs and metrics.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from master.app.database import get_connection
from master.app.services.alert_service import AlertService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.health")


class HealthService:
    """Calculates comprehensive, explainable health scores and risk assessments."""

    def __init__(self):
        self._alert_svc = AlertService()

    def evaluate_device_health(self, device_id: str, persist_alerts: bool = True) -> Optional[dict]:
        """
        Evaluate full health score, resource breakdown, log health, connectivity,
        explainable factors, and active alerts for a single device.
        """
        conn = get_connection()
        try:
            device_row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?;", (device_id,)
            ).fetchone()
            if not device_row:
                return None

            device = dict(device_row)
            is_online = (device.get("status") or "").lower() == "online"
            last_seen = device.get("last_seen")

            # 1. Fetch latest telemetry snapshot
            tel_row = conn.execute(
                """SELECT * FROM telemetry WHERE device_id = ?
                   ORDER BY timestamp DESC, id DESC LIMIT 1;""",
                (device_id,),
            ).fetchone()

            telemetry = None
            if tel_row:
                telemetry = dict(tel_row)
                if telemetry.get("details"):
                    try:
                        telemetry["details"] = json.loads(telemetry["details"])
                    except Exception:
                        pass

            # 2. Fetch recent telemetry records for trend evaluation
            hist_rows = conn.execute(
                """SELECT cpu_usage, memory_usage, disk_usage, timestamp
                   FROM telemetry WHERE device_id = ?
                   ORDER BY timestamp DESC, id DESC LIMIT 10;""",
                (device_id,),
            ).fetchall()
            recent_telemetries = [dict(r) for r in hist_rows]

            # 3. Query historical logs for this specific client (Strict Isolation!)
            log_stats = self._query_client_log_stats(conn, device_id)

        finally:
            conn.close()

        # ── Component Evaluations ───────────────────────────────────
        resource_eval = self._evaluate_resources(telemetry)
        log_eval = self._evaluate_logs(log_stats)
        conn_eval = self._evaluate_connectivity(is_online, last_seen)
        trend_eval = self._evaluate_trend(recent_telemetries)

        # ── Weighted Overall Calculation ────────────────────────────
        explanations = []

        if resource_eval["available"]:
            res_score = resource_eval["score"]
            raw_score = (
                0.40 * res_score +
                0.30 * log_eval["score"] +
                0.20 * conn_eval["score"] +
                0.10 * trend_eval["score"]
            )
            # Component-level capping: Saturated/elevated resources prevent false 'GOOD'
            if res_score <= 40.0:
                raw_score = min(raw_score, 49.0)
            elif res_score <= 75.0:
                raw_score = min(raw_score, 79.0)
        else:
            # Telemetry unavailable: scale across logs, connectivity, trend
            raw_score = (
                0.50 * log_eval["score"] +
                0.35 * conn_eval["score"] +
                0.15 * trend_eval["score"]
            )

        calculated_score = int(round(raw_score))
        calculated_score = max(0, min(100, calculated_score))

        # ── MANDATORY OFFLINE OVERRIDE ──────────────────────────────
        # An offline device must NEVER appear as GOOD or WARNING.
        # Health classification must be CRITICAL and score capped at 49.
        if not is_online:
            final_score = min(calculated_score, 49)
            final_status = "CRITICAL"
            status_badge = "🔴 CRITICAL"
            explanations.append({
                "factor": "connectivity",
                "severity": "CRITICAL",
                "icon": "🔴",
                "text": "🔴 Device is currently offline.",
            })
        else:
            final_score = calculated_score
            if final_score >= 80:
                final_status = "GOOD"
                status_badge = "🟢 GOOD"
            elif final_score >= 50:
                final_status = "WARNING"
                status_badge = "🟡 WARNING"
            else:
                final_status = "CRITICAL"
                status_badge = "🔴 CRITICAL"

            explanations.append({
                "factor": "connectivity",
                "severity": "INFO",
                "icon": "🟢",
                "text": "🟢 Device is actively online and communicating.",
            })

        # Add Resource Explanations
        for exp in resource_eval["explanations"]:
            explanations.append(exp)

        # Add Log Explanations
        for exp in log_eval["explanations"]:
            explanations.append(exp)

        # Add Trend Explanation
        explanations.append(trend_eval["explanation"])

        # ── Active Alerts ───────────────────────────────────────────
        active_alerts = self._alert_svc.evaluate_device_alerts(
            device_id=device_id,
            device_status=device.get("status", "inactive"),
            telemetry=telemetry,
            log_counts=log_stats,
        )

        if persist_alerts:
            self._alert_svc.sync_open_alerts_to_db(device_id, active_alerts)

        # ── Thermal Telemetry (Real or 'Not available') ─────────────
        thermal_info = self._extract_thermal_info(telemetry)

        # ── Human-Readable Health Summary ───────────────────────────
        summary = self._generate_health_summary(
            score=final_score,
            status=final_status,
            is_online=is_online,
            resource_eval=resource_eval,
            log_eval=log_eval,
            active_alerts=active_alerts,
        )

        evaluated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        return {
            "device_id": device_id,
            "device_name": device.get("device_name", device_id),
            "device_type": device.get("device_type", "OTHER"),
            "operating_system": device.get("operating_system", "Unknown"),
            "ip_address": device.get("ip_address", "—"),
            "hostname": device.get("hostname", "—"),
            "status": final_status,
            "status_badge": status_badge,
            "score": final_score,
            "raw_score": calculated_score,
            "is_online": is_online,
            "evaluated_at": evaluated_at,
            "components": {
                "resources": resource_eval,
                "logs": log_eval,
                "connectivity": conn_eval,
                "trend": trend_eval,
                "thermal": thermal_info,
            },
            "explanations": explanations,
            "alerts": active_alerts,
            "alerts_count": len(active_alerts),
            "summary": summary,
        }

    # ── Internal Evaluator Helpers ──────────────────────────────────

    def _evaluate_resources(self, telemetry: Optional[dict]) -> dict:
        """Evaluate CPU, RAM, and Disk metrics."""
        if not telemetry:
            return {
                "available": False,
                "score": 100,
                "cpu": {"usage": None, "score": None, "status": "N/A", "display": "Data unavailable"},
                "ram": {"usage": None, "score": None, "status": "N/A", "display": "Data unavailable"},
                "storage": {"usage": None, "score": None, "status": "N/A", "display": "Data unavailable"},
                "network": {"sent_mb": None, "recv_mb": None, "display": "Data unavailable"},
                "explanations": [{
                    "factor": "resources",
                    "severity": "INFO",
                    "icon": "⚪",
                    "text": "⚪ Telemetry resource data is not yet recorded.",
                }],
            }

        cpu = telemetry.get("cpu_usage")
        ram = telemetry.get("memory_usage")
        disk = telemetry.get("disk_usage")

        explanations = []

        # 1. CPU Score
        if cpu is not None:
            cpu = float(cpu)
            if cpu < 70.0:
                cpu_score = 100.0
                cpu_status = "HEALTHY"
                explanations.append({"factor": "cpu", "severity": "INFO", "icon": "🟢", "text": f"🟢 CPU is operating normally ({cpu:.1f}%)"})
            elif cpu < 85.0:
                cpu_score = 75.0
                cpu_status = "WARNING"
                explanations.append({"factor": "cpu", "severity": "WARNING", "icon": "🟡", "text": f"🟡 CPU utilization is elevated ({cpu:.1f}%)"})
            elif cpu < 95.0:
                cpu_score = 40.0
                cpu_status = "SERIOUS"
                explanations.append({"factor": "cpu", "severity": "WARNING", "icon": "🟡", "text": f"🟡 CPU workload is high ({cpu:.1f}%)"})
            else:
                cpu_score = 10.0
                cpu_status = "CRITICAL"
                explanations.append({"factor": "cpu", "severity": "CRITICAL", "icon": "🔴", "text": f"🔴 CPU utilization is critically saturated ({cpu:.1f}%)"})
            cpu_display = f"{cpu:.1f}%"
        else:
            cpu_score = 100.0
            cpu_status = "N/A"
            cpu_display = "Data unavailable"

        # 2. RAM Score
        if ram is not None:
            ram = float(ram)
            if ram < 70.0:
                ram_score = 100.0
                ram_status = "HEALTHY"
                explanations.append({"factor": "ram", "severity": "INFO", "icon": "🟢", "text": f"🟢 RAM utilization is healthy ({ram:.1f}%)"})
            elif ram < 85.0:
                ram_score = 75.0
                ram_status = "WARNING"
                explanations.append({"factor": "ram", "severity": "WARNING", "icon": "🟡", "text": f"🟡 RAM utilization is elevated ({ram:.1f}%)"})
            elif ram < 95.0:
                ram_score = 40.0
                ram_status = "SERIOUS"
                explanations.append({"factor": "ram", "severity": "WARNING", "icon": "🟡", "text": f"🟡 RAM memory allocation is high ({ram:.1f}%)"})
            else:
                ram_score = 10.0
                ram_status = "CRITICAL"
                explanations.append({"factor": "ram", "severity": "CRITICAL", "icon": "🔴", "text": f"🔴 RAM memory is critically depleted ({ram:.1f}%)"})
            ram_display = f"{ram:.1f}%"
        else:
            ram_score = 100.0
            ram_status = "N/A"
            ram_display = "Data unavailable"

        # 3. Disk / Storage Score
        if disk is not None:
            disk = float(disk)
            if disk < 70.0:
                disk_score = 100.0
                disk_status = "HEALTHY"
                explanations.append({"factor": "storage", "severity": "INFO", "icon": "🟢", "text": f"🟢 Storage usage is healthy ({disk:.1f}% used)"})
            elif disk < 85.0:
                disk_score = 75.0
                disk_status = "WARNING"
                explanations.append({"factor": "storage", "severity": "WARNING", "icon": "🟡", "text": f"🟡 Storage usage is moderately high ({disk:.1f}% used)"})
            elif disk < 95.0:
                disk_score = 40.0
                disk_status = "SERIOUS"
                explanations.append({"factor": "storage", "severity": "WARNING", "icon": "🟡", "text": f"🟡 Storage capacity approaching limit ({disk:.1f}% used)"})
            else:
                disk_score = 10.0
                disk_status = "CRITICAL"
                explanations.append({"factor": "storage", "severity": "CRITICAL", "icon": "🔴", "text": f"🔴 Storage is critically full ({disk:.1f}% used)"})
            disk_display = f"{disk:.1f}%"
        else:
            disk_score = 100.0
            disk_status = "N/A"
            disk_display = "Data unavailable"

        # Weighted resource sub-score
        weighted_res = (0.35 * cpu_score) + (0.35 * ram_score) + (0.30 * disk_score)

        return {
            "available": True,
            "score": round(weighted_res, 1),
            "cpu": {
                "usage": cpu,
                "score": cpu_score,
                "status": cpu_status,
                "display": cpu_display,
            },
            "ram": {
                "usage": ram,
                "score": ram_score,
                "status": ram_status,
                "display": ram_display,
                "used_gb": telemetry.get("memory_used_gb"),
                "total_gb": telemetry.get("memory_total_gb"),
            },
            "storage": {
                "usage": disk,
                "score": disk_score,
                "status": disk_status,
                "display": disk_display,
                "free_gb": telemetry.get("disk_free_gb"),
                "total_gb": telemetry.get("disk_total_gb"),
            },
            "network": {
                "sent_mb": telemetry.get("network_bytes_sent_mb"),
                "recv_mb": telemetry.get("network_bytes_recv_mb"),
                "display": f"Sent: {float(telemetry.get('network_bytes_sent_mb') or 0.0):.1f} MB | Recv: {float(telemetry.get('network_bytes_recv_mb') or 0.0):.1f} MB",
            },
            "explanations": explanations,
        }

    def _query_client_log_stats(self, conn, device_id: str) -> dict:
        """Query isolated logs statistics for this device."""
        now_utc = datetime.now(timezone.utc)
        t_1h = (now_utc - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        t_24h = (now_utc - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

        # Counts within last 1 hour
        c_1h = conn.execute(
            """SELECT severity, COUNT(*) as c FROM logs
               WHERE device_id = ? AND timestamp >= ?
               GROUP BY severity;""",
            (device_id, t_1h),
        ).fetchall()
        sev_1h = {r["severity"].upper(): r["c"] for r in c_1h}

        # Counts within last 24 hours
        c_24h = conn.execute(
            """SELECT severity, COUNT(*) as c FROM logs
               WHERE device_id = ? AND timestamp >= ?
               GROUP BY severity;""",
            (device_id, t_24h),
        ).fetchall()
        sev_24h = {r["severity"].upper(): r["c"] for r in c_24h}

        # Total historical counts
        c_tot = conn.execute(
            """SELECT severity, COUNT(*) as c FROM logs
               WHERE device_id = ?
               GROUP BY severity;""",
            (device_id,),
        ).fetchall()
        sev_tot = {r["severity"].upper(): r["c"] for r in c_tot}

        return {
            "warning_1h": sev_1h.get("WARNING", 0),
            "error_1h": sev_1h.get("ERROR", 0),
            "critical_1h": sev_1h.get("CRITICAL", 0),
            "warning_24h": sev_24h.get("WARNING", 0),
            "error_24h": sev_24h.get("ERROR", 0),
            "critical_24h": sev_24h.get("CRITICAL", 0),
            "info_24h": sev_24h.get("INFO", 0),
            "total_warnings": sev_tot.get("WARNING", 0),
            "total_criticals": sev_tot.get("CRITICAL", 0) + sev_tot.get("ERROR", 0),
            "total_logs": sum(sev_tot.values()),
        }

    def _evaluate_logs(self, log_stats: dict) -> dict:
        """
        Evaluate log health score with recency weighting and
        protection against single-event score cliff destruction.
        """
        w_1h = log_stats.get("warning_1h", 0)
        c_1h = log_stats.get("critical_1h", 0) + log_stats.get("error_1h", 0)

        w_rest = max(0, log_stats.get("warning_24h", 0) - w_1h)
        c_rest = max(0, log_stats.get("critical_24h", 0) + log_stats.get("error_24h", 0) - c_1h)

        # Recency weighting
        # Recent (<1h): Warning = -6, Critical = -18
        # Older (1-24h): Warning = -3.5, Critical = -10
        penalty = (w_1h * 6.0) + (c_1h * 18.0) + (w_rest * 3.5) + (c_rest * 10.0)
        log_score = max(0.0, min(100.0, 100.0 - penalty))

        explanations = []
        tot_crit_24 = log_stats.get("critical_24h", 0) + log_stats.get("error_24h", 0)
        tot_warn_24 = log_stats.get("warning_24h", 0)

        if tot_crit_24 > 0:
            explanations.append({
                "factor": "logs",
                "severity": "CRITICAL",
                "icon": "🔴",
                "text": f"🔴 {tot_crit_24} critical/error event(s) detected in last 24 hours",
            })
        elif tot_warn_24 > 0:
            explanations.append({
                "factor": "logs",
                "severity": "WARNING",
                "icon": "🟡",
                "text": f"🟡 {tot_warn_24} warning event(s) detected in last 24 hours",
            })
        else:
            explanations.append({
                "factor": "logs",
                "severity": "INFO",
                "icon": "🟢",
                "text": "🟢 Zero warning or critical log events in last 24 hours",
            })

        return {
            "score": round(log_score, 1),
            "warnings_24h": tot_warn_24,
            "critical_24h": tot_crit_24,
            "info_24h": log_stats.get("info_24h", 0),
            "total_logs": log_stats.get("total_logs", 0),
            "explanations": explanations,
        }

    def _evaluate_connectivity(self, is_online: bool, last_seen: Optional[str]) -> dict:
        """Evaluate connectivity & presence health."""
        if is_online:
            return {
                "score": 100.0,
                "status": "ONLINE",
                "stability": "STABLE",
                "display": "Connected (Live)",
            }
        else:
            return {
                "score": 15.0,
                "status": "OFFLINE",
                "stability": "DISCONNECTED",
                "display": f"Offline (Last seen: {last_seen or 'Unknown'})",
            }

    def _evaluate_trend(self, recent_telemetries: list[dict]) -> dict:
        """Evaluate workload trajectory and stability across recent snapshots."""
        if not recent_telemetries or len(recent_telemetries) < 2:
            return {
                "score": 100.0,
                "trend": "STABLE",
                "explanation": {
                    "factor": "trend",
                    "severity": "INFO",
                    "icon": "🟢",
                    "text": "🟢 Resource trend and telemetry stream are steady",
                },
            }

        cpu_vals = [r["cpu_usage"] for r in recent_telemetries if r.get("cpu_usage") is not None]
        ram_vals = [r["memory_usage"] for r in recent_telemetries if r.get("memory_usage") is not None]

        avg_cpu = sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0
        avg_ram = sum(ram_vals) / len(ram_vals) if ram_vals else 0

        if avg_cpu >= 90.0 or avg_ram >= 90.0:
            return {
                "score": 40.0,
                "trend": "SUSTAINED_OVERLOAD",
                "explanation": {
                    "factor": "trend",
                    "severity": "WARNING",
                    "icon": "🟡",
                    "text": "🟡 Sustained high workload observed across recent telemetry cycles",
                },
            }
        elif avg_cpu >= 75.0 or avg_ram >= 75.0:
            return {
                "score": 75.0,
                "trend": "ELEVATED",
                "explanation": {
                    "factor": "trend",
                    "severity": "WARNING",
                    "icon": "🟡",
                    "text": "🟡 Moderately elevated load observed across recent cycles",
                },
            }
        else:
            return {
                "score": 100.0,
                "trend": "STABLE",
                "explanation": {
                    "factor": "trend",
                    "severity": "INFO",
                    "icon": "🟢",
                    "text": "🟢 Resource trend and operational stability are optimal",
                },
            }

    def _extract_thermal_info(self, telemetry: Optional[dict]) -> dict:
        """
        Extract real temperature if reported by the client;
        never invent fake thermal data.
        """
        if telemetry and telemetry.get("details"):
            details = telemetry["details"]
            if isinstance(details, dict):
                temp = (
                    details.get("temperature") or
                    details.get("thermal", {}).get("temperature_c") or
                    details.get("cpu", {}).get("temperature_c")
                )
                if temp is not None:
                    return {
                        "available": True,
                        "temperature_c": float(temp),
                        "status": "NORMAL" if float(temp) < 75.0 else "HIGH",
                        "display": f"{float(temp):.1f}°C (Normal)",
                    }

        return {
            "available": False,
            "temperature_c": None,
            "status": "N/A",
            "display": "Thermal data: Not available",
        }

    def _generate_health_summary(
        self,
        score: int,
        status: str,
        is_online: bool,
        resource_eval: dict,
        log_eval: dict,
        active_alerts: list[dict],
    ) -> str:
        """Produce an executive human-readable health assessment summary."""
        if not is_online:
            return "Device is currently OFFLINE. Presence and telemetry stream are inactive. Investigation required."

        if status == "GOOD":
            if active_alerts:
                return "Device is operating with acceptable health. Minor advisory conditions detected."
            return "Device is operating normally. All core resources, event streams, and connectivity are healthy."

        if status == "WARNING":
            reasons = []
            if resource_eval["available"]:
                if resource_eval["cpu"]["status"] in ("WARNING", "SERIOUS", "CRITICAL"):
                    reasons.append("elevated CPU utilization")
                if resource_eval["ram"]["status"] in ("WARNING", "SERIOUS", "CRITICAL"):
                    reasons.append("high memory consumption")
                if resource_eval["storage"]["status"] in ("WARNING", "SERIOUS", "CRITICAL"):
                    reasons.append("storage capacity limits")
            if log_eval["warnings_24h"] > 0:
                reasons.append(f"{log_eval['warnings_24h']} warning event(s)")
            if log_eval["critical_24h"] > 0:
                reasons.append(f"{log_eval['critical_24h']} critical log event(s)")

            reason_str = ", ".join(reasons) if reasons else "moderate operational load"
            return f"Device health is in WARNING condition due to {reason_str}. Monitoring recommended."

        # CRITICAL
        reasons = []
        if resource_eval["available"]:
            if resource_eval["cpu"]["status"] == "CRITICAL":
                reasons.append("critical CPU saturation")
            if resource_eval["ram"]["status"] == "CRITICAL":
                reasons.append("critical memory exhaustion")
            if resource_eval["storage"]["status"] == "CRITICAL":
                reasons.append("critically full storage")
        if log_eval["critical_24h"] > 0:
            reasons.append(f"{log_eval['critical_24h']} critical error(s)")

        reason_str = ", ".join(reasons) if reasons else "severe resource or communication failure"
        return f"CRITICAL HEALTH CONDITION: Device performance compromised by {reason_str}. Immediate administrative action advised."

    # ── Historical Trend & Fleet Summary ────────────────────────────

    def get_health_trend(self, device_id: str, limit: int = 10) -> list[dict]:
        """
        Return historical health score trend points computed from historical telemetry snapshots.
        """
        limit = min(max(2, int(limit)), 50)
        conn = get_connection()
        try:
            device_row = conn.execute("SELECT status FROM devices WHERE device_id = ?;", (device_id,)).fetchone()
            if not device_row:
                return []
            is_online = (device_row["status"] or "").lower() == "online"

            rows = conn.execute(
                """SELECT timestamp, cpu_usage, memory_usage, disk_usage
                   FROM telemetry WHERE device_id = ?
                   ORDER BY timestamp DESC LIMIT ?;""",
                (device_id, limit),
            ).fetchall()

            if not rows:
                return []

            trend_points = []
            for r in reversed(rows):
                res_eval = self._evaluate_resources(dict(r))
                # Compute point score
                res_s = res_eval["score"]
                pt_score = int(round(0.60 * res_s + 0.40 * (100.0 if is_online else 15.0)))
                if not is_online:
                    pt_score = min(pt_score, 49)

                status = "GOOD" if pt_score >= 80 else ("WARNING" if pt_score >= 50 else "CRITICAL")
                trend_points.append({
                    "timestamp": r["timestamp"],
                    "score": pt_score,
                    "status": status,
                    "cpu": r["cpu_usage"],
                    "ram": r["memory_usage"],
                    "disk": r["disk_usage"],
                })

            return trend_points
        finally:
            conn.close()

    def get_fleet_health_summary(self) -> dict:
        """Fleet-wide health statistics."""
        conn = get_connection()
        try:
            dev_rows = conn.execute("SELECT device_id FROM devices;").fetchall()
            device_ids = [r["device_id"] for r in dev_rows]
        finally:
            conn.close()

        total = len(device_ids)
        good = 0
        warning = 0
        critical = 0

        for d_id in device_ids:
            h = self.evaluate_device_health(d_id, persist_alerts=False)
            if h:
                if h["status"] == "GOOD":
                    good += 1
                elif h["status"] == "WARNING":
                    warning += 1
                else:
                    critical += 1

        return {
            "total_devices": total,
            "good_count": good,
            "warning_count": warning,
            "critical_count": critical,
            "healthy_percentage": round((good / total * 100), 1) if total else 0.0,
        }
