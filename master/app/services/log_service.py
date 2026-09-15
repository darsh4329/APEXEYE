"""
APEXEYE MASTER — Centralized Log & Activity Service (Phase 5 Enhanced)

Manages centralized log ingestion, search, multi-field filtering,
pagination, and telemetry history for Windows/Linux agents and system events.

Features:
  - Validated batch log ingestion with referential device binding
  - Indexed multi-criteria search (Device, Severity, Category, App, Time range, Keyword)
  - Aggregated log health summary metrics
  - Historical structured telemetry retrieval
  - Full backwards compatibility with Phase 2 ingest/query signatures
"""

import json
from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.logs")

VALID_SEVERITIES = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
VALID_CATEGORIES = {
    "APPLICATION", "PRODUCTIVITY", "BROWSER", "COMMUNICATION",
    "DEVELOPMENT", "MEDIA", "GAME/ENTERTAINMENT", "UNKNOWN_APPLICATION",
    "SYSTEM", "SECURITY", "NETWORK", "AGENT", "CCTV", "OTHER"
}


class LogValidationError(Exception):
    """Raised when log payload validation fails."""
    pass


class LogService:
    """Business logic for centralized logging and telemetry search."""

    def ingest(self, device_id: str, entries: list[dict]) -> dict:
        """
        Backwards-compatible ingestion method.
        """
        stored = self.ingest_logs(device_id, entries)
        return {"device_id": device_id, "stored": stored}

    def ingest_logs(self, device_id: str, logs_list: list[dict]) -> int:
        """
        Validate and ingest a batch of log/activity events from an authenticated agent.
        """
        if not isinstance(logs_list, list) or not logs_list:
            return 0

        # Maximum batch size per request
        if len(logs_list) > 500:
            raise LogValidationError("Batch exceeds maximum allowed size (500 events)")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            # Check device type
            device_row = conn.execute(
                "SELECT device_type FROM devices WHERE device_id = ?;", (device_id,)
            ).fetchone()
            device_type = device_row["device_type"] if device_row else "OTHER"

            inserted_count = 0
            for item in logs_list:
                if not isinstance(item, dict):
                    continue

                msg = str(item.get("message", "")).strip()
                if not msg:
                    continue

                ts = item.get("timestamp", now)
                raw_level = str(item.get("severity", item.get("level", "INFO"))).upper()
                sev = raw_level if raw_level in VALID_SEVERITIES else "INFO"

                raw_cat = str(item.get("category", "OTHER")).upper()
                cat = raw_cat if raw_cat in VALID_CATEGORIES else "OTHER"

                evt = str(item.get("event_type", "INFO")).strip()
                app_name = item.get("application_name")
                src = str(item.get("source", "agent")).strip()
                details = item.get("details")
                details_json = (
                    json.dumps(details)
                    if isinstance(details, (dict, list))
                    else (str(details) if details else None)
                )

                # Safe deduplication: skip if identical event was already recorded
                existing = conn.execute(
                    """SELECT id FROM logs
                       WHERE device_id = ? AND timestamp = ? AND event_type = ? AND message = ?
                       LIMIT 1;""",
                    (device_id, ts, evt, msg),
                ).fetchone()
                if existing:
                    continue

                conn.execute(
                    """INSERT INTO logs
                       (device_id, device_type, timestamp, level, severity,
                        event_type, category, application_name, message, source,
                        details, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        device_id, device_type, ts, sev, sev,
                        evt, cat, app_name, msg, src,
                        details_json, now,
                    ),
                )
                inserted_count += 1

            conn.commit()
            logger.info("Ingested %d log event(s) from device '%s'", inserted_count, device_id)
            return inserted_count

        finally:
            conn.close()

    def query(self, filters: dict) -> list[dict]:
        """
        Backwards-compatible query method.
        """
        res = self.search_logs(
            device_id=filters.get("device_id"),
            severity=filters.get("level") or filters.get("severity"),
            limit=int(filters.get("limit", 100)),
        )
        return res.get("logs", [])

    def search_logs(
        self,
        device_id: str | None = None,
        device_type: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        event_type: str | None = None,
        application_name: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        query: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """
        Query centralized logs with multi-parameter filtering and pagination.
        """
        limit = min(max(1, int(limit)), 200)
        offset = max(0, int(offset))

        where_clauses = []
        params = []

        if device_id:
            where_clauses.append("device_id = ?")
            params.append(device_id)

        if device_type:
            where_clauses.append("device_type = ?")
            params.append(device_type)

        if severity:
            sev_list = [
                s.strip().upper()
                for s in severity.split(",")
                if s.strip().upper() in VALID_SEVERITIES
            ]
            if sev_list:
                placeholders = ",".join("?" for _ in sev_list)
                where_clauses.append(f"severity IN ({placeholders})")
                params.extend(sev_list)

        if category:
            cat_list = [
                c.strip().upper()
                for c in category.split(",")
                if c.strip().upper() in VALID_CATEGORIES
            ]
            if cat_list:
                placeholders = ",".join("?" for _ in cat_list)
                where_clauses.append(f"category IN ({placeholders})")
                params.extend(cat_list)

        if event_type:
            where_clauses.append("event_type = ?")
            params.append(event_type)

        if application_name:
            where_clauses.append("application_name LIKE ?")
            params.append(f"%{application_name}%")

        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time)

        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time)

        if query:
            where_clauses.append(
                "(message LIKE ? OR application_name LIKE ? OR event_type LIKE ?)"
            )
            q_param = f"%{query}%"
            params.extend([q_param, q_param, q_param])

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        conn = get_connection()
        try:
            # Count total matches
            count_query = f"SELECT COUNT(*) as c FROM logs{where_sql};"
            total = conn.execute(count_query, params).fetchone()["c"]

            # Fetch paginated rows
            data_query = f"""
                SELECT * FROM logs
                {where_sql}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?;
            """
            rows = conn.execute(data_query, (*params, limit, offset)).fetchall()

            logs_list = []
            for r in rows:
                item = dict(r)
                if item.get("details"):
                    try:
                        item["details"] = json.loads(item["details"])
                    except Exception:
                        pass
                logs_list.append(item)

            return {
                "total": total,
                "limit": limit,
                "offset": offset,
                "logs": logs_list,
            }

        finally:
            conn.close()

    def get_log_summary(self) -> dict:
        """
        Return count summaries for dashboard widgets and health analysis.
        """
        conn = get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) as c FROM logs;").fetchone()["c"]
            info_count = conn.execute(
                "SELECT COUNT(*) as c FROM logs WHERE severity = 'INFO';"
            ).fetchone()["c"]
            warn_count = conn.execute(
                "SELECT COUNT(*) as c FROM logs WHERE severity = 'WARNING';"
            ).fetchone()["c"]
            err_count = conn.execute(
                "SELECT COUNT(*) as c FROM logs WHERE severity IN ('ERROR', 'CRITICAL');"
            ).fetchone()["c"]

            cat_rows = conn.execute(
                "SELECT category, COUNT(*) as c FROM logs GROUP BY category;"
            ).fetchall()
            categories = {r["category"]: r["c"] for r in cat_rows}

            app_rows = conn.execute(
                """SELECT application_name, COUNT(*) as c FROM logs
                   WHERE application_name IS NOT NULL AND timestamp >= datetime('now', '-24 hours')
                   GROUP BY application_name ORDER BY c DESC LIMIT 5;"""
            ).fetchall()
            top_apps = [{r["application_name"]: r["c"]} for r in app_rows]

            return {
                "total": total,
                "info": info_count,
                "warning": warn_count,
                "error": err_count,
                "categories": categories,
                "top_apps_24h": top_apps,
            }

        finally:
            conn.close()

    def get_telemetry_history(
        self,
        device_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Query historical structured telemetry time-series for devices.
        """
        limit = min(max(1, int(limit)), 500)
        where = []
        params = []

        if device_id:
            where.append("device_id = ?")
            params.append(device_id)

        if start_time:
            where.append("timestamp >= ?")
            params.append(start_time)

        if end_time:
            where.append("timestamp <= ?")
            params.append(end_time)

        where_sql = (" WHERE " + " AND ".join(where)) if where else ""

        conn = get_connection()
        try:
            rows = conn.execute(
                f"""SELECT * FROM telemetry
                    {where_sql}
                    ORDER BY timestamp DESC LIMIT ?;""",
                (*params, limit),
            ).fetchall()

            results = []
            for r in rows:
                item = dict(r)
                if item.get("details"):
                    try:
                        item["details"] = json.loads(item["details"])
                    except Exception:
                        pass
                results.append(item)
            return results
        finally:
            conn.close()

    def get_device_current_activity(self, device_id: str) -> dict:
        """
        Retrieve the latest recorded APPLICATION_ACTIVE state for a device.

        Conservative semantics: reports the focused foreground application without
        speculating on productivity or employee work state.
        """
        conn = get_connection()
        try:
            row = conn.execute(
                """SELECT timestamp, application_name, category, message, details
                   FROM logs
                   WHERE device_id = ? AND event_type = 'APPLICATION_ACTIVE'
                   ORDER BY timestamp DESC, id DESC
                   LIMIT 1;""",
                (device_id,),
            ).fetchone()

            if not row:
                return {
                    "device_id": device_id,
                    "has_activity": False,
                    "foreground_application": None,
                    "category": None,
                    "last_changed": None,
                    "status_text": "No recent active application recorded",
                }

            app_name = row["application_name"] or "Unknown Application"
            cat = row["category"] or "OTHER"
            ts = row["timestamp"]

            return {
                "device_id": device_id,
                "has_activity": True,
                "foreground_application": app_name,
                "category": cat,
                "last_changed": ts,
                "status_text": f"Foreground application: {app_name} ({cat})",
            }
        finally:
            conn.close()

    def get_all_current_activities(self) -> list[dict]:
        """
        Retrieve the latest recorded APPLICATION_ACTIVE state for all registered devices.
        """
        conn = get_connection()
        try:
            devices = conn.execute(
                "SELECT device_id, device_name, device_type FROM devices;"
            ).fetchall()
            results = []
            for d in devices:
                did = d["device_id"]
                act = self.get_device_current_activity(did)
                act["device_name"] = d["device_name"]
                act["device_type"] = d["device_type"]
                results.append(act)
            return results
        finally:
            conn.close()

    def clear_logs(self, device_id: str | None = None) -> int:
        """
        Clear development logs and events from the logs table.
        Does NOT touch devices, device_auth, telemetry, CCTV registrations, or configuration.
        Returns the number of deleted records.
        """
        conn = get_connection()
        try:
            if device_id:
                cursor = conn.execute("DELETE FROM logs WHERE device_id = ?;", (device_id,))
            else:
                cursor = conn.execute("DELETE FROM logs;")
            conn.commit()
            deleted = cursor.rowcount
            logger.info("Cleared %d log record(s) from database (device_id=%s)", deleted, device_id or "ALL")
            return deleted
        finally:
            conn.close()

    def get_live_critical_alerts(self, since_id: int = 0, baseline: bool = False) -> dict:
        """
        Fast lightweight query for emergency critical alerts (e.g. Critical CPU alerts).
        If baseline=True or since_id <= 0, returns the current latest log id without historical popups.
        """
        conn = get_connection()
        try:
            max_row = conn.execute("SELECT MAX(id) as max_id FROM logs;").fetchone()
            latest_id = int(max_row["max_id"]) if max_row and max_row["max_id"] is not None else 0

            if baseline or since_id is None:
                return {
                    "latest_id": latest_id,
                    "alerts": [],
                }

            if since_id < 0:
                since_id = 0

            rows = conn.execute(
                """SELECT l.id, l.device_id, l.timestamp, l.severity, l.level, l.event_type,
                          l.category, l.application_name, l.message, l.details,
                          d.device_name, d.status as device_status
                   FROM logs l
                   LEFT JOIN devices d ON l.device_id = d.device_id
                   WHERE l.id > ?
                     AND (
                         l.event_type IN ('CPU_WARNING', 'CPU_CRITICAL', 'HIGH_CPU_CRITICAL', 'HIGH_CPU_WARNING')
                         OR (l.severity IN ('WARNING', 'CRITICAL') AND (l.message LIKE '%CPU%' OR l.event_type LIKE '%CPU%'))
                     )
                   ORDER BY l.id ASC LIMIT 20;""",
                (since_id,),
            ).fetchall()

            alerts = []
            for r in rows:
                item = dict(r)
                # Parse details to extract real cpu_percent if available
                cpu_val = None
                if item.get("details"):
                    try:
                        det = json.loads(item["details"])
                        if isinstance(det, dict):
                            cpu_val = det.get("cpu_usage") or det.get("cpu_percent") or det.get("cpu")
                    except Exception:
                        pass

                # If not in details, try extracting from message e.g. "High CPU utilization alert: 98.5%"
                if cpu_val is None and item.get("message"):
                    import re
                    m = re.search(r"(\d+(?:\.\d+)?)\s*%", item["message"])
                    if m:
                        try:
                            cpu_val = float(m.group(1))
                        except Exception:
                            pass

                item["cpu_percent"] = cpu_val
                # Provide standard formatted human-readable reason
                dev_name = item.get("device_name") or item.get("device_id") or "Device"
                cpu_str = f"{cpu_val:.1f}%" if cpu_val is not None else "High"
                item["human_reason"] = f"Client {dev_name} is using {cpu_str} CPU. CPU utilization is critical."
                alerts.append(item)

            return {
                "latest_id": latest_id,
                "alerts": alerts,
            }
        finally:
            conn.close()


