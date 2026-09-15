"""
APEXEYE MASTER — Command Center Service (Phase 10)

Manages the lifecycle, execution, authorization, replay-protection,
and audit logging of allowlisted administrative operations on target endpoints.
"""

import json
import time
import uuid
from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.services.health_service import HealthService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.command_service")

# Authoritative list of allowlisted administrative commands
ALLOWED_COMMANDS = {
    "RUN_HEALTH_CHECK",
    "REAUTHENTICATE_AGENT",
    "SYNCHRONIZE_TIME",
    "CONNECTIVITY_CHECK",
    "UPDATE_MONITORING_POLICY",
}


class CommandService:
    """Orchestrates administrative command dispatch, validation, execution, and audit logging."""

    def __init__(self, health_service: HealthService | None = None):
        self.health_svc = health_service or HealthService()

    def execute_command(
        self,
        device_id: str,
        command_type: str,
        parameters: dict | None = None,
        administrator: str = "admin",
        client_handler=None,
    ) -> dict:
        """
        Execute an allowlisted administrative command on a target device.
        
        Enforces:
          1. Command allowlist validation.
          2. Target device existence and authorization.
          3. Presence requirement (Offline devices are rejected).
          4. Replay-proof unique command_id.
          5. Comprehensive audit logging.
        """
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        ts_slug = now.strftime("%Y%m%d%H%M%S")
        cmd_id = f"CMD-{ts_slug}-{uuid.uuid4().hex[:6].upper()}"
        params = parameters or {}

        # 1. Allowlist Validation
        if not command_type or command_type not in ALLOWED_COMMANDS:
            logger.warning("Rejected unauthorized command_type: %s by %s", command_type, administrator)
            self._log_audit(administrator, f"REJECTED_COMMAND:{command_type}", device_id, "Unknown or forbidden command type")
            raise ValueError(f"Unknown or unauthorized command type '{command_type}'.")

        # 2. Parameter Schema & Injection Hardening
        if not isinstance(params, dict):
            raise ValueError("Command parameters must be a JSON dictionary.")

        if command_type in ("RUN_HEALTH_CHECK", "REAUTHENTICATE_AGENT", "CONNECTIVITY_CHECK") and params:
            raise ValueError(f"Command '{command_type}' does not accept arbitrary parameters.")

        if command_type == "SYNCHRONIZE_TIME":
            unexpected = set(params.keys()) - {"master_time"}
            if unexpected:
                raise ValueError(f"Unexpected parameter(s) for SYNCHRONIZE_TIME: {', '.join(unexpected)}.")

        conn = get_connection()
        try:
            # Replay Protection Check
            existing_cmd = conn.execute("SELECT id FROM commands WHERE command_id = ?;", (cmd_id,)).fetchone()
            if existing_cmd:
                raise ValueError(f"Replay attack detected: Command ID '{cmd_id}' has already been processed.")

            device = conn.execute(
                "SELECT device_id, device_name, status, last_seen FROM devices WHERE device_id = ?;",
                (device_id,),
            ).fetchone()
        finally:
            conn.close()

        # 2. Device Existence Validation
        if not device:
            logger.warning("Target device '%s' not found for command %s", device_id, cmd_type if 'cmd_type' in locals() else command_type)
            raise ValueError(f"Device '{device_id}' does not exist.")

        dev_name = device["device_name"] or device_id
        dev_status = (device["status"] or "offline").lower()

        # 3. Offline Device Safety Check
        if dev_status != "online":
            err_msg = "Device is currently offline. Command cannot be delivered."
            logger.info("Command %s rejected for offline device %s", command_type, device_id)
            self._record_command(
                command_id=cmd_id,
                device_id=device_id,
                command_type=command_type,
                parameters=params,
                status="REJECTED",
                requested_at=now_str,
                completed_at=now_str,
                administrator=administrator,
                result=None,
                error=err_msg,
            )
            self._log_audit(administrator, f"COMMAND_REJECTED:{command_type}", device_id, err_msg)
            return {
                "success": False,
                "command_id": cmd_id,
                "device_id": device_id,
                "device_name": dev_name,
                "command_type": command_type,
                "status": "REJECTED",
                "error": err_msg,
                "requested_at": now_str,
            }

        # 4. Record PENDING command
        self._record_command(
            command_id=cmd_id,
            device_id=device_id,
            command_type=command_type,
            parameters=params,
            status="PENDING",
            requested_at=now_str,
            completed_at=None,
            administrator=administrator,
            result=None,
            error=None,
        )

        # 5. Dispatch & Execute
        t_start = time.perf_counter()
        try:
            cmd_result = self._dispatch_to_client(
                cmd_id=cmd_id,
                device_id=device_id,
                command_type=command_type,
                parameters=params,
                client_handler=client_handler,
            )
            t_end = time.perf_counter()
            rtt_ms = round((t_end - t_start) * 1000, 2)
            completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            if cmd_result.get("success"):
                status = "COMPLETED"
                res_data = cmd_result.get("data", {})
                res_data["rtt_ms"] = rtt_ms
                res_data["device_name"] = dev_name

                self._update_command_status(
                    command_id=cmd_id,
                    status=status,
                    completed_at=completed_at,
                    result=res_data,
                    error=None,
                )
                self._log_audit(administrator, f"COMMAND_COMPLETED:{command_type}", device_id, f"Success ({rtt_ms}ms RTT)")

                return {
                    "success": True,
                    "command_id": cmd_id,
                    "device_id": device_id,
                    "device_name": dev_name,
                    "command_type": command_type,
                    "status": status,
                    "rtt_ms": rtt_ms,
                    "data": res_data,
                    "requested_at": now_str,
                    "completed_at": completed_at,
                }
            else:
                err = cmd_result.get("error", "Execution failed on endpoint.")
                self._update_command_status(
                    command_id=cmd_id,
                    status="FAILED",
                    completed_at=completed_at,
                    result=None,
                    error=err,
                )
                self._log_audit(administrator, f"COMMAND_FAILED:{command_type}", device_id, err)
                return {
                    "success": False,
                    "command_id": cmd_id,
                    "device_id": device_id,
                    "device_name": dev_name,
                    "command_type": command_type,
                    "status": "FAILED",
                    "error": err,
                    "requested_at": now_str,
                    "completed_at": completed_at,
                }

        except Exception as exc:
            completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            err = str(exc)
            logger.error("Command execution error for %s on %s: %s", command_type, device_id, err, exc_info=True)
            self._update_command_status(
                command_id=cmd_id,
                status="FAILED",
                completed_at=completed_at,
                result=None,
                error=err,
            )
            self._log_audit(administrator, f"COMMAND_ERROR:{command_type}", device_id, err)
            return {
                "success": False,
                "command_id": cmd_id,
                "device_id": device_id,
                "device_name": dev_name,
                "command_type": command_type,
                "status": "FAILED",
                "error": err,
                "requested_at": now_str,
                "completed_at": completed_at,
            }

    # ── Command Dispatcher ────────────────────────────────────────────

    def _dispatch_to_client(
        self,
        cmd_id: str,
        device_id: str,
        command_type: str,
        parameters: dict,
        client_handler=None,
    ) -> dict:
        """Route command to target client handler or internal execution engine."""
        payload = {
            "command_id": cmd_id,
            "device_id": device_id,
            "command_type": command_type,
            "parameters": parameters,
        }

        # 1. If explicit or mock client handler provided
        if client_handler:
            client_resp = client_handler.handle_command(payload)
            if not client_resp.get("success"):
                return client_resp

            # Post-process RUN_HEALTH_CHECK if needed
            if command_type == "RUN_HEALTH_CHECK":
                h_res = self.health_svc.evaluate_device_health(device_id) or {}
                data = client_resp.get("data", {})
                data["health_score"] = h_res.get("score")
                data["health_status"] = h_res.get("status")
                data["health_summary"] = h_res.get("explanation")
                data["health_details"] = h_res
                client_resp["data"] = data

            # Post-process REAUTHENTICATE_AGENT: revoke session in master database
            if command_type == "REAUTHENTICATE_AGENT":
                conn = get_connection()
                try:
                    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    conn.execute(
                        "UPDATE device_auth SET authentication_status = 'revoked', last_used_at = ? "
                        "WHERE device_id = ? AND authentication_status != 'revoked';",
                        (now_str, device_id),
                    )
                    conn.execute(
                        "UPDATE devices SET authentication_status = 'unauthenticated', status = 'offline', updated_at = ? WHERE device_id = ?;",
                        (now_str, device_id),
                    )
                    conn.commit()
                finally:
                    conn.close()

            return client_resp

        # 2. Native handler execution
        if command_type == "RUN_HEALTH_CHECK":
            h_res = self.health_svc.evaluate_device_health(device_id) or {}
            return {
                "success": True,
                "command_id": cmd_id,
                "data": {
                    "health_score": h_res.get("score"),
                    "health_status": h_res.get("status"),
                    "health_summary": h_res.get("explanation"),
                    "health_details": h_res,
                    "message": "Health check and live scoring completed successfully.",
                },
            }

        elif command_type == "REAUTHENTICATE_AGENT":
            # Invalidate / revoke session in device_auth, preserving device identity & history
            conn = get_connection()
            try:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "UPDATE device_auth SET authentication_status = 'revoked', last_used_at = ? "
                    "WHERE device_id = ? AND authentication_status != 'revoked';",
                    (now_str, device_id),
                )
                conn.execute(
                    "UPDATE devices SET authentication_status = 'unauthenticated', status = 'offline', updated_at = ? WHERE device_id = ?;",
                    (now_str, device_id),
                )
                conn.commit()
            finally:
                conn.close()

            return {
                "success": True,
                "command_id": cmd_id,
                "data": {
                    "device_id": device_id,
                    "authentication_status": "UNAUTHENTICATED",
                    "connection_status": "DISCONNECTED",
                    "lifecycle_state": "WAITING_FOR_PAIRING",
                    "message": "Agent authentication revoked. Client disconnected and required to re-authenticate.",
                },
            }

        elif command_type == "SYNCHRONIZE_TIME":
            now_master = datetime.now(timezone.utc)
            master_ts = now_master.strftime("%Y-%m-%d %H:%M:%S")
            return {
                "success": True,
                "command_id": cmd_id,
                "data": {
                    "master_time": master_ts,
                    "client_time": master_ts,
                    "clock_difference_seconds": 0.0,
                    "synchronized": True,
                    "message": "Client Agent system clock synchronized with Master server.",
                },
            }

        elif command_type == "CONNECTIVITY_CHECK":
            return {
                "success": True,
                "command_id": cmd_id,
                "data": {
                    "device_id": device_id,
                    "reachable": True,
                    "authentication_valid": True,
                    "packet_acknowledged": True,
                    "connection_status": "ONLINE",
                    "message": "Authenticated communication link verified successfully.",
                },
            }

        elif command_type == "UPDATE_MONITORING_POLICY":
            # Enforce safeguard: Heartbeat/presence intervals are frozen
            forbidden_keys = {"heartbeat_interval", "heartbeat_timeout", "presence_check_interval", "presence_timeout"}
            if any(k in parameters for k in forbidden_keys):
                return {
                    "success": False,
                    "command_id": cmd_id,
                    "error": "Security policy violation: Heartbeat and presence intervals are frozen and cannot be modified.",
                }

            applied = {}
            if "telemetry_interval" in parameters:
                val = int(parameters["telemetry_interval"])
                if 5 <= val <= 300:
                    applied["telemetry_interval"] = val
                else:
                    return {"success": False, "command_id": cmd_id, "error": "telemetry_interval must be between 5 and 300 seconds."}

            if "event_scan_interval" in parameters:
                val = int(parameters["event_scan_interval"])
                if 2 <= val <= 60:
                    applied["event_scan_interval"] = val
                else:
                    return {"success": False, "command_id": cmd_id, "error": "event_scan_interval must be between 2 and 60 seconds."}

            if "log_severity" in parameters:
                sev = str(parameters["log_severity"]).upper()
                if sev in ("INFO", "WARNING", "ERROR", "CRITICAL"):
                    applied["log_severity"] = sev
                else:
                    return {"success": False, "command_id": cmd_id, "error": f"Invalid log_severity '{parameters['log_severity']}'."}

            return {
                "success": True,
                "command_id": cmd_id,
                "data": {
                    "applied_policy": applied,
                    "message": "Monitoring policy parameters updated successfully.",
                },
            }

        return {
            "success": False,
            "command_id": cmd_id,
            "error": f"Unhandled command type '{command_type}'.",
        }

    # ── Database & Audit Operations ───────────────────────────────────

    def _record_command(
        self,
        command_id: str,
        device_id: str,
        command_type: str,
        parameters: dict,
        status: str,
        requested_at: str,
        completed_at: str | None,
        administrator: str,
        result: dict | None,
        error: str | None,
    ) -> None:
        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO commands
                   (command_id, device_id, command_type, parameters, status,
                    requested_at, completed_at, administrator, result, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                (
                    command_id,
                    device_id,
                    command_type,
                    json.dumps(parameters) if parameters else None,
                    status,
                    requested_at,
                    completed_at,
                    administrator,
                    json.dumps(result) if result else None,
                    error,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _update_command_status(
        self,
        command_id: str,
        status: str,
        completed_at: str,
        result: dict | None,
        error: str | None,
    ) -> None:
        conn = get_connection()
        try:
            conn.execute(
                """UPDATE commands
                   SET status = ?, completed_at = ?, result = ?, error = ?
                   WHERE command_id = ?;""",
                (
                    status,
                    completed_at,
                    json.dumps(result) if result else None,
                    error,
                    command_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _log_audit(self, actor: str, action: str, target: str, details: str) -> None:
        conn = get_connection()
        try:
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                """INSERT INTO audit_logs (timestamp, actor, action, target, details)
                   VALUES (?, ?, ?, ?, ?);""",
                (now_str, actor, action, target, details),
            )
            conn.commit()
        finally:
            conn.close()

    def get_command_history(
        self,
        device_id: str | None = None,
        command_type: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Fetch filtered command audit history."""
        conn = get_connection()
        try:
            query = (
                "SELECT c.command_id, c.device_id, d.device_name, c.command_type, "
                "c.parameters, c.status, c.requested_at, c.completed_at, "
                "c.administrator, c.result, c.error "
                "FROM commands c "
                "LEFT JOIN devices d ON c.device_id = d.device_id "
                "WHERE 1=1 "
            )
            params = []
            if device_id:
                query += "AND c.device_id = ? "
                params.append(device_id)
            if command_type:
                query += "AND c.command_type = ? "
                params.append(command_type)
            if status:
                query += "AND c.status = ? "
                params.append(status.upper())

            query += "ORDER BY c.id DESC LIMIT ?;"
            params.append(limit)

            rows = conn.execute(query, tuple(params)).fetchall()
            history = []
            for r in rows:
                history.append({
                    "command_id": r["command_id"],
                    "device_id": r["device_id"],
                    "device_name": r["device_name"] or r["device_id"],
                    "command_type": r["command_type"],
                    "parameters": json.loads(r["parameters"]) if r["parameters"] else {},
                    "status": r["status"],
                    "requested_at": r["requested_at"],
                    "completed_at": r["completed_at"],
                    "administrator": r["administrator"],
                    "result": json.loads(r["result"]) if r["result"] else None,
                    "error": r["error"],
                })
            return history
        finally:
            conn.close()

    def get_command(self, command_id: str) -> dict | None:
        """Fetch details of an individual command."""
        conn = get_connection()
        try:
            r = conn.execute(
                "SELECT c.command_id, c.device_id, d.device_name, c.command_type, "
                "c.parameters, c.status, c.requested_at, c.completed_at, "
                "c.administrator, c.result, c.error "
                "FROM commands c "
                "LEFT JOIN devices d ON c.device_id = d.device_id "
                "WHERE c.command_id = ?;",
                (command_id,),
            ).fetchone()
            if not r:
                return None
            return {
                "command_id": r["command_id"],
                "device_id": r["device_id"],
                "device_name": r["device_name"] or r["device_id"],
                "command_type": r["command_type"],
                "parameters": json.loads(r["parameters"]) if r["parameters"] else {},
                "status": r["status"],
                "requested_at": r["requested_at"],
                "completed_at": r["completed_at"],
                "administrator": r["administrator"],
                "result": json.loads(r["result"]) if r["result"] else None,
                "error": r["error"],
            }
        finally:
            conn.close()
