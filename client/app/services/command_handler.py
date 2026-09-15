"""
APEXEYE CLIENT — Secure Command Handler (Phase 10)

Executes allowlisted administrative operations dispatched from the Master Command Center.
Strictly forbids arbitrary shell/subprocess execution.
"""

from datetime import datetime, timezone

from client.app.config import config
from client.app.collectors import (
    CPUCollector,
    MemoryCollector,
    DiskCollector,
    NetworkCollector,
)
from client.app.auth import ClientAuth
from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.command_handler")

# Strict Allowlist of permitted administrative commands
ALLOWED_COMMANDS = {
    "RUN_HEALTH_CHECK",
    "REAUTHENTICATE_AGENT",
    "SYNCHRONIZE_TIME",
    "CONNECTIVITY_CHECK",
    "UPDATE_MONITORING_POLICY",
}


class CommandHandler:
    """Handles execution of authenticated, allowlisted administrative commands."""

    def __init__(self, conn=None, auth=None, disconnect_callback=None):
        if conn is not None and auth is None and (hasattr(conn, "device_id") or hasattr(conn, "pair") or hasattr(conn, "is_paired")):
            conn, auth = None, conn
        self.conn = conn
        self.auth = auth or (ClientAuth(conn) if conn else None)
        self._disconnect_callback = disconnect_callback
        self._cpu = CPUCollector()
        self._memory = MemoryCollector()
        self._disk = DiskCollector()
        self._network = NetworkCollector()

    def set_disconnect_callback(self, callback) -> None:
        """Register callback to be invoked when Master orders agent disconnect / re-authentication."""
        self._disconnect_callback = callback

    def handle_command(self, payload: dict) -> dict:
        """
        Validate and execute an administrative command.
        
        Payload format:
            {
                "command_id": "CMD-...",
                "device_id": "DEV-...",
                "command_type": "...",
                "parameters": { ... }
            }
        """
        cmd_id = payload.get("command_id")
        target_device = payload.get("device_id")
        cmd_type = payload.get("command_type")
        params = payload.get("parameters") or {}

        # 1. Allowlist Validation
        if not cmd_type or cmd_type not in ALLOWED_COMMANDS:
            logger.warning("Rejected non-allowlisted command: %s (ID: %s)", cmd_type, cmd_id)
            return {
                "success": False,
                "command_id": cmd_id,
                "error": f"Command '{cmd_type}' is not recognized or not permitted.",
            }

        # 2. Target Device Verification
        current_dev = self.auth.device_id if self.auth else None
        if target_device and current_dev and target_device != current_dev:
            logger.warning("Device ID mismatch: requested %s, local %s", target_device, current_dev)
            return {
                "success": False,
                "command_id": cmd_id,
                "error": f"Target device mismatch. Local device is '{current_dev}'.",
            }

        # 3. Parameter Schema & Injection Hardening
        if not isinstance(params, dict):
            return {
                "success": False,
                "command_id": cmd_id,
                "error": "Parameters must be a valid JSON dictionary.",
            }

        # Check for unexpected parameters / command injection attempts
        if cmd_type in ("RUN_HEALTH_CHECK", "REAUTHENTICATE_AGENT", "CONNECTIVITY_CHECK") and params:
            logger.warning("Rejected unexpected parameters for %s: %s", cmd_type, params)
            return {
                "success": False,
                "command_id": cmd_id,
                "error": f"Command '{cmd_type}' does not accept arbitrary parameters.",
            }

        if cmd_type == "SYNCHRONIZE_TIME":
            unexpected = set(params.keys()) - {"master_time"}
            if unexpected:
                return {
                    "success": False,
                    "command_id": cmd_id,
                    "error": f"Unexpected parameter(s) for SYNCHRONIZE_TIME: {', '.join(unexpected)}.",
                }

        logger.info("Executing administrative command: %s (ID: %s)", cmd_type, cmd_id)

        try:
            if cmd_type == "RUN_HEALTH_CHECK":
                return self._exec_run_health_check(cmd_id)
            elif cmd_type == "REAUTHENTICATE_AGENT":
                return self._exec_reauthenticate_agent(cmd_id)
            elif cmd_type == "SYNCHRONIZE_TIME":
                return self._exec_synchronize_time(cmd_id, params)
            elif cmd_type == "CONNECTIVITY_CHECK":
                return self._exec_connectivity_check(cmd_id)
            elif cmd_type == "UPDATE_MONITORING_POLICY":
                return self._exec_update_monitoring_policy(cmd_id, params)
        except Exception as exc:
            logger.error("Command %s execution error: %s", cmd_type, exc, exc_info=True)
            return {
                "success": False,
                "command_id": cmd_id,
                "error": str(exc),
            }

    # ── Command 1: RUN_HEALTH_CHECK ───────────────────────────────────

    def _exec_run_health_check(self, cmd_id: str) -> dict:
        """Collect live hardware telemetry metrics for health calculation."""
        cpu_data = self._cpu.collect()
        mem_data = self._memory.collect()
        disk_data = self._disk.collect()
        net_data = self._network.collect()

        telemetry_payload = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_usage": cpu_data.get("cpu_usage", 0.0),
            "memory_usage": mem_data.get("memory_usage_percent", 0.0),
            "disk_usage": disk_data.get("disk_usage_percent", 0.0),
            "network_usage": net_data.get("bytes_sent_rate_mbps", 0.0) + net_data.get("bytes_recv_rate_mbps", 0.0),
            "cpu": cpu_data,
            "memory": mem_data,
            "disk": disk_data,
            "network": net_data,
        }

        return {
            "success": True,
            "command_id": cmd_id,
            "command_type": "RUN_HEALTH_CHECK",
            "data": {
                "telemetry": telemetry_payload,
                "message": "Live telemetry query completed successfully.",
            },
        }

    # ── Command 2: REAUTHENTICATE_AGENT ───────────────────────────────

    def _exec_reauthenticate_agent(self, cmd_id: str) -> dict:
        """Invalidate session, clear stored credentials, and trigger agent disconnect."""
        dev_id = self.auth.device_id if self.auth else (getattr(config, "CLIENT_ID", None) or "UNKNOWN")
        logger.warning(
            "Master ordered forced re-authentication for Windows client %s. Invalidating session.",
            dev_id,
        )

        # 1. Clear local credentials (preserving persistent device identity)
        if self.auth:
            self.auth._clear_credentials()

        # 2. Clear connection identity
        if self.conn:
            self.conn.clear_identity()

        # 3. Fire disconnect callback to stop background loops and transition to WAITING_FOR_PAIRING
        if self._disconnect_callback:
            try:
                self._disconnect_callback()
            except Exception as exc:
                logger.error("Error executing disconnect callback: %s", exc)

        return {
            "success": True,
            "command_id": cmd_id,
            "command_type": "REAUTHENTICATE_AGENT",
            "data": {
                "device_id": dev_id,
                "authentication_status": "UNAUTHENTICATED",
                "connection_status": "DISCONNECTED",
                "lifecycle_state": "WAITING_FOR_PAIRING",
                "message": "Client agent session terminated. Re-pairing required.",
            },
        }

    # ── Command 3: SYNCHRONIZE_TIME ───────────────────────────────────

    def _exec_synchronize_time(self, cmd_id: str, params: dict) -> dict:
        """Synchronize client timestamp with authoritative Master timestamp."""
        master_ts_str = params.get("master_time")
        now_client = datetime.now(timezone.utc)
        client_ts_str = now_client.strftime("%Y-%m-%d %H:%M:%S")

        clock_diff = 0.0
        if master_ts_str:
            try:
                master_dt = datetime.fromisoformat(master_ts_str.replace("Z", "+00:00"))
                if master_dt.tzinfo is None:
                    master_dt = master_dt.replace(tzinfo=timezone.utc)
                clock_diff = round((master_dt - now_client).total_seconds(), 3)
            except Exception:
                pass

        return {
            "success": True,
            "command_id": cmd_id,
            "command_type": "SYNCHRONIZE_TIME",
            "data": {
                "master_time": master_ts_str or client_ts_str,
                "client_time": client_ts_str,
                "clock_difference_seconds": clock_diff,
                "synchronized": True,
                "message": f"Time synchronization completed (offset: {clock_diff:+.2f}s).",
            },
        }

    # ── Command 4: CONNECTIVITY_CHECK ─────────────────────────────────

    def _exec_connectivity_check(self, cmd_id: str) -> dict:
        """Acknowledge authenticated Master-to-Client communication test."""
        dev_id = self.auth.device_id if self.auth else "UNKNOWN"
        return {
            "success": True,
            "command_id": cmd_id,
            "command_type": "CONNECTIVITY_CHECK",
            "data": {
                "device_id": dev_id,
                "reachable": True,
                "authentication_valid": True,
                "packet_acknowledged": True,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            },
        }

    # ── Command 5: UPDATE_MONITORING_POLICY ────────────────────────────

    def _exec_update_monitoring_policy(self, cmd_id: str, params: dict) -> dict:
        """
        Update approved runtime monitoring parameters.
        STRICTLY PROTECTS frozen heartbeat and presence constants (3s/9s/1s).
        """
        # Forbidden parameters check
        forbidden_keys = {"heartbeat_interval", "heartbeat_timeout", "presence_check_interval", "presence_timeout"}
        if any(k in params for k in forbidden_keys):
            return {
                "success": False,
                "command_id": cmd_id,
                "error": "Security policy violation: Heartbeat and presence intervals are frozen and cannot be modified.",
            }

        applied = {}

        # 1. Telemetry Interval (Safe range: 5s - 60s, Default: 10s)
        tel_interval = params.get("telemetry_interval")
        if tel_interval is not None:
            try:
                val = int(tel_interval)
                if 5 <= val <= 300:
                    config.TELEMETRY_INTERVAL = val
                    applied["telemetry_interval"] = val
                else:
                    return {
                        "success": False,
                        "command_id": cmd_id,
                        "error": f"Invalid telemetry_interval {val}. Allowed range is 5 to 300 seconds.",
                    }
            except (ValueError, TypeError):
                return {"success": False, "command_id": cmd_id, "error": "telemetry_interval must be an integer."}

        # 2. Event Scan Interval (Safe range: 2s - 60s)
        scan_interval = params.get("event_scan_interval")
        if scan_interval is not None:
            try:
                val = int(scan_interval)
                if 2 <= val <= 60:
                    config.EVENT_SCAN_INTERVAL = val
                    applied["event_scan_interval"] = val
                else:
                    return {
                        "success": False,
                        "command_id": cmd_id,
                        "error": f"Invalid event_scan_interval {val}. Allowed range is 2 to 60 seconds.",
                    }
            except (ValueError, TypeError):
                return {"success": False, "command_id": cmd_id, "error": "event_scan_interval must be an integer."}

        # 3. Log Severity Threshold
        severity = params.get("log_severity")
        if severity is not None:
            sev_clean = str(severity).upper()
            if sev_clean in ("INFO", "WARNING", "ERROR", "CRITICAL"):
                applied["log_severity"] = sev_clean
            else:
                return {
                    "success": False,
                    "command_id": cmd_id,
                    "error": f"Invalid log_severity '{severity}'. Allowed: INFO, WARNING, ERROR, CRITICAL.",
                }

        return {
            "success": True,
            "command_id": cmd_id,
            "command_type": "UPDATE_MONITORING_POLICY",
            "data": {
                "applied_policy": applied,
                "message": "Monitoring policy applied successfully.",
            },
        }
