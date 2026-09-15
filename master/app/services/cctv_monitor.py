"""
APEXEYE MASTER — CCTV Background Monitoring Engine (Phase 4)

Runs a background daemon thread in Master to periodically monitor all
enabled CCTV cameras, log state transitions, and record telemetry.

Features:
  - Configurable polling interval (APEXEYE_CCTV_CHECK_INTERVAL_SECONDS)
  - Automatic status transition detection (OFFLINE <-> ONLINE)
  - Meaningful event logging to Master logs table without polling noise
  - On-demand instant single-camera probe API (check_now)
"""

import threading
import time
from datetime import datetime, timezone

from master.app.config import config
from master.app.database import get_connection
from master.app.services.cctv_service import CCTVService
from master.app.services.cctv_prober import probe_cctv
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.cctv.monitor")


class CCTVMonitorEngine:
    """Orchestrates periodic background monitoring for CCTV endpoints."""

    def __init__(self, service: CCTVService | None = None):
        self.service = service or CCTVService()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_known_status: dict[str, str] = {}  # cctv_id -> last_status
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background monitor loop."""
        if self._thread and self._thread.is_alive():
            logger.warning("CCTV monitor thread already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="ApexEyeMaster-CCTVMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "CCTV background monitor engine started (interval=%ds)",
            config.CCTV_CHECK_INTERVAL,
        )

    def stop(self) -> None:
        """Stop the background monitor loop."""
        logger.info("Stopping CCTV monitor engine \u2026")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("CCTV monitor engine stopped.")

    def check_now(self, cctv_id: str) -> dict | None:
        """
        Perform an immediate, on-demand probe for a single CCTV camera.
        Returns the latest telemetry result.
        """
        cctv = self.service.get_cctv(cctv_id, include_secrets=True)
        if not cctv:
            return None

        telemetry = probe_cctv(cctv)
        self._process_result(cctv, telemetry)
        return telemetry

    def _monitor_loop(self) -> None:
        """Main periodic polling loop."""
        # Initial short delay on Master boot to allow DB ready
        self._stop_event.wait(timeout=2)

        while not self._stop_event.is_set():
            try:
                self._poll_all_enabled()
            except Exception as exc:
                logger.error("Error in CCTV monitor cycle: %s", exc, exc_info=True)

            self._stop_event.wait(timeout=config.CCTV_CHECK_INTERVAL)

    def _poll_all_enabled(self) -> None:
        """Poll all enabled CCTV devices."""
        cctvs = self.service.list_cctv(include_secrets=True)
        enabled = [c for c in cctvs if c.get("is_enabled", True)]

        if not enabled:
            return

        for cctv in enabled:
            if self._stop_event.is_set():
                break
            try:
                telemetry = probe_cctv(cctv)
                self._process_result(cctv, telemetry)
            except Exception as exc:
                logger.error("Error probing CCTV '%s': %s", cctv.get("cctv_id"), exc)

    def _process_result(self, cctv: dict, telemetry: dict) -> None:
        """Store telemetry and detect/log state transitions."""
        cctv_id = cctv["cctv_id"]
        new_status = telemetry["status"]

        with self._lock:
            old_status = self._last_known_status.get(cctv_id, cctv.get("status", "UNKNOWN"))
            self._last_known_status[cctv_id] = new_status

        # Store in DB
        self.service.store_telemetry(cctv_id, telemetry)

        # Detect transition
        if old_status != new_status and old_status != "UNKNOWN":
            self._log_status_transition(cctv, old_status, new_status, telemetry)
        elif old_status == "UNKNOWN":
            logger.info("CCTV '%s' initial status evaluated as %s", cctv_id, new_status)

    def _log_status_transition(
        self, cctv: dict, old_status: str, new_status: str, telemetry: dict
    ) -> None:
        """Log state transitions in Master logs table and system logger."""
        cctv_id = cctv["cctv_id"]
        name = cctv.get("name", cctv_id)
        reason = telemetry.get("failure_reason", "")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        if new_status == "ONLINE":
            level = "INFO"
            msg = f"CCTV '{name}' ({cctv_id}) recovered and is now ONLINE"
        elif new_status == "OFFLINE":
            level = "WARNING"
            msg = f"CCTV '{name}' ({cctv_id}) went OFFLINE. Reason: {reason}"
        else:
            level = "WARNING"
            msg = f"CCTV '{name}' ({cctv_id}) status changed to {new_status}. Reason: {reason}"

        logger.info("[STATUS CHANGE] %s", msg)

        # Persist event in central logs table
        try:
            conn = get_connection()
            conn.execute(
                """INSERT INTO logs (timestamp, level, event_type, message, source)
                   VALUES (?,?,?,?,?)""",
                (now, level, "cctv_status_change", msg, "cctv_monitor"),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.error("Failed to write CCTV status transition log: %s", exc)


# Global singleton instance
cctv_monitor_engine = CCTVMonitorEngine()
