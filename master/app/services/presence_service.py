"""
APEXEYE MASTER — Client Presence & Heartbeat Timeout Engine

Runs a background daemon thread in Master to periodically verify client
heartbeat and telemetry freshness.

If a client stops sending heartbeats / telemetry (e.g. computer shutdown,
power loss, network disconnect, crash), this service automatically transitions
the device status from 'online' to 'offline' after the configurable grace period
(HEARTBEAT_TIMEOUT_SECONDS).

Preserves:
  - last_seen
  - device identity
  - pairing/authentication
  - historical telemetry
  - historical logs
"""

import threading
import time
from datetime import datetime, timezone

from master.app.config import config
from master.app.services.device_service import DeviceService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.presence")


class PresenceMonitorEngine:
    """Orchestrates periodic background presence reconciliation for registered devices."""

    def __init__(self, service: DeviceService | None = None):
        self.service = service or DeviceService()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background presence monitor loop."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                logger.warning("Presence monitor thread already running")
                return

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="ApexEyeMaster-PresenceMonitor",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "Master device presence monitoring engine started (interval=%ds, timeout=%ds)",
                config.PRESENCE_CHECK_INTERVAL,
                config.HEARTBEAT_TIMEOUT_SECONDS,
            )

    def stop(self) -> None:
        """Stop the background presence monitor loop."""
        logger.info("Stopping presence monitor engine …")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Presence monitor engine stopped.")

    def check_now(self) -> int:
        """Manually trigger a presence check immediately. Returns count of transitioned devices."""
        return self.service.reconcile_presence()

    def _monitor_loop(self) -> None:
        """Main loop: periodically reconciles presence timeout."""
        logger.info("Presence monitor loop initialized")
        while not self._stop_event.is_set():
            try:
                self.service.reconcile_presence()
            except Exception as exc:
                logger.error("Error during presence reconciliation: %s", exc)

            interval = getattr(config, "PRESENCE_CHECK_INTERVAL", 1)
            self._stop_event.wait(timeout=max(1, interval))


# Global singleton instance
presence_monitor_engine = PresenceMonitorEngine()
