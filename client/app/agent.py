"""
APEXEYE CLIENT — Agent Orchestrator (Phase 2)

Manages all background workers for telemetry collection, heartbeat,
host information reporting, and process event monitoring.

Each activity runs in its own daemon thread with configurable intervals.
The agent gracefully shuts down when stop() is called or the process
is interrupted.
"""

import json
import threading
import time
from datetime import datetime, timezone

from client.app.config import config
from client.app.communication import MasterConnection
from client.app.collectors import (
    CPUCollector,
    MemoryCollector,
    DiskCollector,
    NetworkCollector,
    OSInfoCollector,
    EventCollector,
)
from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.agent")


class Agent:
    """
    Main agent orchestrator.

    Runs background threads for:
      - Telemetry collection (CPU, RAM, disk, network) — every TELEMETRY_INTERVAL
      - Heartbeat — every HEARTBEAT_INTERVAL
      - Host info — on startup, then every HOST_INFO_INTERVAL
      - Process event monitoring — every EVENT_SCAN_INTERVAL
    """

    def __init__(self, conn: MasterConnection, firewall_agent=None):
        self.conn = conn
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

        # Collectors
        self._cpu = CPUCollector()
        self._memory = MemoryCollector()
        self._disk = DiskCollector()
        self._network = NetworkCollector()
        self._os_info = OSInfoCollector()
        self._events = EventCollector()

        # Firewall agent (reuse pre-initialized instance if available)
        if firewall_agent is not None:
            self._firewall_agent = firewall_agent
            self._firewall_agent._stop_event = self._stop_event
        else:
            from client.app.services.firewall_agent import FirewallAgent
            self._firewall_agent = FirewallAgent(conn, self._stop_event)

        logger.info("Agent initialized with all collectors")

    def start(self) -> None:
        """Start all background workers."""
        logger.info("=" * 60)
        logger.info("APEXEYE Agent starting …")
        logger.info("  Telemetry interval : %ds", config.TELEMETRY_INTERVAL)
        logger.info("  Heartbeat interval : %ds", config.HEARTBEAT_INTERVAL)
        logger.info("  Event scan interval: %ds", config.EVENT_SCAN_INTERVAL)
        logger.info("  Host info interval : %ds", config.HOST_INFO_INTERVAL)
        logger.info("=" * 60)

        # Load cached firewall policy and apply before first sync
        self._firewall_agent.start()

        workers = [
            ("Telemetry", self._telemetry_loop),
            ("Heartbeat", self._heartbeat_loop),
            ("HostInfo", self._host_info_loop),
            ("EventMonitor", self._event_loop),
        ]

        for name, target in workers:
            t = threading.Thread(
                target=self._safe_worker, args=(name, target),
                name=f"ApexEye-{name}", daemon=True,
            )
            self._threads.append(t)
            t.start()
            logger.info("Worker started: %s", name)

        # Firewall sync worker
        self._firewall_thread = threading.Thread(
            target=self._safe_worker, args=("FirewallSync", self._firewall_agent.run_sync_loop),
            name="ApexEye-FirewallSync", daemon=True,
        )
        self._firewall_thread.start()
        logger.info("Worker started: FirewallSync")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal all workers to stop and wait for them to finish."""
        logger.info("Agent shutdown requested …")
        self._stop_event.set()
        curr = threading.current_thread()
        for t in self._threads:
            if t is not curr and t.is_alive():
                t.join(timeout=timeout)
        if hasattr(self, "_firewall_thread") and self._firewall_thread is not curr and self._firewall_thread.is_alive():
            self._firewall_thread.join(timeout=timeout)
        logger.info("Agent stopped.")

    def wait(self) -> None:
        """Block until stop is signaled (used by main thread)."""
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=0.5)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
            self.stop()

    @property
    def is_running(self) -> bool:
        return not self._stop_event.is_set()

    # ── Worker Wrapper ──────────────────────────────────────────

    def _safe_worker(self, name: str, func) -> None:
        """Wrap a worker function with exception handling."""
        try:
            func()
        except Exception as exc:
            logger.error("Worker %s crashed: %s", name, exc, exc_info=True)

    # ── Telemetry Worker ────────────────────────────────────────

    def _telemetry_loop(self) -> None:
        """Collect and send telemetry periodically."""
        logger.info("Telemetry worker running (interval=%ds)", config.TELEMETRY_INTERVAL)
        # Small stagger (0.1s) allows heartbeat to establish online status first
        self._stop_event.wait(timeout=0.1)

        while not self._stop_event.is_set():
            if not self.conn.is_authenticated:
                break
            try:
                # Collect all telemetry
                cpu_data = self._cpu.collect()
                memory_data = self._memory.collect()
                disk_data = self._disk.collect()
                network_data = self._network.collect()

                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

                payload = {
                    "timestamp": timestamp,
                    "cpu": cpu_data,
                    "memory": memory_data,
                    "disk": disk_data,
                    "network": network_data,
                }

                success = self.conn.send_telemetry(payload)
                if success:
                    logger.info(
                        "Telemetry sent — CPU: %.1f%%, RAM: %.1f%%, Disk: %.1f%%",
                        cpu_data.get("cpu_usage", 0),
                        memory_data.get("memory_usage_percent", 0),
                        disk_data.get("disk_usage_percent", 0),
                    )
                else:
                    logger.warning("Telemetry transmission failed (will retry next interval)")

            except Exception as exc:
                logger.error("Telemetry collection/send error: %s", exc)

            # Wait for next interval (checking stop_event frequently)
            self._stop_event.wait(timeout=config.TELEMETRY_INTERVAL)

    # ── Heartbeat Worker ────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        """Send heartbeat to Master periodically."""
        logger.info("Heartbeat worker running (interval=%ds)", config.HEARTBEAT_INTERVAL)

        while not self._stop_event.is_set():
            if not self.conn.is_authenticated:
                break
            try:
                success = self.conn.send_heartbeat(client_status="running")
                if success:
                    logger.debug("Heartbeat sent")
                else:
                    logger.warning("Heartbeat failed (will retry next interval)")
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)

            self._stop_event.wait(timeout=config.HEARTBEAT_INTERVAL)

    # ── Host Info Worker ────────────────────────────────────────

    def _host_info_loop(self) -> None:
        """Send host information on startup and periodically."""
        logger.info("Host info worker running (interval=%ds)", config.HOST_INFO_INTERVAL)
        # Stagger initial host info send (0.3s) to avoid colliding with heartbeat and telemetry
        self._stop_event.wait(timeout=0.3)

        while not self._stop_event.is_set():
            if not self.conn.is_authenticated:
                break
            try:
                host_data = self._os_info.collect()
                success = self.conn.send_host_info(host_data)
                if success:
                    logger.info("Host info sent to Master")
                else:
                    logger.warning("Host info send failed (will retry next interval)")
            except Exception as exc:
                logger.error("Host info error: %s", exc)

            self._stop_event.wait(timeout=config.HOST_INFO_INTERVAL)

    # ── Event Monitor Worker ────────────────────────────────────

    def _event_loop(self) -> None:
        """Monitor process start/stop events and send to Master."""
        logger.info("Event monitor running (interval=%ds)", config.EVENT_SCAN_INTERVAL)
        # Stagger initial scan (1.0s) so baseline established in __init__ is not duplicate-scanned immediately at t=0
        self._stop_event.wait(timeout=min(config.EVENT_SCAN_INTERVAL, 1.0))

        while not self._stop_event.is_set():
            if not self.conn.is_authenticated:
                break
            try:
                events = self._events.collect()
                if events:
                    success = self.conn.send_events(events)
                    if success:
                        logger.info("Sent %d process event(s) to Master", len(events))
                    else:
                        logger.warning("Event send failed (%d events lost)", len(events))
            except Exception as exc:
                logger.error("Event monitor error: %s", exc)

            self._stop_event.wait(timeout=config.EVENT_SCAN_INTERVAL)
