"""
APEXEYE LINUX CLIENT — Agent Orchestrator (Phase 3)

Manages all background workers for the Linux agent:
  - Telemetry collection (CPU, RAM, disk, network)
  - Heartbeat transmission
  - Host/OS information reporting
  - Process event monitoring
"""

import sys
import threading
import time
from datetime import datetime, timezone

from client_linux.app.config import config
from client_linux.app.communication import MasterConnection
from client_linux.app.collectors import (
    CPUCollector,
    MemoryCollector,
    DiskCollector,
    NetworkCollector,
    OSInfoCollector,
    EventCollector,
)
from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.agent")


class Agent:
    """Main Linux agent orchestrator running daemon background workers."""

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
            from client_linux.app.services.firewall_agent import FirewallAgent
            self._firewall_agent = FirewallAgent(conn, self._stop_event)

        logger.info("Linux Agent initialized with all collectors")

    def start(self) -> None:
        """Start all background workers."""
        logger.info("=" * 60)
        logger.info("APEXEYE Linux Agent starting \u2026")
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
                name=f"ApexEyeLinux-{name}", daemon=True,
            )
            self._threads.append(t)
            t.start()
            logger.info("Linux worker started: %s", name)

        # Firewall sync worker
        self._firewall_thread = threading.Thread(
            target=self._safe_worker, args=("FirewallSync", self._firewall_agent.run_sync_loop),
            name="ApexEyeLinux-FirewallSync", daemon=True,
        )
        self._firewall_thread.start()
        logger.info("Linux worker started: FirewallSync")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal all workers to stop and wait for them to finish."""
        logger.info("Linux Agent shutdown requested \u2026")
        self._stop_event.set()
        curr = threading.current_thread()
        end_time = time.time() + max(timeout, 3.0)
        for t in self._threads:
            if t is not curr and t.is_alive():
                rem = max(end_time - time.time(), 0.2)
                t.join(timeout=rem)
        if hasattr(self, "_firewall_thread") and self._firewall_thread is not curr and self._firewall_thread.is_alive():
            rem = max(end_time - time.time(), 0.2)
            self._firewall_thread.join(timeout=rem)

        # On Linux, release unmapped free heap arenas back to kernel upon worker teardown
        if sys.platform.startswith("linux"):
            try:
                import ctypes
                libc = ctypes.CDLL("libc.so.6")
                if hasattr(libc, "malloc_trim"):
                    libc.malloc_trim(0)
            except Exception:
                pass

        logger.info("Linux Agent stopped.")

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

    def _safe_worker(self, name: str, func) -> None:
        """Wrap a worker function with exception handling."""
        try:
            func()
        except Exception as exc:
            logger.error("Linux worker %s crashed: %s", name, exc, exc_info=True)

    # ── Telemetry Worker ────────────────────────────────────────

    def _telemetry_loop(self) -> None:
        """Collect and send Linux CPU, RAM, disk, network telemetry periodically."""
        logger.info("Linux telemetry worker running (interval=%ds)", config.TELEMETRY_INTERVAL)
        # Small stagger (0.1s) allows heartbeat to establish online status first
        self._stop_event.wait(timeout=0.1)

        while not self._stop_event.is_set():
            if not self.conn.is_authenticated:
                break
            try:
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
                        "Linux telemetry sent \u2014 CPU: %.1f%%, RAM: %.1f%%, Disk: %.1f%%",
                        cpu_data.get("cpu_usage", 0),
                        memory_data.get("memory_usage_percent", 0),
                        disk_data.get("disk_usage_percent", 0),
                    )
                else:
                    logger.warning("Linux telemetry transmission failed (buffered for retry)")

            except Exception as exc:
                logger.error("Linux telemetry collection/send error: %s", exc)

            self._stop_event.wait(timeout=config.TELEMETRY_INTERVAL)

    # ── Heartbeat Worker ────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        """Send heartbeat to Master periodically."""
        logger.info("Linux heartbeat worker running (interval=%ds)", config.HEARTBEAT_INTERVAL)

        while not self._stop_event.is_set():
            if not self.conn.is_authenticated:
                break
            try:
                success = self.conn.send_heartbeat(client_status="running")
                if success:
                    logger.debug("Linux heartbeat sent")
                else:
                    logger.warning("Linux heartbeat failed")
            except Exception as exc:
                logger.error("Linux heartbeat error: %s", exc)

            self._stop_event.wait(timeout=config.HEARTBEAT_INTERVAL)

    # ── Host Info Worker ────────────────────────────────────────

    def _host_info_loop(self) -> None:
        """Send Linux host info on startup and periodically."""
        logger.info("Linux host info worker running (interval=%ds)", config.HOST_INFO_INTERVAL)
        # Stagger initial host info send (0.3s) to avoid colliding with heartbeat and telemetry
        self._stop_event.wait(timeout=0.3)

        while not self._stop_event.is_set():
            if not self.conn.is_authenticated:
                break
            try:
                host_data = self._os_info.collect()
                success = self.conn.send_host_info(host_data)
                if success:
                    logger.info("Linux host info sent to Master")
                else:
                    logger.warning("Linux host info send failed")
            except Exception as exc:
                logger.error("Linux host info error: %s", exc)

            self._stop_event.wait(timeout=config.HOST_INFO_INTERVAL)

    # ── Event Monitor Worker ────────────────────────────────────

    def _event_loop(self) -> None:
        """Monitor Linux process start/stop events and send to Master."""
        logger.info("Linux event monitor running (interval=%ds)", config.EVENT_SCAN_INTERVAL)
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
                        logger.info("Sent %d Linux process event(s) to Master", len(events))
                    else:
                        logger.warning("Linux event send failed (%d events)", len(events))
            except Exception as exc:
                logger.error("Linux event monitor error: %s", exc)

            self._stop_event.wait(timeout=config.EVENT_SCAN_INTERVAL)
