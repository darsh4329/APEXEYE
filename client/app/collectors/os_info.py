"""
APEXEYE CLIENT — OS / Host Information Collector (Phase 2)

Collects static and semi-static host information:
  - Hostname
  - Operating system and version
  - Windows version/build
  - CPU model / architecture
  - RAM total
  - Local IP
  - Boot time
  - System architecture
"""

import platform
import socket
from datetime import datetime, timezone

import psutil

from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.collectors.os_info")


class OSInfoCollector:
    """Collects host/OS information."""

    def collect(self) -> dict:
        """
        Collect host information.

        Returns a dict with system identification data.
        This is semi-static information that rarely changes.
        """
        try:
            # Boot time
            boot_ts = psutil.boot_time()
            boot_time = datetime.fromtimestamp(boot_ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # RAM total
            mem = psutil.virtual_memory()
            ram_total_gb = round(mem.total / (1024 ** 3), 2)

            # CPU info
            cpu_cores_logical = psutil.cpu_count(logical=True)
            cpu_cores_physical = psutil.cpu_count(logical=False)
            freq = psutil.cpu_freq()
            cpu_max_freq = round(freq.max, 2) if freq and freq.max else None

            # Local IP
            local_ip = self._get_local_ip()

            # OS version details
            os_version = platform.version()
            os_release = platform.release()

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            result = {
                "timestamp": timestamp,
                "hostname": socket.gethostname(),
                "operating_system": platform.system(),
                "os_version": os_version,
                "os_release": os_release,
                "os_full": f"{platform.system()} {os_release} (Build {os_version})",
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "cpu_model": platform.processor() or "Unknown",
                "cpu_cores_logical": cpu_cores_logical,
                "cpu_cores_physical": cpu_cores_physical,
                "cpu_max_freq_mhz": cpu_max_freq,
                "ram_total_gb": ram_total_gb,
                "local_ip": local_ip,
                "boot_time": boot_time,
                "python_version": platform.python_version(),
                "machine_type": platform.machine(),
                "node": platform.node(),
            }

            logger.debug(
                "Host info collected: %s / %s / %s",
                result["hostname"],
                result["os_full"],
                result["architecture"],
            )
            return result

        except Exception as exc:
            logger.error("Failed to collect host information: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }

    @staticmethod
    def _get_local_ip() -> str:
        """Best-effort local IP detection."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
