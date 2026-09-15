"""
APEXEYE LINUX CLIENT — OS / Host Information Collector (Phase 3)

Collects Linux host and distribution information:
  - Hostname & FQDN
  - Linux distribution name, version, ID (Ubuntu, Debian, Fedora, RHEL, etc.)
  - Kernel release & architecture (uname -r, x86_64, aarch64)
  - CPU model & core counts
  - Total RAM
  - System uptime & boot time (/proc/uptime)
  - Local IP address
"""

import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.collectors.os_info")


class OSInfoCollector:
    """Collects Linux host/OS information."""

    def collect(self) -> dict:
        """
        Collect Linux host identification data.
        Returns a dict compatible with Master device and host_details storage.
        """
        try:
            # 1. Distro info from /etc/os-release
            distro_info = self._parse_os_release()
            os_name = distro_info.get("NAME", "Linux")
            os_version = distro_info.get("VERSION", platform.version())
            os_pretty = distro_info.get("PRETTY_NAME", f"Linux {platform.release()}")

            # 2. Uptime & boot time
            uptime_seconds = self._get_uptime_seconds()
            boot_time = self._get_boot_time(uptime_seconds)

            # 3. RAM total
            ram_total_gb = self._get_ram_total_gb()

            # 4. CPU details
            cpu_model = self._get_cpu_model()
            logical_cores = os.cpu_count() or 1
            physical_cores = None
            cpu_max_freq = None
            if psutil:
                physical_cores = psutil.cpu_count(logical=False)
                freq = psutil.cpu_freq()
                if freq and freq.max:
                    cpu_max_freq = round(freq.max, 2)

            local_ip = self._get_local_ip()
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            result = {
                "timestamp": timestamp,
                "hostname": socket.gethostname(),
                "operating_system": os_name,
                "os_version": os_version,
                "os_release": platform.release(),
                "os_full": os_pretty,
                "distro_id": distro_info.get("ID", "linux"),
                "architecture": platform.machine(),
                "processor": cpu_model,
                "cpu_model": cpu_model,
                "cpu_cores_logical": logical_cores,
                "cpu_cores_physical": physical_cores or logical_cores,
                "cpu_max_freq_mhz": cpu_max_freq,
                "ram_total_gb": ram_total_gb,
                "local_ip": local_ip,
                "boot_time": boot_time,
                "uptime_seconds": uptime_seconds,
                "python_version": platform.python_version(),
                "machine_type": platform.machine(),
                "node": platform.node(),
            }

            logger.debug(
                "Linux host info collected: %s / %s / %s",
                result["hostname"], result["os_full"], result["architecture"],
            )
            return result

        except Exception as exc:
            logger.error("Failed to collect Linux host information: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }

    @staticmethod
    def _parse_os_release() -> dict[str, str]:
        """Parse /etc/os-release or /usr/lib/os-release."""
        for path in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
            if path.exists():
                try:
                    data = {}
                    for line in path.read_text(encoding="utf-8").splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            data[k.strip()] = v.strip('"\'')
                    return data
                except Exception:
                    pass
        return {}

    @staticmethod
    def _get_cpu_model() -> str:
        """Extract CPU model name from /proc/cpuinfo."""
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            try:
                for line in cpuinfo.read_text().splitlines():
                    if "model name" in line:
                        return line.split(":", 1)[1].strip()
                    if "Hardware" in line or "Processor" in line:
                        return line.split(":", 1)[1].strip()
            except Exception:
                pass
        return platform.processor() or "Linux CPU"

    @staticmethod
    def _get_uptime_seconds() -> int | None:
        """Read system uptime in seconds from /proc/uptime."""
        uptime_file = Path("/proc/uptime")
        if uptime_file.exists():
            try:
                first_val = uptime_file.read_text().split()[0]
                return int(float(first_val))
            except Exception:
                pass
        return None

    @staticmethod
    def _get_boot_time(uptime_sec: int | None) -> str:
        """Calculate boot time string."""
        if psutil:
            try:
                boot_ts = psutil.boot_time()
                return datetime.fromtimestamp(boot_ts, tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except Exception:
                pass

        if uptime_sec is not None:
            now_ts = datetime.now(timezone.utc).timestamp()
            boot_ts = now_ts - uptime_sec
            return datetime.fromtimestamp(boot_ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _get_ram_total_gb() -> float:
        """Get total RAM in GB."""
        if psutil:
            return round(psutil.virtual_memory().total / (1024 ** 3), 2)

        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            try:
                for line in meminfo.read_text().splitlines():
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return round(kb / (1024 ** 2), 2)
            except Exception:
                pass
        return 0.0

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
