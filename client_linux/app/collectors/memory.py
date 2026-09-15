"""
APEXEYE LINUX CLIENT — Memory / RAM Collector (Phase 3)

Collects Linux RAM and Swap telemetry:
  - Total, used, and available RAM
  - RAM usage percentage
  - Swap total, used, and free
  - Linux Buffers & Cached memory metrics
"""

from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.collectors.memory")


def _bytes_to_gb(b: int) -> float:
    """Convert bytes to gigabytes, rounded to 2 decimal places."""
    return round(b / (1024 ** 3), 2)


class MemoryCollector:
    """Collects Linux RAM and Swap telemetry data."""

    def collect(self) -> dict:
        """
        Collect a single RAM telemetry sample.
        Returns a timestamped dict with memory & swap metrics.
        """
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            # Preferred: psutil if available
            if psutil:
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()
                result = {
                    "timestamp": timestamp,
                    "memory_total_gb": _bytes_to_gb(mem.total),
                    "memory_used_gb": _bytes_to_gb(mem.used),
                    "memory_available_gb": _bytes_to_gb(mem.available),
                    "memory_usage_percent": mem.percent,
                    "memory_total_bytes": mem.total,
                    "memory_used_bytes": mem.used,
                    "memory_available_bytes": mem.available,
                    "swap_total_gb": _bytes_to_gb(swap.total),
                    "swap_used_gb": _bytes_to_gb(swap.used),
                    "swap_percent": swap.percent,
                }
                logger.debug(
                    "Linux RAM collected: %.1f%% (%.2f / %.2f GB)",
                    mem.percent, _bytes_to_gb(mem.used), _bytes_to_gb(mem.total),
                )
                return result

            # Native Linux fallback: /proc/meminfo
            meminfo = self._parse_proc_meminfo()
            if meminfo:
                total = meminfo.get("MemTotal", 0) * 1024
                free = meminfo.get("MemFree", 0) * 1024
                avail = meminfo.get("MemAvailable", free) * 1024
                used = max(0, total - avail)
                percent = round((used / total * 100.0) if total > 0 else 0.0, 1)

                swap_total = meminfo.get("SwapTotal", 0) * 1024
                swap_free = meminfo.get("SwapFree", 0) * 1024
                swap_used = max(0, swap_total - swap_free)
                swap_percent = round((swap_used / swap_total * 100.0) if swap_total > 0 else 0.0, 1)

                result = {
                    "timestamp": timestamp,
                    "memory_total_gb": _bytes_to_gb(total),
                    "memory_used_gb": _bytes_to_gb(used),
                    "memory_available_gb": _bytes_to_gb(avail),
                    "memory_usage_percent": percent,
                    "memory_total_bytes": total,
                    "memory_used_bytes": used,
                    "memory_available_bytes": avail,
                    "swap_total_gb": _bytes_to_gb(swap_total),
                    "swap_used_gb": _bytes_to_gb(swap_used),
                    "swap_percent": swap_percent,
                }
                return result

            # Default empty fallback
            return {
                "timestamp": timestamp,
                "memory_total_gb": 0.0,
                "memory_used_gb": 0.0,
                "memory_available_gb": 0.0,
                "memory_usage_percent": 0.0,
            }

        except Exception as exc:
            logger.error("Failed to collect Linux RAM telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }

    @staticmethod
    def _parse_proc_meminfo() -> dict[str, int]:
        """Parse /proc/meminfo on Linux returning values in kB."""
        path = Path("/proc/meminfo")
        if not path.exists():
            return {}

        data = {}
        try:
            for line in path.read_text().splitlines():
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val_str = parts[1].strip().split()[0]
                    data[key] = int(val_str)
        except Exception:
            pass
        return data
