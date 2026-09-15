"""
APEXEYE CLIENT — Memory (RAM) Collector (Phase 2)

Collects RAM telemetry using psutil:
  - Total RAM
  - Used RAM
  - Available RAM
  - RAM usage percentage
"""

from datetime import datetime, timezone

import psutil

from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.collectors.memory")


def _bytes_to_gb(b: int) -> float:
    """Convert bytes to gigabytes, rounded to 2 decimal places."""
    return round(b / (1024 ** 3), 2)


class MemoryCollector:
    """Collects RAM telemetry data."""

    def collect(self) -> dict:
        """
        Collect a single RAM telemetry sample.

        Returns a timestamped dict with memory metrics.
        """
        try:
            mem = psutil.virtual_memory()

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            result = {
                "timestamp": timestamp,
                "memory_total_gb": _bytes_to_gb(mem.total),
                "memory_used_gb": _bytes_to_gb(mem.used),
                "memory_available_gb": _bytes_to_gb(mem.available),
                "memory_usage_percent": mem.percent,
                "memory_total_bytes": mem.total,
                "memory_used_bytes": mem.used,
                "memory_available_bytes": mem.available,
            }

            logger.debug(
                "RAM telemetry collected: %.1f%% usage (%.2f / %.2f GB)",
                mem.percent,
                _bytes_to_gb(mem.used),
                _bytes_to_gb(mem.total),
            )
            return result

        except Exception as exc:
            logger.error("Failed to collect RAM telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }
