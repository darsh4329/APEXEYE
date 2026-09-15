"""
APEXEYE CLIENT — CPU Collector (Phase 2)

Collects CPU telemetry using psutil:
  - Overall CPU usage percentage
  - CPU core count (logical + physical)
  - CPU frequency (current, min, max) where available
  - Per-core usage percentages
"""

from datetime import datetime, timezone

import psutil

from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.collectors.cpu")


class CPUCollector:
    """Collects CPU telemetry data."""

    def __init__(self):
        # Establish baseline reference sample so subsequent non-blocking calls return accurate deltas
        try:
            psutil.cpu_percent(interval=None)
            psutil.cpu_percent(percpu=True)
        except Exception:
            pass

    def collect(self) -> dict:
        """
        Collect a single CPU telemetry sample.

        Returns a timestamped dict with CPU metrics.
        Uses non-blocking delta measurement since previous sample to eliminate collector delay.
        """
        try:
            # Overall CPU usage (non-blocking delta since previous sample)
            cpu_usage = psutil.cpu_percent(interval=None)

            # Core counts
            logical_cores = psutil.cpu_count(logical=True)
            physical_cores = psutil.cpu_count(logical=False)

            # CPU frequency (may not be available on all systems)
            freq = psutil.cpu_freq()
            cpu_frequency = None
            if freq:
                cpu_frequency = {
                    "current_mhz": round(freq.current, 2),
                    "min_mhz": round(freq.min, 2),
                    "max_mhz": round(freq.max, 2),
                }

            # Per-core usage (non-blocking, uses delta since last call)
            per_core = psutil.cpu_percent(percpu=True)

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            result = {
                "timestamp": timestamp,
                "cpu_usage": cpu_usage,
                "cpu_cores": logical_cores,
                "cpu_cores_physical": physical_cores,
                "cpu_frequency": cpu_frequency,
                "per_core_usage": per_core,
            }

            logger.debug("CPU telemetry collected: %.1f%% usage", cpu_usage)
            return result

        except Exception as exc:
            logger.error("Failed to collect CPU telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }
