"""
APEXEYE LINUX CLIENT — CPU Collector (Phase 3)

Collects Linux CPU telemetry:
  - Overall CPU usage percentage
  - Load averages (1m, 5m, 15m)
  - CPU core counts (logical + physical)
  - CPU frequency (current, min, max) where available
  - Per-core usage percentages
"""

import os
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.collectors.cpu")


class CPUCollector:
    """Collects Linux CPU telemetry data."""

    def __init__(self):
        self._prev_stat: tuple[int, int] | None = None
        if psutil:
            try:
                psutil.cpu_percent(interval=None)
                psutil.cpu_percent(percpu=True)
            except Exception:
                pass

    def collect(self) -> dict:
        """
        Collect a single CPU telemetry sample.
        Returns a timestamped dict with CPU metrics and Linux load averages.
        """
        try:
            # 1. Overall CPU usage
            cpu_usage = self._get_cpu_usage()

            # 2. Core counts
            logical_cores = os.cpu_count() or 1
            physical_cores = None
            if psutil:
                physical_cores = psutil.cpu_count(logical=False) or logical_cores

            # 3. Linux Load averages (1m, 5m, 15m)
            load_avg = None
            if hasattr(os, "getloadavg"):
                try:
                    lavg = os.getloadavg()
                    load_avg = {
                        "load_1m": round(lavg[0], 2),
                        "load_5m": round(lavg[1], 2),
                        "load_15m": round(lavg[2], 2),
                    }
                except Exception:
                    pass

            # 4. CPU frequency
            cpu_frequency = self._get_cpu_frequency()

            # 5. Per-core usage
            per_core = []
            if psutil:
                per_core = psutil.cpu_percent(percpu=True)

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            result = {
                "timestamp": timestamp,
                "cpu_usage": cpu_usage,
                "cpu_cores": logical_cores,
                "cpu_cores_physical": physical_cores,
                "cpu_frequency": cpu_frequency,
                "per_core_usage": per_core,
                "load_average": load_avg,
            }

            logger.debug("Linux CPU telemetry collected: %.1f%% usage", cpu_usage)
            return result

        except Exception as exc:
            logger.error("Failed to collect Linux CPU telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }

    def _get_cpu_usage(self) -> float:
        """Calculate CPU usage from psutil or /proc/stat."""
        if psutil:
            return round(psutil.cpu_percent(interval=None), 1)

        # Fallback to /proc/stat calculation on Linux
        proc_stat = Path("/proc/stat")
        if proc_stat.exists():
            try:
                line = proc_stat.read_text().splitlines()[0]
                fields = [int(x) for x in line.split()[1:]]
                idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
                total = sum(fields)

                if self._prev_stat:
                    prev_idle, prev_total = self._prev_stat
                    diff_idle = idle - prev_idle
                    diff_total = total - prev_total
                    self._prev_stat = (idle, total)
                    if diff_total > 0:
                        return round(100.0 * (1.0 - (diff_idle / diff_total)), 1)

                self._prev_stat = (idle, total)
                return 0.0
            except Exception:
                pass

        return 0.0

    def _get_cpu_frequency(self) -> dict | None:
        """Get CPU frequency from psutil or sysfs."""
        if psutil:
            freq = psutil.cpu_freq()
            if freq and freq.current:
                return {
                    "current_mhz": round(freq.current, 2),
                    "min_mhz": round(freq.min, 2) if freq.min else None,
                    "max_mhz": round(freq.max, 2) if freq.max else None,
                }

        # Fallback to /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq
        cur_freq_file = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
        if cur_freq_file.exists():
            try:
                khz = int(cur_freq_file.read_text().strip())
                return {"current_mhz": round(khz / 1000.0, 2)}
            except Exception:
                pass

        return None
