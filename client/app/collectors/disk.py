"""
APEXEYE CLIENT — Disk Collector (Phase 2)

Collects disk telemetry using psutil:
  - Per-partition/drive information
  - Total space, used space, free space
  - Usage percentage
"""

from datetime import datetime, timezone

import psutil

from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.collectors.disk")


def _bytes_to_gb(b: int) -> float:
    """Convert bytes to gigabytes, rounded to 2 decimal places."""
    return round(b / (1024 ** 3), 2)


class DiskCollector:
    """Collects disk telemetry data."""

    def __init__(self, partition_ttl: float = 60.0):
        self._partition_ttl = partition_ttl
        self._cached_partitions = []
        self._cached_partitions_time = 0.0

    def _get_partitions(self):
        import time
        now = time.time()
        if self._cached_partitions and (now - self._cached_partitions_time) < self._partition_ttl:
            return self._cached_partitions
        try:
            parts = psutil.disk_partitions(all=False)
            if parts:
                self._cached_partitions = parts
                self._cached_partitions_time = now
                return parts
        except Exception:
            pass
        return self._cached_partitions or []

    def collect(self) -> dict:
        """
        Collect disk telemetry for all logical drives/partitions.

        Returns a timestamped dict with per-drive metrics.
        """
        try:
            partitions = self._get_partitions()
            drives = []
            total_bytes = 0
            used_bytes = 0

            for part in partitions:
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    drives.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_gb": _bytes_to_gb(usage.total),
                        "used_gb": _bytes_to_gb(usage.used),
                        "free_gb": _bytes_to_gb(usage.free),
                        "usage_percent": usage.percent,
                    })
                    total_bytes += usage.total
                    used_bytes += usage.used
                except PermissionError:
                    # Some drives may not be accessible (e.g. CD-ROM)
                    logger.debug(
                        "Skipping inaccessible partition: %s", part.device
                    )
                except Exception as exc:
                    logger.warning(
                        "Error reading partition %s: %s", part.device, exc
                    )

            overall_percent = round(
                (used_bytes / total_bytes * 100) if total_bytes > 0 else 0, 1
            )

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            result = {
                "timestamp": timestamp,
                "disk_usage_percent": overall_percent,
                "disk_total_gb": _bytes_to_gb(total_bytes),
                "disk_used_gb": _bytes_to_gb(used_bytes),
                "disk_free_gb": _bytes_to_gb(total_bytes - used_bytes),
                "drives": drives,
            }

            logger.debug(
                "Disk telemetry collected: %.1f%% overall usage, %d drives",
                overall_percent,
                len(drives),
            )
            return result

        except Exception as exc:
            logger.error("Failed to collect disk telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }


def _safe_disk_usage(mountpoint: str) -> bool:
    """Check if disk_usage can be read for a mountpoint."""
    try:
        psutil.disk_usage(mountpoint)
        return True
    except Exception:
        return False
