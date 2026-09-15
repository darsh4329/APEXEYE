"""
APEXEYE LINUX CLIENT — Disk Collector (Phase 3)

Collects Linux filesystem and mount point telemetry:
  - Per-mountpoint disk usage (ext4, btrfs, xfs, etc.)
  - Total space, used space, free space
  - Usage percentages and aggregate storage metrics
  - Filters out virtual/pseudo filesystems (proc, sysfs, tmpfs)
"""

import os
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.collectors.disk")

# Virtual filesystems to exclude on Linux
_EXCLUDED_FSTYPES = {
    "sysfs", "proc", "devtmpfs", "devpts", "tmpfs", "securityfs",
    "cgroup", "cgroup2", "pstore", "bpf", "autofs", "mqueue",
    "debugfs", "tracefs", "hugetlbfs", "fusectl", "configfs", "ramfs",
}


def _bytes_to_gb(b: int) -> float:
    """Convert bytes to gigabytes, rounded to 2 decimal places."""
    return round(b / (1024 ** 3), 2)


class DiskCollector:
    """Collects Linux disk telemetry data."""

    def __init__(self, partition_ttl: float = 60.0):
        self._partition_ttl = partition_ttl
        self._cached_partitions = []
        self._cached_partitions_time = 0.0

    def _get_partitions(self):
        import time
        now = time.time()
        if self._cached_partitions and (now - self._cached_partitions_time) < self._partition_ttl:
            return self._cached_partitions
        if psutil:
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
        Collect disk telemetry for all physical/real mounts.
        Returns a timestamped dict with per-drive metrics and aggregate storage.
        """
        try:
            drives = []
            total_bytes = 0
            used_bytes = 0

            partitions = self._get_partitions()
            if partitions:
                for part in partitions:
                    if part.fstype in _EXCLUDED_FSTYPES:
                        continue
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
                    except Exception:
                        continue
            else:
                # Native Linux fallback: parse /proc/mounts and use os.statvfs
                drives, total_bytes, used_bytes = self._collect_via_statvfs()

            overall_percent = round(
                (used_bytes / total_bytes * 100.0) if total_bytes > 0 else 0.0, 1
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
                "Linux disk telemetry collected: %.1f%% overall usage, %d mount points",
                overall_percent, len(drives),
            )
            return result

        except Exception as exc:
            logger.error("Failed to collect Linux disk telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }

    def _collect_via_statvfs(self) -> tuple[list[dict], int, int]:
        """Native fallback using os.statvfs on Linux."""
        drives = []
        total_bytes = 0
        used_bytes = 0

        mounts_file = Path("/proc/mounts")
        seen_mounts = set()

        if mounts_file.exists():
            try:
                for line in mounts_file.read_text().splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        dev, mount, fstype = parts[0], parts[1], parts[2]
                        if fstype in _EXCLUDED_FSTYPES or mount in seen_mounts:
                            continue
                        if not dev.startswith("/dev/"):
                            continue

                        seen_mounts.add(mount)
                        try:
                            st = os.statvfs(mount)
                            t_b = st.f_blocks * st.f_frsize
                            f_b = st.f_bavail * st.f_frsize
                            u_b = t_b - f_b
                            pct = round((u_b / t_b * 100.0) if t_b > 0 else 0.0, 1)

                            drives.append({
                                "device": dev,
                                "mountpoint": mount,
                                "fstype": fstype,
                                "total_gb": _bytes_to_gb(t_b),
                                "used_gb": _bytes_to_gb(u_b),
                                "free_gb": _bytes_to_gb(f_b),
                                "usage_percent": pct,
                            })
                            total_bytes += t_b
                            used_bytes += u_b
                        except Exception:
                            continue
            except Exception:
                pass

        return drives, total_bytes, used_bytes
