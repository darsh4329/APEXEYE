"""
APEXEYE CLIENT — Network Collector (Phase 2)

Collects network telemetry using psutil:
  - Network interface information
  - Interface state (up/down)
  - IP addresses
  - Bytes sent/received per interface
  - Connection statistics
"""

from datetime import datetime, timezone

import psutil

from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.collectors.network")


def _bytes_to_mb(b: int) -> float:
    """Convert bytes to megabytes, rounded to 2 decimal places."""
    return round(b / (1024 ** 2), 2)


class NetworkCollector:
    """Collects network telemetry data."""

    def collect(self) -> dict:
        """
        Collect network telemetry for all interfaces.

        Returns a timestamped dict with per-interface metrics
        and aggregate connection statistics.
        """
        try:
            # Interface addresses
            addrs = psutil.net_if_addrs()

            # Interface stats (up/down, speed, etc.)
            stats = psutil.net_if_stats()

            # I/O counters per interface
            io_counters = psutil.net_io_counters(pernic=True)

            # Overall I/O counters
            overall_io = psutil.net_io_counters()

            interfaces = []
            for iface_name in addrs:
                iface_info = {
                    "name": iface_name,
                    "addresses": [],
                    "is_up": False,
                    "speed_mbps": 0,
                    "bytes_sent_mb": 0,
                    "bytes_recv_mb": 0,
                }

                # Addresses (IPv4 only for brevity)
                for addr in addrs[iface_name]:
                    if addr.family.name in ("AF_INET", "AF_INET6"):
                        iface_info["addresses"].append({
                            "family": addr.family.name,
                            "address": addr.address,
                            "netmask": addr.netmask,
                        })

                # Stats
                if iface_name in stats:
                    st = stats[iface_name]
                    iface_info["is_up"] = st.isup
                    iface_info["speed_mbps"] = st.speed

                # I/O
                if iface_name in io_counters:
                    io = io_counters[iface_name]
                    iface_info["bytes_sent_mb"] = _bytes_to_mb(io.bytes_sent)
                    iface_info["bytes_recv_mb"] = _bytes_to_mb(io.bytes_recv)
                    iface_info["packets_sent"] = io.packets_sent
                    iface_info["packets_recv"] = io.packets_recv
                    iface_info["errors_in"] = io.errin
                    iface_info["errors_out"] = io.errout

                interfaces.append(iface_info)

            # Connection statistics (counts by status) - empty dict avoids expensive OS socket table scans
            conn_stats = {}

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            result = {
                "timestamp": timestamp,
                "network_bytes_sent_mb": _bytes_to_mb(overall_io.bytes_sent),
                "network_bytes_recv_mb": _bytes_to_mb(overall_io.bytes_recv),
                "interfaces": interfaces,
                "connection_stats": conn_stats,
            }

            logger.debug(
                "Network telemetry collected: %d interfaces, sent=%.1f MB, recv=%.1f MB",
                len(interfaces),
                _bytes_to_mb(overall_io.bytes_sent),
                _bytes_to_mb(overall_io.bytes_recv),
            )
            return result

        except Exception as exc:
            logger.error("Failed to collect network telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }
