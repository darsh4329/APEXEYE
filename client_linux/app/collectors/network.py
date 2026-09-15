"""
APEXEYE LINUX CLIENT — Network Collector (Phase 3)

Collects Linux network interface telemetry and I/O statistics:
  - Network interface details (eth0, ens33, wlan0, lo, etc.)
  - IP addresses (IPv4 & IPv6) and link state
  - Bytes and packets transmitted and received
  - Error and drop counts
"""

from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.collectors.network")


def _bytes_to_mb(b: int) -> float:
    """Convert bytes to megabytes, rounded to 2 decimal places."""
    return round(b / (1024 ** 2), 2)


class NetworkCollector:
    """Collects Linux network telemetry data."""

    def collect(self) -> dict:
        """
        Collect network telemetry for all network interfaces.
        Returns a timestamped dict with per-interface metrics and aggregate stats.
        """
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            if psutil:
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                io_counters = psutil.net_io_counters(pernic=True)
                overall_io = psutil.net_io_counters()

                interfaces = []
                for iface_name, addr_list in addrs.items():
                    iface_info = {
                        "name": iface_name,
                        "addresses": [],
                        "is_up": False,
                        "speed_mbps": 0,
                        "bytes_sent_mb": 0.0,
                        "bytes_recv_mb": 0.0,
                    }

                    for addr in addr_list:
                        if addr.family.name in ("AF_INET", "AF_INET6"):
                            iface_info["addresses"].append({
                                "family": addr.family.name,
                                "address": addr.address,
                                "netmask": addr.netmask,
                            })

                    if iface_name in stats:
                        st = stats[iface_name]
                        iface_info["is_up"] = st.isup
                        iface_info["speed_mbps"] = st.speed

                    if iface_name in io_counters:
                        io = io_counters[iface_name]
                        iface_info["bytes_sent_mb"] = _bytes_to_mb(io.bytes_sent)
                        iface_info["bytes_recv_mb"] = _bytes_to_mb(io.bytes_recv)
                        iface_info["packets_sent"] = io.packets_sent
                        iface_info["packets_recv"] = io.packets_recv
                        iface_info["errors_in"] = io.errin
                        iface_info["errors_out"] = io.errout

                    interfaces.append(iface_info)

                result = {
                    "timestamp": timestamp,
                    "network_bytes_sent_mb": _bytes_to_mb(overall_io.bytes_sent),
                    "network_bytes_recv_mb": _bytes_to_mb(overall_io.bytes_recv),
                    "interfaces": interfaces,
                }
                logger.debug(
                    "Linux network collected: %d interfaces, sent=%.1f MB, recv=%.1f MB",
                    len(interfaces), _bytes_to_mb(overall_io.bytes_sent), _bytes_to_mb(overall_io.bytes_recv),
                )
                return result

            # Native Linux fallback: /proc/net/dev
            interfaces, total_sent, total_recv = self._parse_proc_net_dev()
            return {
                "timestamp": timestamp,
                "network_bytes_sent_mb": _bytes_to_mb(total_sent),
                "network_bytes_recv_mb": _bytes_to_mb(total_recv),
                "interfaces": interfaces,
            }

        except Exception as exc:
            logger.error("Failed to collect Linux network telemetry: %s", exc)
            return {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
            }

    @staticmethod
    def _parse_proc_net_dev() -> tuple[list[dict], int, int]:
        """Parse /proc/net/dev on Linux."""
        path = Path("/proc/net/dev")
        if not path.exists():
            return [], 0, 0

        interfaces = []
        total_sent = 0
        total_recv = 0

        try:
            lines = path.read_text().splitlines()[2:]
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    name = parts[0].strip()
                    cols = parts[1].split()
                    recv_b = int(cols[0])
                    sent_b = int(cols[8])
                    total_recv += recv_b
                    total_sent += sent_b

                    interfaces.append({
                        "name": name,
                        "addresses": [],
                        "is_up": True,
                        "bytes_sent_mb": _bytes_to_mb(sent_b),
                        "bytes_recv_mb": _bytes_to_mb(recv_b),
                        "packets_recv": int(cols[1]),
                        "packets_sent": int(cols[9]),
                    })
        except Exception:
            pass

        return interfaces, total_sent, total_recv
