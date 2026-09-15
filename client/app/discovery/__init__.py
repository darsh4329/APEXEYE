"""
APEXEYE CLIENT — Automatic Master Discovery Module

Implements multi-layer Master endpoint resolution:
1. Explicit APEXEYE_MASTER_URL (Environment variable / .env)
2. Automatic LAN Master discovery (UDP 9101 subnet-directed broadcast probe + beacon listener)
3. Stable Hostname / local DNS discovery (apexeye-master, mDNS, Master hostname)
4. Cached previously verified Master endpoint (.apexeye_master_cache.json)
5. Localhost development fallback (http://127.0.0.1:9100)

Every candidate endpoint is strictly verified using:
  - TCP port connection test
  - HTTP GET /api/health returning status="healthy"

Automatic IP-change recovery:
  When connection to Master fails, discover_master(force_rediscovery=True) can be invoked
  to dynamically find the new Master IP and update active configurations without dropping
  authentication tokens or requiring .env edits.
"""

import ipaddress
import json
import os
import re
import socket
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Set
from urllib.parse import urlparse

try:
    import psutil
except ImportError:
    psutil = None

DISCOVERY_UDP_PORT = int(os.getenv("APEXEYE_DISCOVERY_PORT", "9101"))
DEFAULT_MASTER_PORT = 9100

_VIRTUAL_NAME_PATTERNS = re.compile(
    r"(virtualbox|vbox|vmware|vethernet|hyper-v|docker|wsl|tap|tun|loopback|npcap|pcap)",
    re.IGNORECASE,
)

_IGNORED_IP_PREFIXES = (
    "127.",        # Loopback
    "169.254.",    # Link-local / APIPA
    "0.0.0.0",     # Any
)

_VIRTUAL_HOST_ONLY_SUBNETS = [
    ipaddress.ip_network("192.168.56.0/24"),
]


def is_virtual_or_link_local_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is loopback, link-local, or in a known virtual subnet."""
    if not ip_str or any(ip_str.startswith(p) for p in _IGNORED_IP_PREFIXES):
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
            return True
        for subnet in _VIRTUAL_HOST_ONLY_SUBNETS:
            if ip_obj in subnet:
                return True
    except ValueError:
        return True
    return False


def get_active_subnet_broadcasts() -> List[str]:
    """
    Enumerate active physical network interfaces and calculate their subnet broadcast addresses.
    Excludes loopback (127.x.x.x), link-local (169.254.x.x), VirtualBox host-only (192.168.56.x),
    and virtual adapters.
    Always includes global broadcast (255.255.255.255).
    """
    broadcasts: Set[str] = {"255.255.255.255"}

    # 1. psutil interface scan
    if psutil is not None:
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()

            for iface_name, addr_list in addrs.items():
                iface_stat = stats.get(iface_name)
                is_up = iface_stat.isup if iface_stat else True
                if not is_up:
                    continue

                if _VIRTUAL_NAME_PATTERNS.search(iface_name):
                    continue

                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if is_virtual_or_link_local_ip(ip):
                            continue

                        # Explicit broadcast attribute if available
                        if getattr(addr, "broadcast", None) and addr.broadcast:
                            broadcasts.add(addr.broadcast)

                        # Netmask-derived subnet broadcast
                        if getattr(addr, "netmask", None) and addr.netmask:
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{addr.netmask}", strict=False)
                                broadcasts.add(str(network.broadcast_address))
                            except Exception:
                                pass

                        # Standard /24 subnet broadcast fallback
                        parts = ip.split(".")
                        if len(parts) == 4:
                            broadcasts.add(f"{parts[0]}.{parts[1]}.{parts[2]}.255")
        except Exception:
            pass

    # 2. Hostname address enumeration fallback
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not is_virtual_or_link_local_ip(ip):
                parts = ip.split(".")
                if len(parts) == 4:
                    broadcasts.add(f"{parts[0]}.{parts[1]}.{parts[2]}.255")
    except Exception:
        pass

    # 3. Kernel routing lookup fallback
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if not is_virtual_or_link_local_ip(ip):
                parts = ip.split(".")
                if len(parts) == 4:
                    broadcasts.add(f"{parts[0]}.{parts[1]}.{parts[2]}.255")
    except Exception:
        pass

    return sorted(list(broadcasts))


def get_cache_file_path() -> Path:
    """Determine path to local Master endpoint cache file."""
    try:
        from client.app.config import find_env_file
        env_p = find_env_file()
        if env_p:
            return env_p.parent / ".apexeye_master_cache.json"
    except Exception:
        pass

    cwd_cache = Path.cwd() / ".apexeye_master_cache.json"
    if (Path.cwd() / "client").is_dir():
        return Path.cwd() / "client" / ".apexeye_master_cache.json"
    return cwd_cache


def load_cached_master(cache_path: Optional[Path] = None) -> Optional[dict]:
    """Load the last verified Master endpoint from cache."""
    path = cache_path or get_cache_file_path()
    if not path or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text("utf-8"))
        if isinstance(data, dict) and data.get("url"):
            return data
    except Exception:
        pass
    return None


def save_cached_master(url: str, hostname: str = "", source: str = "", cache_path: Optional[Path] = None) -> None:
    """Save a verified Master endpoint to local cache."""
    path = cache_path or get_cache_file_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "url": url.rstrip("/"),
            "hostname": hostname,
            "source": source,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(json.dumps(payload, indent=2), "utf-8")
    except Exception:
        pass


def verify_master_endpoint(candidate_url: str, timeout: float = 2.0) -> Tuple[bool, dict]:
    """
    Verify candidate Master endpoint:
    1. Parse host & port.
    2. TCP socket connection check.
    3. HTTP GET /api/health check (status == "healthy").
    """
    if not candidate_url:
        return False, {"error": "Empty URL"}

    clean_url = candidate_url.rstrip("/")
    try:
        parsed = urlparse(clean_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else DEFAULT_MASTER_PORT)
    except Exception as exc:
        return False, {"error": f"Invalid URL format: {exc}"}

    # 1. TCP connection check
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except Exception as exc:
        return False, {"error": f"TCP {port} unreachable on {host}: {exc}"}

    # 2. HTTP GET /api/health check
    health_url = f"{clean_url}/api/health"
    try:
        req = urllib.request.Request(health_url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                if isinstance(body, dict) and body.get("status") == "healthy":
                    return True, body
                return False, {"error": f"Unexpected health response: {body}"}
    except Exception as exc:
        return False, {"error": f"Health check failed: {exc}"}

    return False, {"error": "Verification failed"}


class MasterDiscoverer:
    """Multi-tier discovery engine for APEXEYE Master."""

    def __init__(self, discovery_port: int = DISCOVERY_UDP_PORT):
        self.discovery_port = discovery_port

    def discover_via_udp_lan(self, timeout: float = 2.0) -> Optional[Tuple[str, str]]:
        """
        Broadcast UDP discovery probes on LAN and subnet broadcasts and listen for Master responses.
        Returns (verified_url, source_description) or None.
        """
        sock = None
        candidates: List[Tuple[str, str, int]] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.4)

            probe_payload = json.dumps({"query": "APEXEYE_DISCOVERY"}).encode("utf-8")
            target_broadcasts = get_active_subnet_broadcasts()

            start_time = time.time()
            probe_attempts = 0
            max_probe_bursts = 3
            last_burst_time = 0.0

            while (time.time() - start_time) < timeout:
                now = time.time()
                # Send periodic probe bursts to mitigate Wi-Fi packet drops
                if probe_attempts < max_probe_bursts and (now - last_burst_time) >= 0.25:
                    for bcast in target_broadcasts:
                        try:
                            sock.sendto(probe_payload, (bcast, self.discovery_port))
                        except Exception:
                            pass
                    last_burst_time = now
                    probe_attempts += 1

                try:
                    data, addr = sock.recvfrom(2048)
                    if not data:
                        continue
                    resp = json.loads(data.decode("utf-8", errors="ignore"))
                    if isinstance(resp, dict) and resp.get("service") == "APEXEYE_MASTER":
                        lan_ip = resp.get("lan_ip") or addr[0]
                        port = int(resp.get("port", DEFAULT_MASTER_PORT))
                        hostname = resp.get("hostname", "")
                        cand = (lan_ip, hostname, port)
                        if cand not in candidates:
                            candidates.append(cand)
                            cand_url = f"http://{lan_ip}:{port}"
                            ok, _ = verify_master_endpoint(cand_url, timeout=1.5)
                            if ok:
                                save_cached_master(cand_url, hostname=hostname, source=f"LAN discovery ({lan_ip}:{port})")
                                return cand_url, f"LAN discovery ({lan_ip}:{port})"
                except (socket.timeout, TimeoutError):
                    pass
                except Exception:
                    pass

        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        # Fallback verify any remaining collected candidates
        for ip, host_name, port in candidates:
            cand_url = f"http://{ip}:{port}"
            ok, _ = verify_master_endpoint(cand_url, timeout=1.5)
            if ok:
                save_cached_master(cand_url, hostname=host_name, source=f"LAN discovery ({ip}:{port})")
                return cand_url, f"LAN discovery ({ip}:{port})"

        return None

    def discover_via_hostnames(self) -> Optional[Tuple[str, str]]:
        """
        Attempt resolving stable Master hostnames (e.g. apexeye-master, cached hostname).
        Returns (verified_url, source_description) or None.
        """
        hostname_candidates = ["apexeye-master", "apexeye-master.local"]

        cached = load_cached_master()
        if cached and cached.get("hostname"):
            h = cached["hostname"]
            if h not in hostname_candidates:
                hostname_candidates.append(h)

        for name in hostname_candidates:
            cand_url = f"http://{name}:{DEFAULT_MASTER_PORT}"
            ok, _ = verify_master_endpoint(cand_url, timeout=1.2)
            if ok:
                save_cached_master(cand_url, hostname=name, source=f"hostname discovery ({name}:{DEFAULT_MASTER_PORT})")
                return cand_url, f"hostname discovery ({name}:{DEFAULT_MASTER_PORT})"

        return None

    def discover_via_cache(self) -> Optional[Tuple[str, str]]:
        """
        Attempt connecting to the previously cached Master endpoint.
        Returns (verified_url, source_description) or None.
        """
        cached = load_cached_master()
        if not cached or not cached.get("url"):
            return None

        url = cached["url"]
        ok, _ = verify_master_endpoint(url, timeout=1.5)
        if ok:
            parsed = urlparse(url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or DEFAULT_MASTER_PORT
            return url, f"cached Master endpoint ({host}:{port})"

        return None

    def resolve(
        self,
        explicit_url: Optional[str] = None,
        explicit_source: Optional[str] = None,
        allow_cache: bool = True,
        allow_fallback: bool = True,
    ) -> Tuple[str, str]:
        """
        Full layered resolution:
        1. If explicit_url is provided and verified -> use it.
        2. If explicit_url provided but unreachable -> attempt LAN discovery as recovery.
        3. Automatic LAN discovery.
        4. Hostname discovery.
        5. Cached Master endpoint.
        6. Default localhost fallback.
        """
        # 1. Explicit override check
        if explicit_url:
            clean_explicit = explicit_url.rstrip("/")
            ok, _ = verify_master_endpoint(clean_explicit, timeout=2.0)
            if ok:
                src = explicit_source or "environment (APEXEYE_MASTER_URL)"
                parsed = urlparse(clean_explicit)
                save_cached_master(clean_explicit, hostname=parsed.hostname or "", source=src)
                return clean_explicit, src

        # 2. LAN Master Discovery
        lan_result = self.discover_via_udp_lan(timeout=2.0)
        if lan_result:
            return lan_result

        # 3. Hostname discovery
        host_result = self.discover_via_hostnames()
        if host_result:
            return host_result

        # 4. Cached endpoint
        if allow_cache:
            cache_result = self.discover_via_cache()
            if cache_result:
                return cache_result

        # 5. If explicit URL was supplied (even if unreachable at startup), retain it rather than localhost if non-loopback
        if explicit_url:
            src = explicit_source or "environment (APEXEYE_MASTER_URL)"
            return explicit_url.rstrip("/"), src

        # 6. Localhost fallback
        if allow_fallback:
            return f"http://127.0.0.1:{DEFAULT_MASTER_PORT}", "default (localhost fallback)"

        return f"http://127.0.0.1:{DEFAULT_MASTER_PORT}", "default (localhost fallback)"


master_discoverer = MasterDiscoverer()
