"""
APEXEYE MASTER — Network Discovery & Interface Management Utility

Provides reliable local LAN IPv4 address discovery, distinguishes physical
Wi-Fi/Ethernet adapters from virtual/host-only adapters (VirtualBox, VMware, Docker,
APIPA/link-local), and formats diagnostic connection information for clients.
"""

import ipaddress
import os
import re
import socket
from typing import List, Dict, Optional

try:
    import psutil
except ImportError:
    psutil = None


# Subnets and interface keywords known to be virtual, host-only, link-local, or VPN
_VIRTUAL_NAME_PATTERNS = re.compile(
    r"(virtualbox|vbox|vmware|vethernet|hyper-v|docker|wsl|tap|tun|loopback|npcap|pcap)",
    re.IGNORECASE,
)

_IGNORED_IP_PREFIXES = (
    "127.",        # Loopback
    "169.254.",    # Link-local / APIPA
    "0.0.0.0",     # Any
)

# Known default host-only subnets (e.g. VirtualBox default 192.168.56.0/24)
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


def get_lan_interfaces() -> List[Dict[str, str]]:
    """
    Enumerate all network interfaces with their IPv4 addresses, classifying each.
    
    Returns a list of dicts:
      [
        {
          "name": "Wi-Fi",
          "ip": "10.177.134.109",
          "type": "physical",      # "physical", "virtual", "vpn", or "link-local"
          "is_primary": True,
          "description": "Realtek 8821CE Wireless LAN" (if available)
        },
        ...
      ]
    """
    interfaces: List[Dict[str, str]] = []
    primary_ip = get_primary_lan_ip()

    if psutil is not None:
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()

            for iface_name, addr_list in addrs.items():
                iface_stat = stats.get(iface_name)
                # If interface is explicitly down, skip or mark down
                is_up = iface_stat.isup if iface_stat else True

                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if ip.startswith("127."):
                            continue

                        # Determine classification
                        is_virtual_name = bool(_VIRTUAL_NAME_PATTERNS.search(iface_name))
                        is_virtual_ip = is_virtual_or_link_local_ip(ip)

                        if ip.startswith("169.254."):
                            if_type = "link-local"
                        elif is_virtual_name or is_virtual_ip:
                            if_type = "virtual"
                        elif "vpn" in iface_name.lower() or "tap" in iface_name.lower():
                            if_type = "vpn"
                        else:
                            if_type = "physical"

                        interfaces.append({
                            "name": iface_name,
                            "ip": ip,
                            "type": if_type,
                            "is_up": is_up,
                            "is_primary": (ip == primary_ip),
                        })
        except Exception:
            pass

    # Fallback if psutil found no candidate physical interfaces
    if not interfaces:
        candidate = primary_ip
        if candidate and not candidate.startswith("127."):
            interfaces.append({
                "name": "Default Interface",
                "ip": candidate,
                "type": "physical",
                "is_up": True,
                "is_primary": True,
            })

    return interfaces


def get_primary_lan_ip() -> str:
    """
    Determine the primary reachable LAN IPv4 address of the Master host.
    
    1. Checks explicit APEXEYE_ADVERTISE_IP / APEXEYE_MASTER_ADVERTISE_IP environment variable.
    2. Uses UDP routing query (connects UDP socket to 8.8.8.8 without sending packets).
    3. Scans psutil physical/Wi-Fi interfaces.
    4. Falls back to socket.gethostbyname(hostname) or 127.0.0.1.
    """
    # 1. Explicit override (support both names)
    override = (os.getenv("APEXEYE_ADVERTISE_IP") or os.getenv("APEXEYE_MASTER_ADVERTISE_IP") or "").strip()
    if override:
        try:
            ip_obj = ipaddress.ip_address(override)
            if not (ip_obj.is_loopback or ip_obj.is_unspecified):
                return override
        except ValueError:
            pass

    # 2. Kernel routing table lookup via UDP socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # 8.8.8.8 is used merely to resolve routing table; no packet is transmitted
            s.connect(("8.8.8.8", 80))
            candidate = s.getsockname()[0]
            if candidate and not is_virtual_or_link_local_ip(candidate):
                return candidate
    except Exception:
        pass

    # 3. psutil interface scan — search for physical up interface
    if psutil is not None:
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()

            # Prefer Wi-Fi / Ethernet
            preferred_candidates = []
            other_candidates = []

            for name, addr_list in addrs.items():
                is_up = stats[name].isup if name in stats else True
                if not is_up:
                    continue
                if _VIRTUAL_NAME_PATTERNS.search(name):
                    continue

                for a in addr_list:
                    if a.family == socket.AF_INET:
                        ip = a.address
                        if not is_virtual_or_link_local_ip(ip):
                            lower_name = name.lower()
                            if "wi-fi" in lower_name or "wireless" in lower_name or "wlan" in lower_name:
                                preferred_candidates.insert(0, ip)
                            elif "ethernet" in lower_name or "eth" in lower_name or "en" in lower_name:
                                preferred_candidates.append(ip)
                            else:
                                other_candidates.append(ip)

            if preferred_candidates:
                return preferred_candidates[0]
            if other_candidates:
                return other_candidates[0]
        except Exception:
            pass

    # 4. Fallback hostname resolution
    try:
        hostname = socket.gethostname()
        candidate = socket.gethostbyname(hostname)
        if candidate and not candidate.startswith("127.") and not is_virtual_or_link_local_ip(candidate):
            return candidate
    except Exception:
        pass

    return "127.0.0.1"


def format_network_banner(host: str, port: int) -> str:
    """Format a detailed network diagnostic banner for Master startup."""
    primary_ip = get_primary_lan_ip()
    interfaces = get_lan_interfaces()

    lines = [
        "=" * 60,
        "APEXEYE MASTER -- NETWORK CONFIGURATION & LISTENER",
        "=" * 60,
        f"Server Listener       : {host}:{port}",
        f"Master Local Admin UI : http://127.0.0.1:{port}",
        f"Detected Primary LAN  : http://{primary_ip}:{port}",
        "",
        "Available Network Interfaces on Master Host:",
    ]

    if interfaces:
        for iface in interfaces:
            name = iface["name"]
            ip = iface["ip"]
            if_type = iface["type"]
            is_primary = iface.get("is_primary", False)

            if is_primary:
                tag = " [RECOMMENDED FOR CLIENTS]"
            elif if_type == "virtual":
                tag = " [Virtual / Host-Only Adapter]"
            elif if_type == "link-local":
                tag = " [Link-Local / Disconnected]"
            elif if_type == "vpn":
                tag = " [VPN / Tunnel Adapter]"
            else:
                tag = ""

            lines.append(f"  * {name:<22} : http://{ip}:{port}{tag}")
    else:
        lines.append(f"  * Primary Interface      : http://{primary_ip}:{port}")

    lines.extend([
        "",
        "Client PC Configuration Guideline:",
        f"  Configure APEXEYE_MASTER_URL in the Client's .env or environment:",
        f"    APEXEYE_MASTER_URL=http://{primary_ip}:{port}",
        "",
        "Security Boundary Status:",
        "  * Master Admin Dashboard : STRICTLY RESTRICTED to Master Localhost (127.0.0.1)",
        "  * Remote LAN Clients     : Authorized API access only (Telemetries/Events/Auth)",
        "  * Remote Admin Attempts  : HTTP 403 Forbidden enforced server-side",
        "=" * 60,
    ])
    return "\n".join(lines)
