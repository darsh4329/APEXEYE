"""
APEXEYE FIREWALL — Platform Enforcement Package
"""

import sys
from typing import Optional
from pathlib import Path

from client.app.services.enforcement.base_enforcer import BaseFirewallEnforcer
from client.app.services.enforcement.windows_adapter import WindowsFirewallAdapter
from client.app.services.enforcement.linux_adapter import LinuxFirewallAdapter


def get_platform_enforcer(
    hosts_path: Optional[Path] = None,
    manage_native_firewall: bool = True,
) -> BaseFirewallEnforcer:
    """Return the appropriate platform enforcement adapter."""
    if sys.platform == "win32":
        return WindowsFirewallAdapter(
            hosts_path=hosts_path,
            manage_native_firewall=manage_native_firewall,
        )
    return LinuxFirewallAdapter(
        hosts_path=hosts_path,
        manage_native_firewall=manage_native_firewall,
    )


__all__ = [
    "BaseFirewallEnforcer",
    "WindowsFirewallAdapter",
    "LinuxFirewallAdapter",
    "get_platform_enforcer",
]
