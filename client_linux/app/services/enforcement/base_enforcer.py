"""
APEXEYE FIREWALL — Base Enforcement Interface (Linux Client)

Defines the abstract interface for platform-specific network and hosts enforcement adapters.
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseFirewallEnforcer(ABC):
    """Abstract base class for platform-specific firewall enforcement."""

    @abstractmethod
    def apply_policy(
        self,
        enabled: bool,
        blocked_domains: list[str],
    ) -> tuple[bool, Optional[str]]:
        """
        Apply or remove local network/hosts enforcement based on policy.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        pass

    @abstractmethod
    def is_enforcement_active(self) -> bool:
        """Return True only if local enforcement is fully in effect."""
        pass

    @abstractmethod
    def is_quic_blocked(self) -> bool:
        """Return True if UDP port 443 (QUIC) is actively blocked by native firewall."""
        pass

    @abstractmethod
    def get_enforcer_status(self) -> dict:
        """Return detailed status of the platform enforcement adapter."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up any native firewall rules or sentinel entries on shutdown."""
        pass


__all__ = ["BaseFirewallEnforcer"]
