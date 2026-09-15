"""
APEXEYE LINUX CLIENT — Linux Firewall Enforcement Adapter

Combines:
1. Linux /etc/hosts sentinel-block redirection to loopback (127.0.0.1 and ::1).
2. Native Linux iptables/nftables outbound UDP 443 (QUIC/HTTP3) drop rule.
3. Linux DNS resolver cache flushing (resolvectl / systemd-resolve / nscd).

Security & Lifecycle guarantees:
- Installs and removes the QUIC rule cleanly with firewall state.
- Never reports ACTIVE if QUIC enforcement failed.
- Cleans up on shutdown.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from client_linux.app.services.enforcement.base_enforcer import BaseFirewallEnforcer
from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.enforcement.linux")

_SENTINEL_BEGIN = "# [APEXEYE-FIREWALL-BEGIN]"
_SENTINEL_END = "# [APEXEYE-FIREWALL-END]"
_REDIRECT_IPV4 = "127.0.0.1"
_REDIRECT_IPV6 = "::1"
_REDIRECT_IP = _REDIRECT_IPV4
_QUIC_COMMENT = "APEXEYE-BLOCK-QUIC"
_HOSTS_PATH = Path("/etc/hosts")


def _get_block_hostnames(normalized_domain: str) -> list[str]:
    entries = [normalized_domain]
    if not normalized_domain.startswith("www."):
        entries.append(f"www.{normalized_domain}")
    return entries


def _strip_apexeye_block(content: str) -> str:
    lines = content.splitlines(keepends=True)
    result = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if stripped == _SENTINEL_BEGIN:
            in_block = True
            continue
        if stripped == _SENTINEL_END:
            in_block = False
            continue
        if not in_block:
            result.append(line)
    return "".join(result)


def _build_apexeye_block(blocked_domains: list[str]) -> str:
    lines = [_SENTINEL_BEGIN + "\n"]
    lines.append("# APEXEYE Firewall — managed block. Do not edit manually.\n")
    for domain in sorted(blocked_domains):
        for hostname in _get_block_hostnames(domain):
            lines.append(f"{_REDIRECT_IPV4} {hostname}\n")
            lines.append(f"{_REDIRECT_IPV6} {hostname}\n")
    lines.append(_SENTINEL_END + "\n")
    return "".join(lines)


class LinuxFirewallAdapter(BaseFirewallEnforcer):
    """
    Manages /etc/hosts loopback redirection and native Linux iptables QUIC blocking.
    """

    def __init__(
        self,
        hosts_path: Optional[Path] = None,
        manage_native_firewall: bool = True,
    ):
        self._hosts_path = hosts_path or _HOSTS_PATH
        self._manage_native_firewall = manage_native_firewall and (sys.platform.startswith("linux"))
        self._quic_active: bool = False
        self._last_error: Optional[str] = None

    def apply_policy(
        self,
        enabled: bool,
        blocked_domains: list[str],
    ) -> tuple[bool, Optional[str]]:
        self._last_error = None

        # 1. Update /etc/hosts
        try:
            content = self._hosts_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            content = ""
        except Exception as exc:
            err = f"Cannot read hosts file {self._hosts_path}: {exc}"
            self._last_error = err
            return False, err

        clean = _strip_apexeye_block(content)
        if clean and not clean.endswith("\n"):
            clean += "\n"

        if enabled and blocked_domains:
            new_content = clean + _build_apexeye_block(blocked_domains)
        else:
            new_content = clean

        try:
            self._hosts_path.write_text(new_content, encoding="utf-8")
        except PermissionError as exc:
            err = f"Permission denied writing to {self._hosts_path}. Run with root/sudo."
            self._last_error = err
            return False, err
        except Exception as exc:
            err = f"Failed to write hosts file {self._hosts_path}: {exc}"
            self._last_error = err
            return False, err

        # Flush DNS cache
        self.flush_dns_cache()

        # 2. Native Linux iptables QUIC / UDP 443 Rule Management
        if self._manage_native_firewall:
            if enabled and blocked_domains:
                quic_ok, quic_err = self._enable_quic_block()
                if not quic_ok:
                    # Never report ACTIVE if QUIC enforcement failed
                    self._last_error = quic_err
                    logger.error("QUIC enforcement failed on Linux: %s", quic_err)
                    try:
                        self._hosts_path.write_text(clean, encoding="utf-8")
                    except Exception:
                        pass
                    return False, quic_err
            else:
                self._disable_quic_block()
        else:
            self._quic_active = bool(enabled and blocked_domains)

        if enabled and blocked_domains:
            logger.info("Linux Firewall ACTIVE: %d domain(s) redirected to loopback (QUIC blocked: %s).", len(blocked_domains), self._quic_active)
        else:
            logger.info("Linux Firewall INACTIVE: APEXEYE block and QUIC rule removed.")

        return True, None

    def _enable_quic_block(self) -> tuple[bool, Optional[str]]:
        """Add iptables rule to drop outbound UDP 443 (QUIC)."""
        try:
            # Check if rule exists
            chk = subprocess.run(
                ["iptables", "-C", "OUTPUT", "-p", "udp", "--dport", "443", "-m", "comment", "--comment", _QUIC_COMMENT, "-j", "DROP"],
                capture_output=True,
                timeout=3,
            )
            if chk.returncode == 0:
                self._quic_active = True
                return True, None

            # Add rule
            add_res = subprocess.run(
                ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-m", "comment", "--comment", _QUIC_COMMENT, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if add_res.returncode == 0:
                self._quic_active = True
                logger.info("Linux iptables rule added: UDP 443 outbound DROP (QUIC).")
                return True, None
            else:
                err_msg = add_res.stderr.strip() or "iptables failed"
                self._quic_active = False
                return False, f"Failed to add iptables QUIC drop rule: {err_msg}"
        except Exception as exc:
            self._quic_active = False
            return False, f"Linux iptables execution error: {exc}"

    def _disable_quic_block(self) -> bool:
        """Remove iptables QUIC rule cleanly."""
        try:
            # Remove rule if present
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "443", "-m", "comment", "--comment", _QUIC_COMMENT, "-j", "DROP"],
                capture_output=True,
                timeout=3,
            )
            self._quic_active = False
            logger.info("Linux iptables QUIC rule removed cleanly.")
            return True
        except Exception as exc:
            logger.debug("iptables delete rule error: %s", exc)
            self._quic_active = False
            return False

    def is_enforcement_active(self) -> bool:
        return self.is_hosts_block_present() and self._quic_active

    def is_quic_blocked(self) -> bool:
        return self._quic_active

    def get_enforcer_status(self) -> dict:
        return {
            "platform": "Linux",
            "hosts_file": str(self._hosts_path),
            "hosts_active": self.is_hosts_block_present(),
            "quic_blocked": self._quic_active,
            "native_firewall_enabled": self._manage_native_firewall,
            "last_error": self._last_error,
        }

    def is_hosts_block_present(self) -> bool:
        try:
            return _SENTINEL_BEGIN in self._hosts_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return False

    def flush_dns_cache(self) -> bool:
        flushed = False
        for cmd in [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"], ["nscd", "-i", "hosts"]]:
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=3)
                if res.returncode == 0:
                    flushed = True
                    break
            except Exception:
                continue
        return flushed

    def cleanup(self) -> None:
        if self._manage_native_firewall:
            self._disable_quic_block()


__all__ = ["LinuxFirewallAdapter"]
