r"""
APEXEYE WINDOWS CLIENT — Windows Firewall Enforcement Adapter

Combines:
1. Windows hosts file sentinel-block redirection to loopback (127.0.0.1 and ::1).
2. Native Windows Defender Firewall outbound UDP 443 (QUIC/HTTP3) block rule:
   Prevents modern browsers from bypassing TCP hosts redirection via QUIC.
3. Windows DNS resolver cache flushing (dnsapi.dll / ipconfig /flushdns).

Security & Lifecycle guarantees:
- Installs and removes the QUIC rule cleanly with firewall state.
- Never reports ACTIVE if QUIC enforcement failed.
- Cleans up on shutdown.
"""

import ctypes
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from client.app.services.enforcement.base_enforcer import BaseFirewallEnforcer
from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.enforcement.windows")

_SENTINEL_BEGIN = "# [APEXEYE-FIREWALL-BEGIN]"
_SENTINEL_END = "# [APEXEYE-FIREWALL-END]"
_REDIRECT_IPV4 = "127.0.0.1"
_REDIRECT_IPV6 = "::1"
_REDIRECT_IP = _REDIRECT_IPV4
_QUIC_RULE_NAME = "APEXEYE-BLOCK-QUIC"


def _get_default_hosts_path() -> Path:
    if sys.platform == "win32":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    return Path("/etc/hosts")


def _get_block_hostnames(normalized_domain: str) -> list[str]:
    """Return list of hostnames to block for a domain (bare + www.)."""
    entries = [normalized_domain]
    if not normalized_domain.startswith("www."):
        entries.append(f"www.{normalized_domain}")
    return entries


def _strip_apexeye_block(content: str) -> str:
    """Remove the APEXEYE sentinel block from hosts content, leave all other lines intact."""
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
    """Build sentinel block containing both IPv4 and IPv6 loopback entries."""
    lines = [_SENTINEL_BEGIN + "\n"]
    lines.append("# APEXEYE Firewall — managed block. Do not edit manually.\n")
    for domain in sorted(blocked_domains):
        for hostname in _get_block_hostnames(domain):
            lines.append(f"{_REDIRECT_IPV4} {hostname}\n")
            lines.append(f"{_REDIRECT_IPV6} {hostname}\n")
    lines.append(_SENTINEL_END + "\n")
    return "".join(lines)


class WindowsFirewallAdapter(BaseFirewallEnforcer):
    """
    Manages hosts-file loopback redirection and native Windows Firewall QUIC blocking.
    """

    def __init__(
        self,
        hosts_path: Optional[Path] = None,
        manage_native_firewall: bool = True,
    ):
        self._hosts_path = hosts_path or _get_default_hosts_path()
        self._manage_native_firewall = manage_native_firewall and (sys.platform == "win32")
        self._quic_active: bool = False
        self._last_error: Optional[str] = None

    def apply_policy(
        self,
        enabled: bool,
        blocked_domains: list[str],
    ) -> tuple[bool, Optional[str]]:
        """
        Apply or remove local hosts and native firewall enforcement.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        self._last_error = None

        # 1. Apply Hosts-File Redirection
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
            err = (
                f"Permission denied writing to {self._hosts_path}. "
                "Run the APEXEYE client as Administrator."
            )
            self._last_error = err
            return False, err
        except Exception as exc:
            err = f"Failed to write hosts file {self._hosts_path}: {exc}"
            self._last_error = err
            return False, err

        # Flush DNS cache immediately
        self.flush_dns_cache()

        # 2. Native Windows Firewall QUIC / UDP 443 Rule Management
        if self._manage_native_firewall:
            if enabled and blocked_domains:
                quic_ok, quic_err = self._enable_quic_block()
                if not quic_ok:
                    # REQ 1: Never report ACTIVE if QUIC enforcement failed
                    self._last_error = quic_err
                    logger.error("QUIC enforcement failed on Windows: %s", quic_err)
                    # Revert hosts file on failure
                    try:
                        self._hosts_path.write_text(clean, encoding="utf-8")
                    except Exception:
                        pass
                    return False, quic_err
            else:
                self._disable_quic_block()
        else:
            # When native firewall management is disabled (e.g. unit tests or non-Windows)
            self._quic_active = bool(enabled and blocked_domains)

        if enabled and blocked_domains:
            logger.info(
                "Windows Firewall ACTIVE: %d domain(s) redirected to loopback (QUIC blocked: %s).",
                len(blocked_domains),
                self._quic_active,
            )
        else:
            logger.info("Windows Firewall INACTIVE: APEXEYE block and QUIC rule removed.")

        return True, None

    def _enable_quic_block(self) -> tuple[bool, Optional[str]]:
        """Add Windows Defender Firewall rule to block outbound UDP port 443 (QUIC)."""
        try:
            # Check if rule already exists
            check_cmd = [
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={_QUIC_RULE_NAME}",
            ]
            check_res = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if check_res.returncode == 0:
                self._quic_active = True
                return True, None

            # Add outbound block rule for UDP port 443
            add_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={_QUIC_RULE_NAME}",
                "dir=out",
                "action=block",
                "protocol=UDP",
                "remoteport=443",
                "description=APEXEYE Firewall QUIC bypass mitigation rule",
            ]
            add_res = subprocess.run(
                add_cmd,
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if add_res.returncode == 0:
                self._quic_active = True
                logger.info("Windows Firewall rule added: %s (UDP 443 outbound blocked).", _QUIC_RULE_NAME)
                return True, None
            else:
                err_msg = add_res.stderr.strip() or add_res.stdout.strip() or "netsh failed"
                self._quic_active = False
                return False, f"Failed to add QUIC block rule via netsh: {err_msg}"
        except Exception as exc:
            self._quic_active = False
            return False, f"Windows Firewall netsh execution error: {exc}"

    def _disable_quic_block(self) -> bool:
        """Remove Windows Defender Firewall QUIC block rule cleanly."""
        try:
            del_cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={_QUIC_RULE_NAME}",
            ]
            res = subprocess.run(
                del_cmd,
                capture_output=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self._quic_active = False
            if res.returncode == 0:
                logger.info("Windows Firewall rule deleted cleanly: %s", _QUIC_RULE_NAME)
            return True
        except Exception as exc:
            logger.debug("netsh delete rule error: %s", exc)
            self._quic_active = False
            return False

    def is_enforcement_active(self) -> bool:
        """Return True only if sentinel block is present AND QUIC is blocked."""
        try:
            has_hosts = _SENTINEL_BEGIN in self._hosts_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return False
        return has_hosts and self._quic_active

    def is_quic_blocked(self) -> bool:
        return self._quic_active

    def get_enforcer_status(self) -> dict:
        return {
            "platform": "Windows",
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
        """Flush OS DNS resolver cache (both in-process and system-wide service)."""
        flushed = False
        if sys.platform == "win32":
            # 1. In-process resolver cache flush
            try:
                if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "dnsapi"):
                    res = ctypes.windll.dnsapi.DnsFlushResolverCache()
                    if res != 0:
                        flushed = True
            except Exception:
                pass

            # 2. System-wide DNS Client service flush (notifies external apps & browsers)
            try:
                sub_res = subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if sub_res.returncode == 0:
                    flushed = True
            except Exception as exc:
                logger.debug("ipconfig /flushdns execution error: %s", exc)

        return flushed

    def cleanup(self) -> None:
        """Clean up on agent shutdown."""
        if self._manage_native_firewall:
            self._disable_quic_block()
