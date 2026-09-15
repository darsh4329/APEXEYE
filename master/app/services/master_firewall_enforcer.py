"""
APEXEYE MASTER — Local Firewall Enforcer

Enforces the Master firewall policy on the Master machine itself
by maintaining a dedicated guarded block inside the OS hosts file.

Sentinel pattern:
  # [APEXEYE-FIREWALL-BEGIN]
  0.0.0.0 example.com
  0.0.0.0 www.example.com
  # [APEXEYE-FIREWALL-END]

Rules:
  - NEVER modifies any line outside the sentinel block.
  - Creates the sentinel block if absent.
  - Completely replaces the sentinel block on every apply_policy() call.
  - Removing the block (deactivation) leaves the rest of the file intact.
  - Requires write access to the hosts file (admin/root required).
"""

import os
import platform
import sys
from pathlib import Path
from typing import Optional

from master.app.services.firewall_service import get_block_hostnames
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.firewall_enforcer")

# ── Sentinel markers ────────────────────────────────────────────────────────
_SENTINEL_BEGIN = "# [APEXEYE-FIREWALL-BEGIN]"
_SENTINEL_END = "# [APEXEYE-FIREWALL-END]"
_REDIRECT_IPV4 = "127.0.0.1"
_REDIRECT_IPV6 = "::1"
_REDIRECT_IP = _REDIRECT_IPV4

# ── Hosts file path ─────────────────────────────────────────────────────────
def _get_hosts_path() -> Path:
    """Return the OS-appropriate hosts file path."""
    if sys.platform == "win32":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    return Path("/etc/hosts")


def _flush_dns_cache() -> bool:
    """Flush local OS DNS resolver cache after hosts changes."""
    flushed = False
    if sys.platform == "win32":
        try:
            import ctypes
            if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "dnsapi"):
                res = ctypes.windll.dnsapi.DnsFlushResolverCache()
                if res != 0:
                    logger.info("DNS resolver cache flushed via dnsapi.DnsFlushResolverCache.")
                    flushed = True
        except Exception as exc:
            logger.debug("DnsFlushResolverCache failed: %s", exc)

        if not flushed:
            try:
                import subprocess
                subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                logger.info("DNS resolver cache flushed via ipconfig /flushdns.")
                flushed = True
            except Exception as exc:
                logger.warning("ipconfig /flushdns failed: %s", exc)
    else:
        try:
            import subprocess
            for cmd in [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"], ["nscd", "-i", "hosts"]]:
                try:
                    res = subprocess.run(cmd, capture_output=True, timeout=3)
                    if res.returncode == 0:
                        flushed = True
                        break
                except Exception:
                    continue
        except Exception:
            pass
    return flushed


# ── Core enforcement logic ──────────────────────────────────────────────────

def _read_hosts(hosts_path: Path) -> str:
    """Read the hosts file content."""
    try:
        return hosts_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise IOError(f"Cannot read hosts file at {hosts_path}: {exc}") from exc


def _write_hosts(hosts_path: Path, content: str) -> None:
    """Write content to the hosts file atomically."""
    try:
        hosts_path.write_text(content, encoding="utf-8")
    except PermissionError as exc:
        raise PermissionError(
            f"Permission denied writing to {hosts_path}. "
            "The Master process must be run as Administrator (Windows) or root (Linux/macOS)."
        ) from exc
    except Exception as exc:
        raise IOError(f"Failed to write hosts file at {hosts_path}: {exc}") from exc


def _strip_apexeye_block(content: str) -> str:
    """Remove the APEXEYE sentinel block from hosts content, leave everything else intact."""
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
    """Build the APEXEYE sentinel block content with both IPv4 and IPv6 entries."""
    lines = [_SENTINEL_BEGIN + "\n"]
    lines.append("# APEXEYE Firewall — managed block. Do not edit manually.\n")
    for domain in sorted(blocked_domains):
        for hostname in get_block_hostnames(domain):
            lines.append(f"{_REDIRECT_IPV4} {hostname}\n")
            lines.append(f"{_REDIRECT_IPV6} {hostname}\n")
    lines.append(_SENTINEL_END + "\n")
    return "".join(lines)


# ── Public interface ────────────────────────────────────────────────────────

class MasterFirewallEnforcer:
    """
    Manages the local APEXEYE firewall sentinel block on the Master machine.
    Thread-safe via file-level operations (file system provides ordering).
    """

    def __init__(self, hosts_path: Optional[Path] = None):
        self._hosts_path = hosts_path or _get_hosts_path()

    def apply_policy(
        self,
        enabled: bool,
        blocked_domains: list[str],
    ) -> tuple[bool, Optional[str]]:
        """
        Apply the firewall policy to the local hosts file.

        Args:
            enabled:         Whether the firewall is active.
            blocked_domains: List of normalized domain names to block.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        try:
            content = _read_hosts(self._hosts_path)
        except IOError as exc:
            logger.error("Cannot read hosts file: %s", exc)
            return False, str(exc)

        # Strip any existing APEXEYE block
        clean = _strip_apexeye_block(content)

        # Ensure file ends with newline before appending
        if clean and not clean.endswith("\n"):
            clean += "\n"

        if enabled and blocked_domains:
            new_content = clean + _build_apexeye_block(blocked_domains)
        else:
            # Disabled or no domains: just leave the file without the block
            new_content = clean

        try:
            _write_hosts(self._hosts_path, new_content)
        except (PermissionError, IOError) as exc:
            logger.error("Failed to write firewall policy to hosts file: %s", exc)
            return False, str(exc)

        # Flush DNS cache so local changes take immediate effect
        _flush_dns_cache()

        if enabled and blocked_domains:
            logger.info(
                "Firewall ACTIVE: %d domain(s) blocked in %s (IPv4 + IPv6)",
                len(blocked_domains), self._hosts_path,
            )
        else:
            logger.info(
                "Firewall INACTIVE: APEXEYE block removed from %s",
                self._hosts_path,
            )
        return True, None

    def is_enforcement_active(self) -> bool:
        """
        Return True if the APEXEYE sentinel block is currently present
        and non-empty in the hosts file.
        """
        try:
            content = _read_hosts(self._hosts_path)
        except IOError:
            return False
        return _SENTINEL_BEGIN in content and _SENTINEL_END in content

    def get_blocked_hostnames(self) -> list[str]:
        """Return the deduplicated list of hostnames currently in the APEXEYE hosts block."""
        try:
            content = _read_hosts(self._hosts_path)
        except IOError:
            return []
        lines = content.splitlines()
        in_block = False
        hostnames: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped == _SENTINEL_BEGIN:
                in_block = True
                continue
            if stripped == _SENTINEL_END:
                break
            if in_block and stripped and not stripped.startswith("#"):
                parts = stripped.split()
                if len(parts) >= 2:
                    h = parts[1]
                    if h not in hostnames:
                        hostnames.append(h)
        return hostnames


# Singleton for use by firewall_api
master_firewall_enforcer = MasterFirewallEnforcer()
