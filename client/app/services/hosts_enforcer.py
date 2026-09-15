r"""
APEXEYE WINDOWS CLIENT — Hosts-File Firewall Enforcer

Enforces the Master firewall policy on this Windows machine by maintaining
a dedicated guarded block inside the Windows hosts file:

  C:\Windows\System32\drivers\etc\hosts

Sentinel block pattern (ONLY this block is touched):
  # [APEXEYE-FIREWALL-BEGIN]
  0.0.0.0 example.com
  0.0.0.0 www.example.com
  # [APEXEYE-FIREWALL-END]

Security rules:
  - Never modifies any line outside the sentinel block.
  - On deactivation: removes only the APEXEYE block; rest is untouched.
  - Requires Administrator privileges to write the hosts file.
  - Returns (False, error_message) on permission failure — NEVER silently pretends success.
"""

import sys
from pathlib import Path
from typing import Optional

from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.hosts_enforcer")

_SENTINEL_BEGIN = "# [APEXEYE-FIREWALL-BEGIN]"
_SENTINEL_END = "# [APEXEYE-FIREWALL-END]"
_REDIRECT_IPV4 = "127.0.0.1"
_REDIRECT_IPV6 = "::1"
_REDIRECT_IP = _REDIRECT_IPV4  # Backward compatibility alias


def _get_hosts_path() -> Path:
    if sys.platform == "win32":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    # Fallback for non-Windows (shouldn't happen for this client)
    return Path("/etc/hosts")


def _flush_dns_cache() -> bool:
    """
    Flush the OS DNS resolver cache after policy changes so blocked/unblocked
    domains take effect immediately in browsers and network sockets without reboot.
    """
    flushed = False
    if sys.platform == "win32":
        # 1. Fast in-process flush via Windows dnsapi.dll
        try:
            import ctypes
            if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "dnsapi"):
                res = ctypes.windll.dnsapi.DnsFlushResolverCache()
                if res != 0:
                    logger.info("DNS resolver cache flushed via dnsapi.DnsFlushResolverCache.")
                    flushed = True
        except Exception as exc:
            logger.debug("DnsFlushResolverCache failed: %s", exc)

        # 2. System-wide DNS Client service flush (notifies external apps & browsers)
        try:
            import subprocess
            sub_res = subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if sub_res.returncode == 0:
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


def _get_block_hostnames(normalized_domain: str) -> list[str]:
    """Return list of hostnames to block for a domain (bare + www.)."""
    entries = [normalized_domain]
    if not normalized_domain.startswith("www."):
        entries.append(f"www.{normalized_domain}")
    return entries


def _read_hosts(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise IOError(f"Cannot read hosts file {path}: {exc}") from exc


def _write_hosts(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except PermissionError as exc:
        raise PermissionError(
            f"Permission denied writing to {path}. "
            "Run the APEXEYE client as Administrator."
        ) from exc
    except Exception as exc:
        raise IOError(f"Failed to write hosts file {path}: {exc}") from exc


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
    """Build sentinel block containing both IPv4 and IPv6 blocking entries."""
    lines = [_SENTINEL_BEGIN + "\n"]
    lines.append("# APEXEYE Firewall — managed block. Do not edit manually.\n")
    for domain in sorted(blocked_domains):
        for hostname in _get_block_hostnames(domain):
            lines.append(f"{_REDIRECT_IPV4} {hostname}\n")
            lines.append(f"{_REDIRECT_IPV6} {hostname}\n")
    lines.append(_SENTINEL_END + "\n")
    return "".join(lines)


class WindowsHostsEnforcer:
    """
    Manages the APEXEYE firewall sentinel block in the Windows hosts file.
    Thread-safe for single-writer use (only the firewall agent calls this).
    """

    def __init__(self, hosts_path: Optional[Path] = None):
        self._hosts_path = hosts_path or _get_hosts_path()

    def apply_policy(
        self,
        enabled: bool,
        blocked_domains: list[str],
    ) -> tuple[bool, Optional[str]]:
        """
        Write or remove the APEXEYE hosts block based on policy.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        try:
            content = _read_hosts(self._hosts_path)
        except IOError as exc:
            return False, str(exc)

        clean = _strip_apexeye_block(content)
        if clean and not clean.endswith("\n"):
            clean += "\n"

        new_content = clean + _build_apexeye_block(blocked_domains) if (enabled and blocked_domains) else clean

        try:
            _write_hosts(self._hosts_path, new_content)
        except (PermissionError, IOError) as exc:
            return False, str(exc)

        # Flush DNS cache so OS/browser immediately recognizes hosts changes
        _flush_dns_cache()

        if enabled and blocked_domains:
            logger.info(
                "Firewall ACTIVE: %d domain(s) blocked in hosts file (IPv4 + IPv6).",
                len(blocked_domains),
            )
        else:
            logger.info("Firewall INACTIVE: APEXEYE block removed from hosts file.")
        return True, None

    def is_enforcement_active(self) -> bool:
        """Return True if the APEXEYE sentinel block is present in the hosts file."""
        try:
            return _SENTINEL_BEGIN in _read_hosts(self._hosts_path)
        except IOError:
            return False
