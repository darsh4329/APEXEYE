"""
APEXEYE LINUX CLIENT — Hosts-File Firewall Enforcer

Enforces the Master firewall policy on this Linux machine by maintaining
a dedicated guarded block inside /etc/hosts:

Sentinel block pattern (ONLY this block is touched):
  # [APEXEYE-FIREWALL-BEGIN]
  0.0.0.0 example.com
  0.0.0.0 www.example.com
  # [APEXEYE-FIREWALL-END]

Security rules:
  - Never modifies any line outside the sentinel block.
  - On deactivation: removes only the APEXEYE block; rest is untouched.
  - Requires root/sudo privileges to write /etc/hosts.
  - Returns (False, error_message) on permission failure — NEVER silently pretends success.
"""

from pathlib import Path
from typing import Optional

from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.hosts_enforcer")

_SENTINEL_BEGIN = "# [APEXEYE-FIREWALL-BEGIN]"
_SENTINEL_END = "# [APEXEYE-FIREWALL-END]"
_REDIRECT_IPV4 = "127.0.0.1"
_REDIRECT_IPV6 = "::1"
_REDIRECT_IP = _REDIRECT_IPV4
_HOSTS_PATH = Path("/etc/hosts")


def _flush_dns_cache() -> bool:
    """
    Flush local resolver caches on Linux if resolver daemons are present.
    Supports systemd-resolved (resolvectl / systemd-resolve) and nscd.
    """
    import subprocess
    flushed = False
    for cmd in [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"], ["nscd", "-i", "hosts"]]:
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=3)
            if res.returncode == 0:
                logger.info("Linux DNS cache flushed via %s", " ".join(cmd))
                flushed = True
                break
        except Exception:
            continue
    return flushed


def _get_block_hostnames(normalized_domain: str) -> list[str]:
    entries = [normalized_domain]
    if not normalized_domain.startswith("www."):
        entries.append(f"www.{normalized_domain}")
    return entries


def _read_hosts(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise IOError(f"Cannot read {path}: {exc}") from exc


def _write_hosts(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except PermissionError as exc:
        raise PermissionError(
            f"Permission denied writing to {path}. "
            "Run the APEXEYE Linux client as root or with sudo."
        ) from exc
    except Exception as exc:
        raise IOError(f"Failed to write {path}: {exc}") from exc


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
    """Build sentinel block containing both IPv4 and IPv6 blocking entries."""
    lines = [_SENTINEL_BEGIN + "\n"]
    lines.append("# APEXEYE Firewall — managed block. Do not edit manually.\n")
    for domain in sorted(blocked_domains):
        for hostname in _get_block_hostnames(domain):
            lines.append(f"{_REDIRECT_IPV4} {hostname}\n")
            lines.append(f"{_REDIRECT_IPV6} {hostname}\n")
    lines.append(_SENTINEL_END + "\n")
    return "".join(lines)


class LinuxHostsEnforcer:
    """
    Manages the APEXEYE firewall sentinel block in /etc/hosts on Linux.
    """

    def __init__(self, hosts_path: Optional[Path] = None):
        self._hosts_path = hosts_path or _HOSTS_PATH

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

        # Flush DNS cache so changes take effect immediately
        _flush_dns_cache()

        if enabled and blocked_domains:
            logger.info("Firewall ACTIVE: %d domain(s) blocked in %s (IPv4 + IPv6).", len(blocked_domains), self._hosts_path)
        else:
            logger.info("Firewall INACTIVE: APEXEYE block removed from %s.", self._hosts_path)
        return True, None

    def is_enforcement_active(self) -> bool:
        try:
            return _SENTINEL_BEGIN in _read_hosts(self._hosts_path)
        except IOError:
            return False
