"""
APEXEYE MASTER — CCTV Device Management Service (Phase 4 / 4.5 Hardened)

Handles CRUD operations, credential security, configuration, and
summary metrics for registered CCTV / IP Camera / NVR endpoints.

Security & Credential Handling:
  - NOTE: `password_enc` uses reversible machine-derived XOR obfuscation
    to avoid plaintext storage on disk. It is NOT production-grade
    cryptographic encryption (AES-256-GCM / KMS encryption is scheduled for Phase 10).
  - Passwords and raw secrets are stripped from API outputs and logs.
  - Master remains the sole manager of the SQLite database.
"""

import base64
import hashlib
import ipaddress
import json
import platform
import re
from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.cctv")


class ValidationError(Exception):
    """Raised when CCTV input validation fails."""
    pass


def _derive_secret_key() -> bytes:
    """Derive local key for prototype password obfuscation (Phase 10 upgrades to KMS/AES-GCM)."""
    seed = f"apexeye-cctv-secret:{platform.node()}:{platform.system()}"
    return hashlib.sha256(seed.encode("utf-8")).digest()


def _obfuscate(plaintext: str) -> str:
    """Obfuscate a password string."""
    if not plaintext:
        return ""
    key = _derive_secret_key()
    data = plaintext.encode("utf-8")
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.urlsafe_b64encode(xored).decode("ascii")


def _deobfuscate(encoded: str) -> str:
    """De-obfuscate a stored password string."""
    if not encoded:
        return ""
    try:
        key = _derive_secret_key()
        xored = base64.urlsafe_b64decode(encoded.encode("ascii"))
        data = bytes(b ^ key[i % len(key)] for i, b in enumerate(xored))
        return data.decode("utf-8")
    except Exception:
        return ""


def _validate_host(host: str) -> str:
    """Validate IPv4, IPv6, or valid hostname/FQDN."""
    host = host.strip()
    if not host:
        raise ValidationError("IP address or hostname is required.")

    # Try IP address
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Hostname validation (RFC 1123)
    hostname_regex = re.compile(
        r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])"
        r"(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$"
    )
    if not hostname_regex.match(host) and host != "localhost":
        raise ValidationError(f"Invalid IP address or hostname: '{host}'")

    return host


class CCTVService:
    """Business logic for CCTV device registration, queries, and updates."""

    def register_cctv(self, data: dict) -> dict:
        """
        Register a new CCTV / IP Camera / NVR endpoint.
        """
        cctv_id = data.get("cctv_id", "").strip()
        name = data.get("name", "").strip()
        ip_address = data.get("ip_address", "").strip()
        port = data.get("port", 554)
        rtsp_path = data.get("rtsp_path", "/stream1").strip()
        rtsp_url = data.get("rtsp_url", "").strip()
        username = data.get("username", "").strip() or None
        password = data.get("password", "")
        location = data.get("location", "").strip() or None
        is_enabled = 1 if data.get("is_enabled", True) else 0

        # Validations
        if not cctv_id:
            raise ValidationError("cctv_id is required.")
        if not re.match(r"^[A-Za-z0-9_\-\.]+$", cctv_id):
            raise ValidationError("cctv_id may only contain alphanumeric characters, hyphens, underscores, and dots.")
        if not name:
            raise ValidationError("name is required.")

        ip_address = _validate_host(ip_address)

        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid port: '{port}'. Must be between 1 and 65535.")

        if not rtsp_path.startswith("/"):
            rtsp_path = "/" + rtsp_path

        # Construct default rtsp_url if not provided
        if not rtsp_url:
            rtsp_url = f"rtsp://{ip_address}:{port}{rtsp_path}"

        password_enc = _obfuscate(password) if password else None
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        try:
            # Check duplicate
            existing = conn.execute(
                "SELECT id FROM cctv_devices WHERE cctv_id = ?;", (cctv_id,)
            ).fetchone()
            if existing:
                raise ValidationError(f"CCTV with ID '{cctv_id}' already exists.")

            conn.execute(
                """INSERT INTO cctv_devices
                   (cctv_id, name, ip_address, port, rtsp_path, rtsp_url,
                    username, password_enc, location, is_enabled, status,
                    last_status_reason, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cctv_id, name, ip_address, port, rtsp_path, rtsp_url,
                    username, password_enc, location, is_enabled, "UNKNOWN",
                    "Awaiting initial check", now, now,
                ),
            )
            conn.commit()

            # Record audit log
            conn.execute(
                """INSERT INTO audit_logs (timestamp, actor, action, target, details)
                   VALUES (?,?,?,?,?)""",
                (now, "admin", "cctv_registered", cctv_id, f"Registered CCTV {name} ({ip_address}:{port})"),
            )
            conn.commit()

            logger.info("Registered CCTV '%s' (%s at %s:%d)", cctv_id, name, ip_address, port)
            return self.get_cctv(cctv_id)

        finally:
            conn.close()

    def list_cctv(self, include_secrets: bool = False) -> list[dict]:
        """List all registered CCTV devices."""
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM cctv_devices ORDER BY created_at DESC;"
            ).fetchall()
            return [self._format_cctv(r, include_secrets=include_secrets) for r in rows]
        finally:
            conn.close()

    def get_cctv(self, cctv_id: str, include_secrets: bool = False) -> dict | None:
        """Get a single CCTV record by ID."""
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM cctv_devices WHERE cctv_id = ?;", (cctv_id,)
            ).fetchone()
            if not row:
                return None
            return self._format_cctv(row, include_secrets=include_secrets)
        finally:
            conn.close()

    def update_cctv(self, cctv_id: str, data: dict) -> dict | None:
        """Update a CCTV configuration."""
        cctv = self.get_cctv(cctv_id, include_secrets=True)
        if not cctv:
            return None

        name = data.get("name", cctv["name"]).strip()
        ip_address = data.get("ip_address", cctv["ip_address"]).strip()
        port = data.get("port", cctv["port"])
        rtsp_path = data.get("rtsp_path", cctv["rtsp_path"]).strip()
        rtsp_url = data.get("rtsp_url", cctv.get("rtsp_url", "")).strip()
        username = data.get("username", cctv.get("username"))
        location = data.get("location", cctv.get("location"))
        is_enabled = 1 if data.get("is_enabled", cctv.get("is_enabled", 1)) else 0

        # Optional password update
        password_enc = cctv.get("_password_enc")
        if "password" in data and data["password"]:
            password_enc = _obfuscate(data["password"])
        elif "password" in data and data["password"] == "":
            password_enc = None

        if not name:
            raise ValidationError("name is required.")
        ip_address = _validate_host(ip_address)

        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid port: '{port}'.")

        if not rtsp_path.startswith("/"):
            rtsp_path = "/" + rtsp_path

        if not rtsp_url:
            rtsp_url = f"rtsp://{ip_address}:{port}{rtsp_path}"

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        try:
            conn.execute(
                """UPDATE cctv_devices SET
                    name = ?, ip_address = ?, port = ?, rtsp_path = ?,
                    rtsp_url = ?, username = ?, password_enc = ?,
                    location = ?, is_enabled = ?, updated_at = ?
                   WHERE cctv_id = ?;""",
                (
                    name, ip_address, port, rtsp_path, rtsp_url,
                    username, password_enc, location, is_enabled, now,
                    cctv_id,
                ),
            )
            conn.commit()
            logger.info("Updated CCTV '%s'", cctv_id)
            return self.get_cctv(cctv_id)
        finally:
            conn.close()

    def set_enabled(self, cctv_id: str, is_enabled: bool) -> dict | None:
        """Enable or disable monitoring for a CCTV device."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        val = 1 if is_enabled else 0
        conn = get_connection()
        try:
            cursor = conn.execute(
                "UPDATE cctv_devices SET is_enabled = ?, updated_at = ? WHERE cctv_id = ?;",
                (val, now, cctv_id),
            )
            conn.commit()
            if cursor.rowcount == 0:
                return None
            logger.info("Set CCTV '%s' is_enabled=%s", cctv_id, is_enabled)
            return self.get_cctv(cctv_id)
        finally:
            conn.close()

    def delete_cctv(self, cctv_id: str) -> bool:
        """Remove a CCTV device and cascade delete its telemetry."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            cursor = conn.execute(
                "DELETE FROM cctv_devices WHERE cctv_id = ?;", (cctv_id,)
            )
            if cursor.rowcount > 0:
                conn.execute(
                    """INSERT INTO audit_logs (timestamp, actor, action, target, details)
                       VALUES (?,?,?,?,?)""",
                    (now, "admin", "cctv_deleted", cctv_id, f"Deleted CCTV {cctv_id}"),
                )
                conn.commit()
                logger.info("Deleted CCTV '%s'", cctv_id)
                return True
            return False
        finally:
            conn.close()

    def store_telemetry(self, cctv_id: str, telemetry: dict) -> None:
        """
        Record a CCTV connectivity snapshot and update device status.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        ts = telemetry.get("timestamp", now)
        tcp_ok = 1 if telemetry.get("tcp_reachable") else 0
        tcp_rt = telemetry.get("tcp_response_time_ms")
        rtsp_ok = 1 if telemetry.get("rtsp_reachable") else 0
        rtsp_rt = telemetry.get("rtsp_response_time_ms")
        status = telemetry.get("status", "UNKNOWN")
        reason = telemetry.get("failure_reason", "")
        details_json = json.dumps(telemetry.get("details", {}))

        conn = get_connection()
        try:
            # Insert telemetry
            conn.execute(
                """INSERT INTO cctv_telemetry
                   (cctv_id, timestamp, tcp_reachable, tcp_response_time_ms,
                    rtsp_reachable, rtsp_response_time_ms, status,
                    failure_reason, details)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (cctv_id, ts, tcp_ok, tcp_rt, rtsp_ok, rtsp_rt, status, reason, details_json),
            )

            # Update device state
            last_succ_sql = "last_successful_check = ?, " if (tcp_ok and rtsp_ok) else ""
            params = [status, reason, ts]
            if tcp_ok and rtsp_ok:
                params.append(ts)

            # Reset or increment consecutive_failures
            if status == "ONLINE":
                conn.execute(
                    f"""UPDATE cctv_devices SET
                        status = ?, last_status_reason = ?, last_checked = ?,
                        {last_succ_sql} consecutive_failures = 0, updated_at = ?
                        WHERE cctv_id = ?;""",
                    (*params, now, cctv_id),
                )
            else:
                conn.execute(
                    f"""UPDATE cctv_devices SET
                        status = ?, last_status_reason = ?, last_checked = ?,
                        {last_succ_sql} consecutive_failures = consecutive_failures + 1, updated_at = ?
                        WHERE cctv_id = ?;""",
                    (*params, now, cctv_id),
                )

            conn.commit()
        finally:
            conn.close()

    def get_summary(self) -> dict:
        """Return counts for dashboard statistics."""
        conn = get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) as c FROM cctv_devices;").fetchone()["c"]
            online = conn.execute("SELECT COUNT(*) as c FROM cctv_devices WHERE status = 'ONLINE' AND is_enabled = 1;").fetchone()["c"]
            offline = conn.execute("SELECT COUNT(*) as c FROM cctv_devices WHERE status != 'ONLINE' AND is_enabled = 1;").fetchone()["c"]
            disabled = conn.execute("SELECT COUNT(*) as c FROM cctv_devices WHERE is_enabled = 0;").fetchone()["c"]
            rtsp_ok = conn.execute(
                "SELECT COUNT(*) as c FROM cctv_devices WHERE status = 'ONLINE' AND is_enabled = 1;"
            ).fetchone()["c"]

            return {
                "total": total,
                "online": online,
                "offline": offline,
                "disabled": disabled,
                "rtsp_available": rtsp_ok,
            }
        finally:
            conn.close()

    def get_recent_telemetry(self, cctv_id: str, limit: int = 50) -> list[dict]:
        """Get recent telemetry snapshots for a CCTV device."""
        conn = get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM cctv_telemetry
                   WHERE cctv_id = ?
                   ORDER BY timestamp DESC LIMIT ?;""",
                (cctv_id, limit),
            ).fetchall()

            results = []
            for r in rows:
                item = dict(r)
                if item.get("details"):
                    try:
                        item["details"] = json.loads(item["details"])
                    except Exception:
                        pass
                results.append(item)
            return results
        finally:
            conn.close()

    def _format_cctv(self, row, include_secrets: bool = False) -> dict:
        """Format database row for API response."""
        data = dict(row)
        password_enc = data.get("password_enc")

        if include_secrets:
            data["_password_enc"] = password_enc
            data["password"] = _deobfuscate(password_enc) if password_enc else ""
        else:
            # Mask or strip secrets
            data.pop("password_enc", None)
            data["has_password"] = bool(password_enc)

        # Convert booleans
        data["is_enabled"] = bool(data.get("is_enabled", 1))
        return data
