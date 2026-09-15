"""
APEXEYE MASTER — Firewall Service

The single source of truth for firewall policy on the Master.

Responsibilities:
  - Firewall ACTIVE/INACTIVE state management
  - Blocked domain CRUD with input normalization and validation
  - Policy versioning (incremented on every state/domain change)
  - Blocked-attempt log ingestion with duplicate suppression
  - Firewall log querying and filtering
  - Audit logging for all administrative actions

Only the Master may call mutating methods (service is authoritative).
Clients retrieve policy via read-only API endpoints.
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from master.app.database import get_connection
from master.app.utils.logger import get_logger
from master.app.utils.timezone import utc_to_local_display

logger = get_logger("apexeye.master.services.firewall")

# ---------------------------------------------------------------------------
# Domain normalization helpers
# ---------------------------------------------------------------------------

# Strip scheme, path, port — keep bare hostname
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
_VALID_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def normalize_domain(raw: str) -> str:
    """
    Normalize any user-entered value to a bare lowercase domain name.

    Examples:
      "https://www.Example.com/path?q=1" → "example.com"
      "http://facebook.com"              → "facebook.com"
      "www.youtube.com"                  → "youtube.com"
      "YouTube.com"                      → "youtube.com"

    Raises ValueError for clearly invalid input.
    """
    if not raw or not isinstance(raw, str):
        raise ValueError("Domain input must be a non-empty string.")

    raw = raw.strip()

    # Remove scheme if present
    if _SCHEME_RE.match(raw):
        parsed = urlparse(raw)
        hostname = (parsed.hostname or "").lower()
    else:
        # No scheme — treat everything before the first / or ? as hostname
        hostname = raw.split("/")[0].split("?")[0].split("#")[0].lower()

    # Strip port
    if ":" in hostname:
        hostname = hostname.rsplit(":", 1)[0]

    # Strip leading www. (only once, so sub.example.com remains as-is)
    if hostname.startswith("www."):
        hostname = hostname[4:]

    if not hostname:
        raise ValueError(f"Could not parse a hostname from: {raw!r}")

    if not _VALID_DOMAIN_RE.match(hostname):
        raise ValueError(
            f"'{hostname}' is not a valid domain name. "
            "Use a format like 'example.com' or 'sub.example.com'."
        )

    return hostname


def get_block_hostnames(normalized_domain: str) -> list[str]:
    """
    Return the list of hostnames to block in the hosts file for a domain.
    Always includes the bare domain and www. prefix.
    Example: "example.com" → ["example.com", "www.example.com"]
    """
    entries = [normalized_domain]
    if not normalized_domain.startswith("www."):
        entries.append(f"www.{normalized_domain}")
    return entries


# ---------------------------------------------------------------------------
# FirewallService
# ---------------------------------------------------------------------------


class FirewallService:
    """Manages all firewall policy, blocked domains, and activity logs."""

    # ── Settings helpers ────────────────────────────────────────────

    def _ensure_settings_row(self, conn) -> dict:
        """Ensure exactly one firewall_settings row exists; return it."""
        row = conn.execute(
            "SELECT id, enabled, policy_version, updated_at, updated_by "
            "FROM firewall_settings LIMIT 1;"
        ).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO firewall_settings (enabled, policy_version, updated_by) "
                "VALUES (0, 0, 'system');"
            )
            conn.commit()
            row = conn.execute(
                "SELECT id, enabled, policy_version, updated_at, updated_by "
                "FROM firewall_settings LIMIT 1;"
            ).fetchone()
        return dict(row)

    def _bump_version(self, conn, actor: str = "admin") -> int:
        """Increment policy_version and update timestamp. Returns new version."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        row = self._ensure_settings_row(conn)
        new_version = row["policy_version"] + 1
        conn.execute(
            "UPDATE firewall_settings SET policy_version = ?, updated_at = ?, updated_by = ? "
            "WHERE id = ?;",
            (new_version, now, actor, row["id"]),
        )
        return new_version

    # ── Audit logging ───────────────────────────────────────────────

    def _log_audit(self, conn, actor: str, action: str, target: str = "", details: str = "") -> None:
        """Write an entry to the existing audit_logs table."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_logs (timestamp, actor, action, target, details) "
            "VALUES (?, ?, ?, ?, ?);",
            (now, actor, action, target, details),
        )

    # ── Public: Policy ──────────────────────────────────────────────

    def get_policy(self) -> dict:
        """
        Return the current authoritative firewall policy.

        {
            "enabled": bool,
            "version": int,
            "blocked_domains": ["example.com", ...]
        }
        """
        conn = get_connection()
        try:
            row = self._ensure_settings_row(conn)
            domains = self._list_active_domains(conn)
            raw_up = row.get("updated_at", "")
            return {
                "enabled": bool(row["enabled"]),
                "version": row["policy_version"],
                "blocked_domains": [d["normalized_domain"] for d in domains],
                "updated_at": utc_to_local_display(raw_up),
                "updated_at_utc": raw_up,
            }
        finally:
            conn.close()

    def get_status(self) -> dict:
        """Return a summary dict for the Master dashboard widget."""
        conn = get_connection()
        try:
            row = self._ensure_settings_row(conn)
            domain_count = conn.execute(
                "SELECT COUNT(*) as c FROM firewall_blocked_domains WHERE is_active = 1;"
            ).fetchone()["c"]
            blocked_today = conn.execute(
                "SELECT COUNT(*) as c FROM firewall_logs "
                "WHERE date(timestamp) = date('now');"
            ).fetchone()["c"]
            raw_up = row.get("updated_at", "")
            return {
                "enabled": bool(row["enabled"]),
                "version": row["policy_version"],
                "domain_count": domain_count,
                "blocked_today": blocked_today,
                "updated_at": utc_to_local_display(raw_up),
                "updated_at_utc": raw_up,
                "updated_by": row.get("updated_by", "system"),
            }
        finally:
            conn.close()

    # ── Public: Enable / Disable ────────────────────────────────────

    def set_enabled(self, enabled: bool, actor: str = "admin") -> dict:
        """Enable or disable the firewall. Returns new policy dict."""
        conn = get_connection()
        try:
            self._ensure_settings_row(conn)
            new_version = self._bump_version(conn, actor)
            conn.execute(
                "UPDATE firewall_settings SET enabled = ?;",
                (1 if enabled else 0,),
            )
            action = "ADMIN_FIREWALL_ENABLED" if enabled else "ADMIN_FIREWALL_DISABLED"
            label = "enabled" if enabled else "disabled"
            self._log_audit(
                conn, actor, action,
                target="firewall",
                details=f"{actor} {label} APEXEYE Firewall. Policy version → {new_version}.",
            )
            conn.commit()
            logger.info("Firewall %s by %s (policy version %d)", label, actor, new_version)
            domains = self._list_active_domains(conn)
            return {
                "enabled": enabled,
                "version": new_version,
                "blocked_domains": [d["normalized_domain"] for d in domains],
            }
        finally:
            conn.close()

    # ── Public: Domain management ───────────────────────────────────

    def add_domain(self, raw_input: str, actor: str = "admin") -> dict:
        """
        Normalize, validate, and add a blocked domain.
        Returns the created domain record.
        Raises ValueError on invalid input or duplicate.
        """
        normalized = normalize_domain(raw_input)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        try:
            # Check duplicate (including inactive)
            existing = conn.execute(
                "SELECT id, is_active FROM firewall_blocked_domains "
                "WHERE normalized_domain = ?;",
                (normalized,),
            ).fetchone()

            if existing:
                if existing["is_active"]:
                    raise ValueError(f"Domain '{normalized}' is already in the blocked list.")
                # Reactivate soft-deleted domain
                conn.execute(
                    "UPDATE firewall_blocked_domains SET is_active = 1, created_at = ?, created_by = ? "
                    "WHERE id = ?;",
                    (now, actor, existing["id"]),
                )
                domain_id = existing["id"]
            else:
                cursor = conn.execute(
                    "INSERT INTO firewall_blocked_domains "
                    "(domain, normalized_domain, created_at, created_by, is_active) "
                    "VALUES (?, ?, ?, ?, 1);",
                    (raw_input.strip(), normalized, now, actor),
                )
                domain_id = cursor.lastrowid

            new_version = self._bump_version(conn, actor)
            self._log_audit(
                conn, actor, "ADMIN_BLOCKED_DOMAIN_ADDED",
                target=normalized,
                details=f"{actor} added '{normalized}' to blocked websites. "
                        f"Policy version → {new_version}.",
            )
            conn.commit()
            logger.info("Domain '%s' added by %s (v%d)", normalized, actor, new_version)
            return {
                "id": domain_id,
                "domain": raw_input.strip(),
                "normalized_domain": normalized,
                "created_at_utc": now,
                "created_at": utc_to_local_display(now),
                "created_by": actor,
                "policy_version": new_version,
            }
        finally:
            conn.close()

    def remove_domain(self, domain_id: int, actor: str = "admin") -> dict:
        """
        Soft-remove a blocked domain by ID.
        Historical firewall logs are preserved.
        """
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT id, normalized_domain FROM firewall_blocked_domains "
                "WHERE id = ? AND is_active = 1;",
                (domain_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"Active blocked domain with id={domain_id} not found.")

            normalized = row["normalized_domain"]
            conn.execute(
                "UPDATE firewall_blocked_domains SET is_active = 0 WHERE id = ?;",
                (domain_id,),
            )
            new_version = self._bump_version(conn, actor)
            self._log_audit(
                conn, actor, "ADMIN_BLOCKED_DOMAIN_REMOVED",
                target=normalized,
                details=f"{actor} removed '{normalized}' from blocked websites. "
                        f"Policy version → {new_version}.",
            )
            conn.commit()
            logger.info("Domain '%s' removed by %s (v%d)", normalized, actor, new_version)
            return {"removed": True, "domain": normalized, "policy_version": new_version}
        finally:
            conn.close()

    def list_domains(self) -> list[dict]:
        """List all active blocked domains."""
        conn = get_connection()
        try:
            return self._list_active_domains(conn)
        finally:
            conn.close()

    def _list_active_domains(self, conn) -> list[dict]:
        rows = conn.execute(
            "SELECT id, domain, normalized_domain, created_at, created_by "
            "FROM firewall_blocked_domains WHERE is_active = 1 ORDER BY created_at DESC;"
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            raw_ca = d.get("created_at", "")
            d["created_at_utc"] = raw_ca
            d["created_at"] = utc_to_local_display(raw_ca)
            result.append(d)
        return result

    def serialize_log(self, log_entry: dict) -> dict:
        """
        Serialize a firewall log dictionary for display/API consumption.
        Preserves the raw UTC timestamp in 'timestamp_utc' for auditing and ordering,
        and provides the local machine/operator timezone string in 'timestamp'.
        Guarantees idempotency (no double-conversion).
        """
        item = dict(log_entry)
        if item.get("_is_serialized"):
            return item

        raw_ts = item.get("timestamp_utc") or item.get("timestamp") or ""
        item["timestamp_utc"] = raw_ts
        item["timestamp"] = utc_to_local_display(raw_ts)
        item["_is_serialized"] = True
        return item

    # ── Public: Blocked-attempt logging ────────────────────────────

    def log_blocked_attempt(
        self,
        device_id: str,
        device_name: str,
        domain: str,
        url: str = "",
        platform: str = "unknown",
        policy_version: int = 0,
        destination_ip: str = "",
        metadata: dict | None = None,
    ) -> dict | None:
        """
        Record a blocked connection attempt from a client.

        De-duplication: one log entry per (device_id, domain) per minute.
        Returns the created log row, or None if suppressed as duplicate.
        """
        # Build a de-dup key: device_id + domain + policy_version + minute-precision timestamp
        # Scoping to policy_version ensures re-enabling or policy changes naturally allow new detections
        minute_bucket = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        raw_key = f"{device_id}:{domain}:v{policy_version}:{minute_bucket}"
        dedup_key = hashlib.sha256(raw_key.encode()).hexdigest()[:32]

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            # Check if already logged in this minute window
            existing = conn.execute(
                "SELECT id FROM firewall_logs WHERE dedup_key = ?;",
                (dedup_key,),
            ).fetchone()
            if existing:
                logger.debug(
                    "Firewall log suppressed (duplicate) for device=%s domain=%s",
                    device_id, domain,
                )
                return None

            meta_str = json.dumps(metadata) if metadata else None
            cursor = conn.execute(
                "INSERT INTO firewall_logs "
                "(device_id, device_name, domain, url, timestamp, action, "
                "policy_version, platform, destination_ip, metadata, dedup_key) "
                "VALUES (?, ?, ?, ?, ?, 'BLOCKED', ?, ?, ?, ?, ?);",
                (
                    device_id, device_name, domain, url or "", now,
                    policy_version, platform, destination_ip or "", meta_str,
                    dedup_key,
                ),
            )
            conn.commit()
            log_id = cursor.lastrowid
            logger.info(
                "Firewall BLOCKED: device=%s domain=%s platform=%s",
                device_id, domain, platform,
            )
            return self.serialize_log({
                "id": log_id,
                "device_id": device_id,
                "device_name": device_name,
                "domain": domain,
                "url": url,
                "timestamp": now,
                "action": "BLOCKED",
                "policy_version": policy_version,
                "platform": platform,
            })
        except Exception as exc:
            logger.error("Failed to write firewall log: %s", exc)
            return None
        finally:
            conn.close()

    def get_logs(
        self,
        device_id: str | None = None,
        domain: str | None = None,
        action: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Query firewall activity logs with optional filters.

        Filters:
          device_id  — exact match
          domain     — exact match
          action     — e.g. 'BLOCKED'
          since      — ISO datetime string (inclusive)
          until      — ISO datetime string (inclusive)
          limit      — max rows (capped at 500)
        """
        limit = min(max(int(limit), 1), 500)
        conditions = []
        params: list = []

        if device_id:
            conditions.append("device_id = ?")
            params.append(device_id)
        if domain:
            conditions.append("domain = ?")
            params.append(domain)
        if action:
            conditions.append("action = ?")
            params.append(action.upper())
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = (
            f"SELECT id, device_id, device_name, domain, url, timestamp, action, "
            f"policy_version, platform, destination_ip, metadata "
            f"FROM firewall_logs {where} ORDER BY timestamp DESC, id DESC LIMIT ?;"
        )
        params.append(limit)

        conn = get_connection()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [self.serialize_log(dict(r)) for r in rows]
        finally:
            conn.close()
