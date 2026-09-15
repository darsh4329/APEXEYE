"""
APEXEYE MASTER — Device Management Service

Phase 1: Full device CRUD with validation.
"""

import re
from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.device")

VALID_DEVICE_TYPES = {"WINDOWS_PC", "LINUX_PC", "CCTV", "AWS_INSTANCE", "OTHER"}
VALID_STATUSES = {"pending", "online", "offline", "inactive", "not_seen"}

# Simple IPv4 pattern — not exhaustive but catches obvious junk
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


class ValidationError(Exception):
    """Raised when device data fails validation."""


class DeviceService:
    """Manages device registration, listing, and status updates."""

    # ── Validation ───────────────────────────────────────────────

    @staticmethod
    def _validate(data: dict, require_device_id: bool = True) -> None:
        """Validate device registration / update data."""
        if require_device_id:
            did = data.get("device_id", "").strip()
            if not did:
                raise ValidationError("device_id is required.")

        name = data.get("device_name", "").strip()
        if require_device_id and not name:
            raise ValidationError("device_name is required.")

        dtype = data.get("device_type", "").strip().upper()
        if require_device_id and dtype not in VALID_DEVICE_TYPES:
            raise ValidationError(
                f"device_type must be one of {VALID_DEVICE_TYPES}."
            )

        ip = data.get("ip_address", "").strip()
        if ip and not _IP_RE.match(ip):
            raise ValidationError(f"Invalid ip_address: {ip}")

    # ── CRUD ─────────────────────────────────────────────────────

    def register(self, data: dict) -> dict:
        """Register a new device. Returns the created device row as dict."""
        self._validate(data)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            conn.execute(
                """INSERT INTO devices
                   (device_id, device_name, device_type, operating_system,
                    hostname, ip_address, location, status,
                    authentication_status, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    data["device_id"].strip(),
                    data["device_name"].strip(),
                    data["device_type"].strip().upper(),
                    data.get("operating_system", "").strip() or None,
                    data.get("hostname", "").strip() or None,
                    data.get("ip_address", "").strip() or None,
                    data.get("location", "").strip() or None,
                    "pending",
                    "unauthenticated",
                    now,
                    now,
                ),
            )
            conn.commit()
            logger.info("Device registered: %s", data["device_id"])
            return self.get_device(data["device_id"].strip())
        except Exception as exc:
            conn.rollback()
            if "UNIQUE constraint" in str(exc):
                raise ValidationError(
                    f"Device ID '{data['device_id']}' already exists."
                ) from exc
            raise
        finally:
            conn.close()

    def upsert_device(
        self,
        data: dict,
        status: str | None = None,
        auth_status: str | None = None,
        last_seen: str | None = None,
    ) -> dict:
        """
        Authoritative upsert for device records.
        If device_id does not exist:
            create one device row (status = status or 'pending', authentication_status = auth_status or 'unauthenticated')
        If device_id already exists:
            update the existing row with provided metadata
            NEVER create a duplicate, NEVER change the device_id
        """
        did = (data.get("device_id") or "").strip()
        if not did:
            raise ValidationError("device_id is required.")

        self._validate(data, require_device_id=False)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        try:
            existing = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?;", (did,)
            ).fetchone()

            if not existing:
                dev_name = (data.get("device_name") or did).strip()
                dev_type = (data.get("device_type") or "WINDOWS_PC").strip().upper()
                if dev_type not in VALID_DEVICE_TYPES:
                    dev_type = "WINDOWS_PC"

                init_status = status or data.get("status") or "pending"
                init_auth = auth_status or data.get("authentication_status") or "unauthenticated"
                init_last_seen = last_seen or (now if init_status == "online" else None)

                conn.execute(
                    """INSERT INTO devices
                       (device_id, device_name, device_type, operating_system,
                        hostname, ip_address, location, status,
                        authentication_status, created_at, updated_at, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        did,
                        dev_name,
                        dev_type,
                        (data.get("operating_system") or "").strip() or None,
                        (data.get("hostname") or "").strip() or None,
                        (data.get("ip_address") or "").strip() or None,
                        (data.get("location") or "").strip() or None,
                        init_status,
                        init_auth,
                        now,
                        now,
                        init_last_seen,
                    ),
                )
                conn.commit()
                logger.info("Device upserted (created): %s (status: %s)", did, init_status)
            else:
                # Update existing row
                sets = ["updated_at = ?"]
                vals = [now]

                if "device_name" in data and data["device_name"]:
                    sets.append("device_name = ?")
                    vals.append(str(data["device_name"]).strip())
                if "device_type" in data and data["device_type"]:
                    dtype = str(data["device_type"]).strip().upper()
                    if dtype in VALID_DEVICE_TYPES:
                        sets.append("device_type = ?")
                        vals.append(dtype)
                if "operating_system" in data and data["operating_system"]:
                    sets.append("operating_system = ?")
                    vals.append(str(data["operating_system"]).strip())
                if "hostname" in data and data["hostname"]:
                    sets.append("hostname = ?")
                    vals.append(str(data["hostname"]).strip())
                if "ip_address" in data and data["ip_address"]:
                    sets.append("ip_address = ?")
                    vals.append(str(data["ip_address"]).strip())
                if "location" in data and data["location"] is not None:
                    sets.append("location = ?")
                    vals.append(str(data["location"]).strip() if data["location"] else None)

                target_status = status or data.get("status")
                if target_status:
                    sets.append("status = ?")
                    vals.append(target_status)

                target_auth = auth_status or data.get("authentication_status")
                if target_auth:
                    sets.append("authentication_status = ?")
                    vals.append(target_auth)

                if last_seen:
                    sets.append("last_seen = ?")
                    vals.append(last_seen)
                elif target_status == "online":
                    sets.append("last_seen = ?")
                    vals.append(now)

                vals.append(did)
                conn.execute(
                    f"UPDATE devices SET {', '.join(sets)} WHERE device_id = ?;",
                    vals,
                )
                conn.commit()
                logger.info("Device upserted (updated): %s (status: %s)", did, target_status or existing["status"])

            return self.get_device(did)
        finally:
            conn.close()

    def reconcile_presence(self, timeout_seconds: int | None = None) -> int:
        """
        Evaluate online devices against the heartbeat timeout grace period.
        Transitions devices that have not communicated within the timeout to 'offline'.
        Preserves last_seen, device identity, authentication, historical telemetry and logs.
        Returns count of devices transitioned.
        """
        if timeout_seconds is None:
            try:
                from master.app.config import config
                timeout_seconds = getattr(config, "HEARTBEAT_TIMEOUT_SECONDS", 9)
            except Exception:
                timeout_seconds = 9

        from datetime import timedelta
        now_dt = datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(seconds=timeout_seconds)).strftime("%Y-%m-%d %H:%M:%S")
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        try:
            cursor = conn.execute(
                """UPDATE devices
                   SET status = 'offline', updated_at = ?
                   WHERE status = 'online'
                     AND (
                         (last_seen IS NOT NULL AND last_seen < ?)
                         OR (last_seen IS NULL AND updated_at < ?)
                     );""",
                (now_str, cutoff, cutoff),
            )
            conn.commit()
            transitioned = cursor.rowcount
            if transitioned > 0:
                logger.info(
                    "Presence reconciliation: transitioned %d device(s) to 'offline' (timeout=%ds)",
                    transitioned,
                    timeout_seconds,
                )
            return transitioned
        finally:
            conn.close()

    def get_device(self, device_id: str, with_telemetry: bool = False) -> dict | None:
        """Return a single device by device_id or None. Optionally includes latest telemetry."""
        self.reconcile_presence()
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?;", (device_id,)
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            if with_telemetry:
                tel_row = conn.execute(
                    "SELECT * FROM telemetry WHERE device_id = ? ORDER BY timestamp DESC, id DESC LIMIT 1;",
                    (device_id,),
                ).fetchone()
                if tel_row:
                    tel_dict = dict(tel_row)
                    if tel_dict.get("details"):
                        try:
                            import json
                            tel_dict["details"] = json.loads(tel_dict["details"])
                        except Exception:
                            pass
                    result["latest_telemetry"] = tel_dict
                else:
                    result["latest_telemetry"] = None
            return result
        finally:
            conn.close()

    def list_devices(self) -> list[dict]:
        """Return all registered devices."""
        self.reconcile_presence()
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY created_at DESC;"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def list_devices_with_telemetry(self) -> list[dict]:
        """Return all registered devices with their latest telemetry metrics attached."""
        self.reconcile_presence()
        import json
        conn = get_connection()
        try:
            rows = conn.execute(
                """SELECT d.*,
                          t.cpu_usage, t.memory_usage, t.disk_usage, t.network_usage,
                          t.memory_total_gb, t.memory_used_gb, t.disk_total_gb, t.disk_free_gb,
                          t.network_bytes_sent_mb, t.network_bytes_recv_mb,
                          t.timestamp AS telemetry_timestamp, t.details AS telemetry_details
                   FROM devices d
                   LEFT JOIN telemetry t ON t.id = (
                       SELECT id FROM telemetry WHERE device_id = d.device_id ORDER BY timestamp DESC, id DESC LIMIT 1
                   )
                   ORDER BY d.created_at DESC;"""
            ).fetchall()

            result = []
            for r in rows:
                item = dict(r)
                if item.get("telemetry_details"):
                    try:
                        item["telemetry_details"] = json.loads(item["telemetry_details"])
                    except Exception:
                        pass
                result.append(item)
            return result
        finally:
            conn.close()

    def update_device(self, device_id: str, data: dict) -> dict | None:
        """Update mutable fields of an existing device."""
        existing = self.get_device(device_id)
        if not existing:
            return None

        self._validate(data, require_device_id=False)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Build SET clause from allowed fields
        allowed = {
            "device_name", "device_type", "operating_system",
            "hostname", "ip_address", "location", "status",
        }
        sets, vals = [], []
        for key in allowed:
            if key in data and data[key] is not None:
                val = data[key].strip() if isinstance(data[key], str) else data[key]
                if key == "device_type":
                    val = val.upper()
                    if val not in VALID_DEVICE_TYPES:
                        raise ValidationError(
                            f"device_type must be one of {VALID_DEVICE_TYPES}."
                        )
                sets.append(f"{key} = ?")
                vals.append(val)

        if not sets:
            return existing

        sets.append("updated_at = ?")
        vals.append(now)
        vals.append(device_id)

        conn = get_connection()
        try:
            conn.execute(
                f"UPDATE devices SET {', '.join(sets)} WHERE device_id = ?;",
                vals,
            )
            conn.commit()
            logger.info("Device updated: %s", device_id)
            return self.get_device(device_id)
        finally:
            conn.close()

    def remove_device(self, device_id: str) -> bool:
        """De-register a device. Returns True if deleted, False if not found."""
        conn = get_connection()
        try:
            cursor = conn.execute(
                "DELETE FROM devices WHERE device_id = ?;", (device_id,)
            )
            conn.commit()
            if cursor.rowcount > 0:
                logger.info("Device removed: %s", device_id)
                return True
            return False
        finally:
            conn.close()

    # ── Status helpers ───────────────────────────────────────────

    def update_status(self, device_id: str, status: str) -> None:
        """Set the status field for a device."""
        if status not in VALID_STATUSES:
            raise ValidationError(f"status must be one of {VALID_STATUSES}.")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            if status == "online":
                conn.execute(
                    "UPDATE devices SET status = ?, last_seen = COALESCE(last_seen, ?), updated_at = ? WHERE device_id = ?;",
                    (status, now, now, device_id),
                )
            else:
                conn.execute(
                    "UPDATE devices SET status = ?, updated_at = ? WHERE device_id = ?;",
                    (status, now, device_id),
                )
            conn.commit()
        finally:
            conn.close()

    def update_last_seen(self, device_id: str) -> None:
        """Touch last_seen timestamp (used by heartbeat in Phase 2+)."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE devices SET last_seen = ?, updated_at = ? WHERE device_id = ?;",
                (now, now, device_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ── Dashboard summary ────────────────────────────────────────

    def get_summary(self) -> dict:
        """Return counts for the dashboard."""
        self.reconcile_presence()
        conn = get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM devices;").fetchone()[0]
            online = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE status = 'online';"
            ).fetchone()[0]
            offline = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE status = 'offline';"
            ).fetchone()[0]
            pending = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE status = 'pending';"
            ).fetchone()[0]
            return {
                "total": total,
                "online": online,
                "offline": offline,
                "pending": pending,
                "attention": pending,  # devices needing action
                "total_devices": total,
                "online_devices": online,
                "offline_devices": offline,
                "pending_devices": pending,
            }
        finally:
            conn.close()
