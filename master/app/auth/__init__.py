"""
APEXEYE MASTER — Authentication / Pairing Service

Phase 1: Secure credential generation, pairing status management.
Credentials are stored as hashed values — plaintext is shown once at generation.
"""

import hashlib
import secrets
from datetime import datetime, timezone, timedelta

from master.app.config import config
from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.auth")

VALID_AUTH_STATUSES = {"pending", "paired", "revoked"}


def _hash_token(token: str) -> str:
    """One-way SHA-256 hash of a token for storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthService:
    """Manages device pairing credentials."""

    def generate_pairing_credential(self, device_id: str) -> dict:
        """
        Generate a secure pairing token for a device.

        Returns a dict with the plaintext token (show once!) and metadata.
        The database only stores the hashed credential_id.
        """
        conn = get_connection()
        try:
            # Ensure the device exists
            device = conn.execute(
                "SELECT device_id FROM devices WHERE device_id = ?;",
                (device_id,),
            ).fetchone()
            if not device:
                raise ValueError(f"Device '{device_id}' not found.")

            # Revoke any existing active credentials for this device
            conn.execute(
                "UPDATE device_auth SET authentication_status = 'revoked' "
                "WHERE device_id = ? AND authentication_status != 'revoked';",
                (device_id,),
            )

            # Generate secure token
            raw_token = secrets.token_urlsafe(48)
            credential_hash = _hash_token(raw_token)
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            expires = (
                datetime.now(timezone.utc)
                + timedelta(hours=config.AUTH_TOKEN_EXPIRY_HOURS)
            ).strftime("%Y-%m-%d %H:%M:%S")

            conn.execute(
                """INSERT INTO device_auth
                   (device_id, credential_id, authentication_status,
                    created_at, expires_at)
                   VALUES (?,?,?,?,?)""",
                (device_id, credential_hash, "pending", now, expires),
            )
            # Update device authentication_status
            conn.execute(
                "UPDATE devices SET authentication_status = 'pending', "
                "updated_at = ? WHERE device_id = ?;",
                (now, device_id),
            )
            conn.commit()
            logger.info("Pairing credential generated for device %s", device_id)
            return {
                "device_id": device_id,
                "token": raw_token,  # Show to admin ONCE
                "credential_id": credential_hash,
                "status": "pending",
                "expires_at": expires,
            }
        finally:
            conn.close()

    def authenticate_device(self, device_id: str, token: str, device_info: dict | None = None) -> bool:
        """
        Validate a device's pairing token.
        On success, marks the credential and device as 'paired', status as 'online', touches last_seen.
        Synchronizes device_info metadata if provided.
        If the device does not exist in `devices` but the pairing credential is valid:
            creates the device record and marks it paired + online.
        """
        token_hash = _hash_token(token)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT id, expires_at, authentication_status FROM device_auth "
                "WHERE device_id = ? AND credential_id = ? "
                "AND authentication_status IN ('pending', 'paired');",
                (device_id, token_hash),
            ).fetchone()

            if not row:
                logger.warning("Auth failed for device %s: invalid credential or revoked", device_id)
                return False

            # Check expiry
            if row["expires_at"] and row["expires_at"] < now:
                logger.warning("Auth failed for device %s: credential expired", device_id)
                return False

            info = dict(device_info or {})
            if "device_info" in info and isinstance(info["device_info"], dict):
                info.update(info.pop("device_info"))
            info["device_id"] = device_id

            # Authoritatively upsert device: creates if new, updates if exists, status='online', auth_status='paired'
            from master.app.services.device_service import DeviceService
            device_svc = DeviceService()
            device_svc.upsert_device(
                info,
                status="online",
                auth_status="paired",
                last_seen=now,
            )

            # Mark credential as paired
            conn.execute(
                "UPDATE device_auth SET authentication_status = 'paired', "
                "last_used_at = ? WHERE id = ?;",
                (now, row["id"]),
            )
            conn.commit()
            logger.info("Device %s authenticated/paired successfully (status: online)", device_id)
            return True
        finally:
            conn.close()


    def revoke_device(self, device_id: str) -> bool:
        """Revoke all credentials for a device."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            cursor = conn.execute(
                "UPDATE device_auth SET authentication_status = 'revoked' "
                "WHERE device_id = ? AND authentication_status != 'revoked';",
                (device_id,),
            )
            conn.execute(
                "UPDATE devices SET authentication_status = 'unauthenticated', "
                "status = 'pending', updated_at = ? WHERE device_id = ?;",
                (now, device_id),
            )
            conn.commit()
            revoked = cursor.rowcount > 0
            if revoked:
                logger.info("Credentials revoked for device %s", device_id)
            return revoked
        finally:
            conn.close()

    def get_auth_status(self, device_id: str) -> dict | None:
        """Return the current authentication state for a device."""
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM device_auth "
                "WHERE device_id = ? ORDER BY created_at DESC LIMIT 1;",
                (device_id,),
            ).fetchone()
            if not row:
                return {"device_id": device_id, "status": "no_credentials"}
            return {
                "device_id": device_id,
                "credential_id": row["credential_id"],
                "status": row["authentication_status"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "last_used_at": row["last_used_at"],
            }
        finally:
            conn.close()
