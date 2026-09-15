"""
APEXEYE CLIENT — Authentication Module

Phase 1: Manages local credential persistence and the pairing workflow.
Phase 2: Credentials are obfuscated before storage — never stored as
         plaintext on disk or in logs.
"""

import base64
import hashlib
import json
import platform
import socket
from pathlib import Path

from client.app.config import config
from client.app.communication import MasterConnection
from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.auth")

# Credential store lives next to the client config, NOT in the Master DB.
_CRED_FILE = Path(config.LOG_PATH).parent / "client" / ".credentials.json"


# ── Credential Obfuscation ──────────────────────────────────────
# Not production-grade encryption (that's Phase 10). This prevents
# the token from sitting in plaintext on disk. Uses a machine-derived
# key so credentials aren't portable between hosts.

def _derive_key() -> bytes:
    """Derive a machine-specific key from hostname + platform."""
    seed = f"{platform.node()}:{platform.machine()}:{platform.system()}"
    return hashlib.sha256(seed.encode("utf-8")).digest()


def _obfuscate(plaintext: str) -> str:
    """Obfuscate a string using XOR with a machine-derived key, then base64."""
    key = _derive_key()
    data = plaintext.encode("utf-8")
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.urlsafe_b64encode(xored).decode("ascii")


def _deobfuscate(encoded: str) -> str:
    """Reverse the obfuscation."""
    key = _derive_key()
    xored = base64.urlsafe_b64decode(encoded.encode("ascii"))
    data = bytes(b ^ key[i % len(key)] for i, b in enumerate(xored))
    return data.decode("utf-8")


class ClientAuth:
    """Handles the full pairing lifecycle with the Master."""

    def __init__(self, conn: MasterConnection):
        self.conn = conn
        self._creds: dict | None = None
        self._authenticated: bool = False
        self._load_stored_credentials()

    # ── Credential persistence ──────────────────────────────────

    def _load_stored_credentials(self) -> None:
        """Load previously stored credentials from disk."""
        if _CRED_FILE.exists():
            try:
                raw = json.loads(_CRED_FILE.read_text("utf-8"))
                # Deobfuscate the token
                if raw.get("_token_enc"):
                    raw["token"] = _deobfuscate(raw["_token_enc"])
                    del raw["_token_enc"]
                self._creds = raw
                logger.info(
                    "Loaded stored credentials for device %s",
                    self._creds.get("device_id"),
                )
            except Exception as exc:
                logger.warning("Could not read stored credentials: %s", exc)
                self._creds = None

    def _save_credentials(self, creds: dict) -> None:
        """Persist credentials to disk with obfuscated token."""
        _CRED_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Store with obfuscated token — never plaintext
        stored = {
            "device_id": creds["device_id"],
            "_token_enc": _obfuscate(creds["token"]),
            "status": creds["status"],
        }
        _CRED_FILE.write_text(json.dumps(stored, indent=2), "utf-8")
        self._creds = creds
        logger.info("Credentials saved (obfuscated) to %s", _CRED_FILE)

    def _clear_credentials(self) -> None:
        """Remove stored authentication token while preserving persistent device identity."""
        dev_id = self.device_id or getattr(config, "CLIENT_ID", None) or socket.gethostname().lower()
        self._authenticated = False
        stored = {
            "device_id": dev_id,
            "status": "unauthenticated",
        }
        try:
            _CRED_FILE.parent.mkdir(parents=True, exist_ok=True)
            _CRED_FILE.write_text(json.dumps(stored, indent=2), "utf-8")
        except Exception as exc:
            logger.warning("Could not write cleared credentials file: %s", exc)
        self._creds = stored
        logger.info("Credentials cleared (persistent device identity '%s' preserved)", dev_id)

    @property
    def is_authenticated(self) -> bool:
        """Return True only when active live authentication has been established with Master."""
        return bool(self._authenticated and self.conn.is_authenticated and self.device_id and self.token)

    @property
    def is_paired(self) -> bool:
        return bool(self._creds and self._creds.get("status") == "paired" and self._creds.get("token"))

    @property
    def device_id(self) -> str | None:
        return self._creds.get("device_id") if self._creds else None

    @property
    def token(self) -> str | None:
        """Return the stored auth token for authenticated requests."""
        return self._creds.get("token") if self._creds else None

    # ── Authentication / Pairing flow ────────────────────────────

    def authenticate(self, device_id: str, token: str) -> tuple[bool, str]:
        """
        Authenticate against Master using provided Device ID and Token.
        Sends complete device identity information and stores credentials on success.
        """
        device_id = device_id.strip()
        token = token.strip()

        if not device_id or not token:
            return False, "Device ID and Authentication Token are required."

        logger.info("[AUTH] Starting Master authentication")
        logger.info("[AUTH] Device ID: %s", device_id)
        logger.info("[AUTH] Contacting Master: /api/devices/%s/authenticate", device_id)

        device_info = self._build_device_info(device_id)
        status, resp = self.conn.authenticate(device_id, token, device_info=device_info)
        logger.info("[AUTH] Master response: %s", status)

        if status == 200:
            logger.info("[AUTH] Master authentication successful")
            logger.info("[DEVICE] Master registration synchronized")
            self._authenticated = True
            self._save_credentials({
                "device_id": device_id,
                "token": token,
                "status": "paired",
            })
            self.conn.set_identity(device_id, token)
            return True, "Authenticated successfully."
        elif status in (401, 403, 404):
            self._authenticated = False
            self.conn.clear_identity()
            self._clear_credentials()
            err_msg = resp.get("error", "Authentication failed.") if isinstance(resp, dict) else "Authentication failed."
            logger.warning("[AUTH] Master authentication rejected for device %s: %s", device_id, err_msg)
            return False, "Authentication failed: Invalid Device ID or Token, or device is not paired on Master."
        else:
            self._authenticated = False
            self.conn.clear_identity()
            err_msg = resp.get("error", "Connection error") if isinstance(resp, dict) else str(resp)
            logger.warning("[AUTH] Master unreachable at %s (%s): %s", self.conn.master_url, status, err_msg)
            return False, f"Master unreachable at {self.conn.master_url}: {err_msg}"

    def pair(self, device_id: str | None = None, token: str | None = None) -> bool:
        """
        Client pairing flow:
        1. If device_id and token passed explicitly -> authenticate and store.
        2. If stored credentials exist -> verify with Master.
        3. Returns True if successfully authenticated/verified, False otherwise.
        """
        if device_id and token:
            ok, _ = self.authenticate(device_id, token)
            return ok

        # Check existing stored credentials
        if self._creds and self._creds.get("token"):
            ok, should_clear = self._verify_existing()
            if ok:
                return True
            if should_clear:
                logger.warning("[AUTH] Stored credentials are no longer valid on Master (401/403). Clearing credentials.")
                self._clear_credentials()
            else:
                logger.warning("[AUTH] Master unreachable during credential verification. Stored credentials preserved.")
            return False

        return False

    def _verify_existing(self) -> tuple[bool, bool]:
        """
        Check if stored credentials are still valid on the Master and synchronize identity.
        Returns: (is_valid: bool, should_clear: bool)
        """
        device_id = self._creds.get("device_id")
        token = self._creds.get("token")
        if not device_id or not token:
            return False, True

        logger.info("[AUTH] Starting Master authentication")
        logger.info("[AUTH] Device ID: %s", device_id)
        logger.info("[AUTH] Contacting Master: /api/devices/%s/authenticate", device_id)

        device_info = self._build_device_info(device_id)
        status, resp = self.conn.authenticate(device_id, token, device_info=device_info)
        logger.info("[AUTH] Master response: %s", status)

        if status == 200:
            logger.info("[AUTH] Master authentication successful")
            logger.info("[DEVICE] Master registration synchronized")
            self._authenticated = True
            self.conn.set_identity(device_id, token)
            return True, False
        elif status in (401, 403, 404):
            self._authenticated = False
            self.conn.clear_identity()
            logger.warning("[AUTH] Existing pairing rejected by Master (%s): %s", status, resp)
            return False, True
        else:
            self._authenticated = False
            self.conn.clear_identity()
            logger.warning("[AUTH] Master unreachable during existing pairing verification (%s): %s", status, resp)
            return False, False

    def _build_device_info(self, device_id: str | None = None) -> dict:
        """Collect local system information for registration."""
        dev_id = device_id or self.device_id or getattr(config, "CLIENT_ID", None) or socket.gethostname().lower()
        return {
            "device_id": dev_id,
            "device_name": socket.gethostname(),
            "device_type": "WINDOWS_PC" if platform.system() == "Windows" else "LINUX_PC",
            "operating_system": f"{platform.system()} {platform.release()}",
            "hostname": socket.gethostname(),
            "ip_address": self._get_local_ip(),
        }

    @staticmethod
    def _get_local_ip() -> str:
        """Best-effort local IP detection."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
