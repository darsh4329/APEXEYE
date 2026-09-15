"""
APEXEYE MASTER - Configuration Module

Loads configuration from environment variables / .env file with robust discovery.
"""

import os
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


def find_env_file() -> Optional[Path]:
    """Deterministically find .env file for Master."""
    explicit = os.getenv("APEXEYE_ENV_FILE") or os.getenv("APEXEEYE_ENV_FILE")
    if explicit:
        p = Path(explicit).resolve()
        if p.is_file():
            return p

    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        return cwd_env.resolve()

    master_dir = Path(__file__).resolve().parent.parent.parent
    master_env = master_dir / ".env"
    if master_env.is_file():
        return master_env.resolve()

    for parent in master_dir.parents:
        cand = parent / ".env"
        if cand.is_file():
            return cand.resolve()

    return None


_env_file = find_env_file()
if _env_file and load_dotenv:
    try:
        load_dotenv(str(_env_file), override=False)
    except Exception:
        pass

_PROJECT_ROOT = _env_file.parent if _env_file else Path(__file__).resolve().parent.parent.parent.parent


class MasterConfig:
    """Central configuration for the APEXEYE Master."""

    APP_NAME = "APEXEYE Master"
    VERSION = "0.1.0"

    # Environment
    ENV = os.getenv("APEXEYE_ENV", "development")

    # Server
    HOST = os.getenv("APEXEYE_MASTER_HOST", "0.0.0.0")
    PORT = int(os.getenv("APEXEYE_MASTER_PORT", "9100"))

    @property
    def ADVERTISE_IP(self) -> str:
        return (os.getenv("APEXEYE_ADVERTISE_IP") or os.getenv("APEXEYE_MASTER_ADVERTISE_IP") or "").strip()

    @property
    def primary_lan_ip(self) -> str:
        if self.ADVERTISE_IP:
            return self.ADVERTISE_IP
        from master.app.utils.network import get_primary_lan_ip
        return get_primary_lan_ip()

    @property
    def lan_url(self) -> str:
        return f"http://{self.primary_lan_ip}:{self.PORT}"

    # Database
    DB_PATH = os.getenv(
        "APEXEYE_DB_PATH",
        str(_PROJECT_ROOT / "database" / "apexeye.db"),
    )

    # Logging
    LOG_PATH = os.getenv(
        "APEXEYE_LOG_PATH",
        str(_PROJECT_ROOT / "logs"),
    )
    LOG_LEVEL = os.getenv("APEXEYE_LOG_LEVEL", "DEBUG")

    # Authentication (Phase 1+)
    AUTH_TOKEN_EXPIRY_HOURS = int(
        os.getenv("APEXEYE_AUTH_TOKEN_EXPIRY_HOURS", "24")
    )

    # Telemetry (Phase 2+)
    TELEMETRY_INTERVAL = int(
        os.getenv("APEXEYE_TELEMETRY_INTERVAL_SECONDS", "10")
    )

    # Presence & Heartbeat Timeout
    HEARTBEAT_TIMEOUT_SECONDS = int(
        os.getenv("APEXEYE_HEARTBEAT_TIMEOUT_SECONDS", "9")
    )
    PRESENCE_CHECK_INTERVAL = int(
        os.getenv("APEXEYE_PRESENCE_CHECK_INTERVAL_SECONDS", "1")
    )

    # CCTV Monitoring (Phase 4)
    CCTV_CHECK_INTERVAL = int(
        os.getenv("APEXEYE_CCTV_CHECK_INTERVAL_SECONDS", "30")
    )
    CCTV_TCP_TIMEOUT = float(
        os.getenv("APEXEYE_CCTV_TCP_TIMEOUT_SECONDS", "3.0")
    )
    CCTV_RTSP_TIMEOUT = float(
        os.getenv("APEXEYE_CCTV_RTSP_TIMEOUT_SECONDS", "4.0")
    )


config = MasterConfig()
