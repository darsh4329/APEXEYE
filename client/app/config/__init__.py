"""
APEXEYE CLIENT — Configuration Module

Loads Client-specific configuration with deterministic .env discovery,
pure-Python .env parsing fallback (no external dependency required),
robust multi-tier Master resolution, and explicit configuration source tracking.

MASTER_URL Precedence:
  1. Process environment variable: APEXEYE_MASTER_URL
  2. Active .env file: APEXEYE_MASTER_URL
  3. Legacy split environment: APEXEYE_MASTER_ADDRESS + APEXEYE_MASTER_SERVER_PORT
  4. Automatic LAN Discovery (UDP 9101 subnet-directed broadcast)
  5. Hostname / DNS Discovery (apexeye-master, mDNS)
  6. Cached verified Master endpoint (.apexeye_master_cache.json)
  7. Safe default: http://127.0.0.1:9100 (localhost fallback)
"""

import json
import os
import socket
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv, dotenv_values
except ImportError:
    load_dotenv = None
    dotenv_values = None


def parse_env_file(filepath: Path) -> Dict[str, str]:
    """
    Parse a .env file into a dictionary without requiring external python-dotenv.
    Handles quotes, export prefixes, inline comments, and whitespace safely.
    """
    env_dict: Dict[str, str] = {}
    if not filepath or not filepath.is_file():
        return env_dict

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip()

                    # Handle quoted values with potential trailing comments
                    if val.startswith('"') and '"' in val[1:]:
                        end_q = val.find('"', 1)
                        val = val[1:end_q]
                    elif val.startswith("'") and "'" in val[1:]:
                        end_q = val.find("'", 1)
                        val = val[1:end_q]
                    else:
                        if " #" in val:
                            val = val.split(" #", 1)[0].strip()
                        if (val.startswith('"') and val.endswith('"')) or (
                            val.startswith("'") and val.endswith("'")
                        ):
                            val = val[1:-1]

                    if key:
                        env_dict[key] = val
    except Exception:
        pass

    return env_dict


def get_candidate_env_paths() -> List[Path]:
    """
    Generate an ordered list of candidate .env paths based on the current execution context.
    Search Order:
      1. Explicit APEXEYE_ENV_FILE / APEXEEYE_ENV_FILE
      2. Script/entrypoint invocation directory (sys.argv[0]) and its parents
      3. Current working directory (Path.cwd()) and its parents
      4. Configuration module directory (__file__) and its parents
      5. Nested client/.env subdirectories
    """
    candidates: List[Path] = []
    seen = set()

    def add_candidate(p: Path):
        try:
            resolved = p.resolve()
            if resolved not in seen:
                seen.add(resolved)
                candidates.append(resolved)
        except Exception:
            pass

    # 1. Explicit override
    explicit = os.getenv("APEXEYE_ENV_FILE") or os.getenv("APEXEEYE_ENV_FILE")
    if explicit:
        add_candidate(Path(explicit))

    # 2. Entrypoint / script directory (sys.argv[0])
    try:
        if sys.argv and sys.argv[0]:
            argv_p = Path(sys.argv[0]).resolve()
            if argv_p.name.lower() not in ("pytest", "pytest.exe", "-c"):
                start_dir = argv_p.parent if argv_p.is_file() else argv_p
                add_candidate(start_dir / ".env")
                add_candidate(start_dir / "client" / ".env")
                for parent in start_dir.parents:
                    add_candidate(parent / ".env")
                    add_candidate(parent / "client" / ".env")
    except Exception:
        pass

    # 3. Current working directory
    try:
        cwd = Path.cwd().resolve()
        add_candidate(cwd / ".env")
        add_candidate(cwd / "client" / ".env")
        for parent in cwd.parents:
            add_candidate(parent / ".env")
            add_candidate(parent / "client" / ".env")
    except Exception:
        pass

    # 4. Config module location (__file__)
    try:
        cfg_dir = Path(__file__).resolve().parent
        add_candidate(cfg_dir / ".env")
        for parent in cfg_dir.parents:
            add_candidate(parent / ".env")
            add_candidate(parent / "client" / ".env")
    except Exception:
        pass

    return candidates


def find_env_file() -> Optional[Path]:
    """
    Deterministically discover the .env file path across diverse deployment layouts.
    Returns the first existing candidate .env path or None.
    """
    for candidate in get_candidate_env_paths():
        if candidate.is_file():
            return candidate
    return None


def is_loopback_url(url: str) -> bool:
    """Check if a URL points to localhost/loopback."""
    if not url:
        return False
    try:
        clean = url.strip()
        if "://" in clean:
            clean = clean.split("://", 1)[1]
        clean = clean.split("/", 1)[0]
        if clean.startswith("[") and "]" in clean:
            host = clean[1:clean.index("]")].lower()
        elif clean.count(":") == 1:
            host = clean.split(":", 1)[0].lower()
        elif clean.startswith("::1"):
            host = "::1"
        else:
            parsed = urlparse(url)
            host = (parsed.hostname or clean).lower()
        return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "testclient")
    except Exception:
        return False


class ResolutionDetails:
    """Diagnostic details of the configuration resolution process."""

    def __init__(self):
        self.env_discovered: bool = False
        self.env_path: Optional[str] = None
        self.env_contains_master: bool = False
        self.parsed_master_url: Optional[str] = None
        self.process_env_master_set: bool = False
        self.lan_discovery_attempted: bool = False
        self.lan_discovery_result: Optional[str] = None
        self.hostname_discovery_result: Optional[str] = None
        self.cache_discovery_result: Optional[str] = None
        self.final_master_url: str = "http://127.0.0.1:9100"
        self.final_source: str = "default (localhost fallback)"
        self.target_host: str = "127.0.0.1"
        self.target_port: int = 9100


_last_resolution_details: ResolutionDetails = ResolutionDetails()


def get_last_resolution_details() -> ResolutionDetails:
    """Retrieve diagnostic details from the most recent configuration resolution."""
    return _last_resolution_details


def _resolve_master_configuration(enable_discovery: bool = True) -> Tuple[str, str, Optional[str], str, int]:
    """
    Resolve Master URL, configuration source, loaded .env path, target host, and target port.

    Precedence:
      1. Process environment: APEXEYE_MASTER_URL
      2. Active .env file: APEXEYE_MASTER_URL
      3. Legacy split environment: APEXEYE_MASTER_ADDRESS + APEXEYE_MASTER_SERVER_PORT
      4. Automatic LAN Discovery (UDP 9101)
      5. Hostname Discovery
      6. Cached Master endpoint
      7. Safe default: http://127.0.0.1:9100

    Returns:
        (master_url, source_description, loaded_env_path_str_or_None, target_host, target_port)
    """
    global _last_resolution_details
    details = ResolutionDetails()

    env_file_path = find_env_file()
    dotenv_dict: Dict[str, str] = {}

    # Check if process environment variable was already explicitly set before loading .env
    proc_master_url = os.environ.get("APEXEYE_MASTER_URL", "").strip()
    proc_master_addr = os.environ.get("APEXEYE_MASTER_ADDRESS", "").strip()

    if proc_master_url or proc_master_addr:
        details.process_env_master_set = True

    if env_file_path:
        details.env_discovered = True
        details.env_path = str(env_file_path)
        # 1. Pure-Python parsing (always works even if python-dotenv is missing)
        dotenv_dict = parse_env_file(env_file_path)

        # 2. Populate os.environ with fallback values if not already present
        for k, v in dotenv_dict.items():
            if k not in os.environ:
                os.environ[k] = v

        # 3. If python-dotenv is available, invoke load_dotenv as well
        if load_dotenv:
            try:
                load_dotenv(str(env_file_path), override=False)
            except Exception:
                pass

    loaded_env_str = str(env_file_path) if env_file_path else None
    env_master_url = dotenv_dict.get("APEXEYE_MASTER_URL", "").strip()
    env_master_addr = dotenv_dict.get("APEXEYE_MASTER_ADDRESS", "").strip()

    if env_master_url:
        details.env_contains_master = True
        details.parsed_master_url = env_master_url
    elif env_master_addr:
        details.env_contains_master = True
        env_port = dotenv_dict.get("APEXEYE_MASTER_SERVER_PORT", "9100").strip()
        details.parsed_master_url = f"http://{env_master_addr}:{env_port}"

    resolved_url: Optional[str] = None
    source: Optional[str] = None

    # ── Tier 1: Process environment variable APEXEYE_MASTER_URL ──
    if proc_master_url:
        resolved_url = proc_master_url
        source = "environment (APEXEYE_MASTER_URL)"
        if enable_discovery:
            try:
                from client.app.discovery import verify_master_endpoint, save_cached_master, master_discoverer
                ok, _ = verify_master_endpoint(proc_master_url, timeout=2.0)
                if ok:
                    save_cached_master(proc_master_url, source=source)
                else:
                    # Explicit env URL unreachable: attempt LAN discovery recovery
                    details.lan_discovery_attempted = True
                    lan_res = master_discoverer.discover_via_udp_lan(timeout=2.0)
                    if lan_res:
                        details.lan_discovery_result = lan_res[0]
                        resolved_url = lan_res[0]
                        source = lan_res[1]
            except Exception:
                pass

    # ── Tier 2: .env file explicit APEXEYE_MASTER_URL ────────────
    elif env_master_url:
        resolved_url = env_master_url
        source = f".env ({loaded_env_str})"
        if enable_discovery:
            try:
                from client.app.discovery import verify_master_endpoint, save_cached_master, master_discoverer
                ok, _ = verify_master_endpoint(env_master_url, timeout=2.0)
                if ok:
                    save_cached_master(env_master_url, source=source)
                else:
                    # Broken/unreachable .env URL: attempt LAN discovery recovery
                    details.lan_discovery_attempted = True
                    lan_res = master_discoverer.discover_via_udp_lan(timeout=2.0)
                    if lan_res:
                        details.lan_discovery_result = lan_res[0]
                        resolved_url = lan_res[0]
                        source = lan_res[1]
                    else:
                        # Check hostname & cache
                        host_res = master_discoverer.discover_via_hostnames()
                        if host_res:
                            details.hostname_discovery_result = host_res[0]
                            resolved_url = host_res[0]
                            source = host_res[1]
                        else:
                            cache_res = master_discoverer.discover_via_cache()
                            if cache_res:
                                details.cache_discovery_result = cache_res[0]
                                resolved_url = cache_res[0]
                                source = cache_res[1]
            except Exception:
                pass

    # ── Tier 3: Legacy split environment APEXEYE_MASTER_ADDRESS ──
    elif proc_master_addr or env_master_addr:
        addr = (
            proc_master_addr
            or env_master_addr
            or os.getenv("APEXEYE_MASTER_ADDRESS", "127.0.0.1")
        ).strip()
        port = (
            os.getenv("APEXEYE_MASTER_SERVER_PORT")
            or dotenv_dict.get("APEXEYE_MASTER_SERVER_PORT", "9100")
        ).strip()
        resolved_url = f"http://{addr}:{port}"
        source = "environment (APEXEYE_MASTER_ADDRESS)" if proc_master_addr else f".env ({loaded_env_str})"
        if enable_discovery and addr not in ("127.0.0.1", "localhost", "0.0.0.0"):
            try:
                from client.app.discovery import verify_master_endpoint, save_cached_master, master_discoverer
                ok, _ = verify_master_endpoint(resolved_url, timeout=2.0)
                if ok:
                    save_cached_master(resolved_url, source=source)
                else:
                    details.lan_discovery_attempted = True
                    lan_res = master_discoverer.discover_via_udp_lan(timeout=2.0)
                    if lan_res:
                        details.lan_discovery_result = lan_res[0]
                        resolved_url = lan_res[0]
                        source = lan_res[1]
            except Exception:
                pass

    # ── Tier 4: Automatic Discovery (LAN, Hostname, Cache) ───────
    elif enable_discovery:
        try:
            from client.app.discovery import master_discoverer
            details.lan_discovery_attempted = True
            lan_res = master_discoverer.discover_via_udp_lan(timeout=2.0)
            if lan_res:
                details.lan_discovery_result = lan_res[0]
                resolved_url = lan_res[0]
                source = lan_res[1]
            else:
                host_res = master_discoverer.discover_via_hostnames()
                if host_res:
                    details.hostname_discovery_result = host_res[0]
                    resolved_url = host_res[0]
                    source = host_res[1]
                else:
                    cache_res = master_discoverer.discover_via_cache()
                    if cache_res:
                        details.cache_discovery_result = cache_res[0]
                        resolved_url = cache_res[0]
                        source = cache_res[1]
                    else:
                        resolved_url = "http://127.0.0.1:9100"
                        source = "default (localhost fallback)"
        except Exception:
            resolved_url = "http://127.0.0.1:9100"
            source = "default (localhost fallback)"

    # ── Tier 5: Safe Localhost Fallback ──────────────────────────
    if not resolved_url:
        resolved_url = "http://127.0.0.1:9100"
        source = "default (localhost fallback)"

    # Validate URL structure
    parsed = urlparse(resolved_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(
            f"Invalid APEXEYE_MASTER_URL: '{resolved_url}'. "
            f"Expected format: http://<host>:<port> (e.g. http://10.177.134.109:9100)"
        )

    clean_url = resolved_url.rstrip("/")
    parsed_clean = urlparse(clean_url)
    target_host = parsed_clean.hostname or "127.0.0.1"
    target_port = parsed_clean.port or (443 if parsed_clean.scheme == "https" else 9100)

    details.final_master_url = clean_url
    details.final_source = source
    details.target_host = target_host
    details.target_port = target_port
    _last_resolution_details = details

    return clean_url, source, loaded_env_str, target_host, target_port


def _resolve_master_url() -> str:
    """Helper for backward compatibility."""
    url, _, _, _, _ = _resolve_master_configuration()
    return url


class ClientConfig:
    """Configuration for the APEXEYE Client agent."""

    APP_NAME = "APEXEYE Client"
    VERSION = "0.2.0"

    def __init__(self):
        self.reload()

    def reload(self):
        """Reload configuration from environment and .env files."""
        env_p = find_env_file()
        if env_p:
            self._PROJECT_ROOT = env_p.parent
        elif not getattr(self, "_PROJECT_ROOT", None):
            self._PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

        # Deterministic Device Identity Resolution:
        # 1. APEXEE_DEVICE_ID / APEXEYE_DEVICE_ID environment variable
        # 2. APEXEYE_CLIENT_ID environment variable
        # 3. Stored identity/credentials data if available
        # 4. socket.gethostname().lower()
        dev_id = os.getenv("APEXEE_DEVICE_ID") or os.getenv("APEXEYE_DEVICE_ID")
        if not dev_id:
            dev_id = os.getenv("APEXEYE_CLIENT_ID")
        if not dev_id:
            for cand_cred in (
                self._PROJECT_ROOT / "client" / ".credentials.json",
                self._PROJECT_ROOT / "client" / ".device_identity.json",
                Path(__file__).resolve().parent.parent.parent / "client" / ".credentials.json",
            ):
                if cand_cred.is_file():
                    try:
                        data = json.loads(cand_cred.read_text("utf-8"))
                        if data.get("device_id"):
                            dev_id = str(data["device_id"]).strip()
                            break
                    except Exception:
                        pass
        if not dev_id:
            try:
                h = socket.gethostname().strip().lower()
                dev_id = h if h else "windows-client"
            except Exception:
                dev_id = "windows-client"

        self.CLIENT_ID = dev_id

        url, src, env_path, host, port = _resolve_master_configuration()
        self.MASTER_URL = url
        self.source = src
        self.loaded_env_path = env_path
        self.target_host = host
        self.target_port = port

        # Resolution details
        details = get_last_resolution_details()
        self.env_discovered = details.env_discovered
        self.env_contains_master = details.env_contains_master
        self.parsed_master_url = details.parsed_master_url
        self.process_env_master_set = details.process_env_master_set
        self.lan_discovery_attempted = details.lan_discovery_attempted
        self.lan_discovery_result = details.lan_discovery_result
        self.hostname_discovery_result = details.hostname_discovery_result
        self.cache_discovery_result = details.cache_discovery_result

        # Legacy fields
        self.MASTER_ADDRESS = host
        self.MASTER_PORT = port

        # Logging
        self.LOG_PATH = os.getenv(
            "APEXEYE_CLIENT_LOG_PATH",
            str(self._PROJECT_ROOT / "logs"),
        )
        self.LOG_LEVEL = os.getenv("APEXEYE_CLIENT_LOG_LEVEL", "DEBUG")

        # Intervals
        self.HEARTBEAT_INTERVAL = int(
            os.getenv("APEXEYE_HEARTBEAT_INTERVAL_SECONDS", "3")
        )
        self.TELEMETRY_INTERVAL = int(
            os.getenv("APEXEYE_CLIENT_TELEMETRY_INTERVAL_SECONDS", "60")
        )
        self.EVENT_SCAN_INTERVAL = int(
            os.getenv("APEXEYE_EVENT_SCAN_INTERVAL_SECONDS", "5")
        )
        self.HOST_INFO_INTERVAL = int(
            os.getenv("APEXEYE_HOST_INFO_INTERVAL_SECONDS", "300")
        )

        # Retries
        self.MAX_RETRY_ATTEMPTS = int(
            os.getenv("APEXEYE_MAX_RETRY_ATTEMPTS", "3")
        )
        self.RETRY_BASE_DELAY = int(
            os.getenv("APEXEYE_RETRY_BASE_DELAY_SECONDS", "5")
        )

    def update_master(self, new_url: str, new_source: str = "LAN discovery") -> None:
        """Dynamically update active Master URL in memory (e.g. after rediscovery)."""
        clean_url = new_url.rstrip("/")
        parsed = urlparse(clean_url)
        self.MASTER_URL = clean_url
        self.source = new_source
        self.target_host = parsed.hostname or "127.0.0.1"
        self.target_port = parsed.port or (443 if parsed.scheme == "https" else 9100)
        self.MASTER_ADDRESS = self.target_host
        self.MASTER_PORT = self.target_port

    @property
    def master_url(self) -> str:
        return self.MASTER_URL

    @property
    def is_localhost_target(self) -> bool:
        return is_loopback_url(self.MASTER_URL)

    @property
    def client_root(self) -> Path:
        return self._PROJECT_ROOT

    @property
    def candidate_env_paths(self) -> List[Path]:
        return get_candidate_env_paths()


config = ClientConfig()
