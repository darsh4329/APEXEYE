"""
APEXEYE LINUX CLIENT — Communication Module (Phase 3)

HTTP communication with the Master API for the Linux Agent:
  - Authenticated requests (X-Device-ID, X-Auth-Token headers)
  - Telemetry, heartbeat, events, and host-info transmission
  - Pre-flight health check (GET /api/health)
  - Retry logic with exponential backoff
  - Small offline buffer for unsent data when Master is temporarily down
  - Graceful handling of Master unavailability with diagnostics
"""

import json
import time
import urllib.request
import urllib.error
from collections import deque
import socket
from urllib.parse import urlparse

from client_linux.app.config import config, is_loopback_url
from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.communication")

_MAX_BUFFER_SIZE = 50


class MasterConnection:
    """Manages HTTP communication with the APEXEYE Master from Linux Client."""

    def __init__(self, master_url: str):
        self.master_url = master_url.rstrip("/")
        self._device_id: str | None = None
        self._auth_token: str | None = None
        self._unauthorized_callback = None
        self._offline_buffer: deque[tuple[str, dict]] = deque(
            maxlen=_MAX_BUFFER_SIZE
        )

    # ── Auth Identity ───────────────────────────────────────────

    def set_identity(self, device_id: str | None, token: str | None) -> None:
        """Set or re-arm the authenticated identity for subsequent requests."""
        self._device_id = device_id
        self._auth_token = token
        if device_id and token:
            logger.info("Linux communication identity set for device %s", device_id)
        else:
            logger.info("Linux communication identity cleared.")

    def clear_identity(self) -> None:
        """
        Safely clear authenticated identity without destroying connection subsystem.
        Subsequent requests will not send device auth headers until re-armed with set_identity.
        """
        self._device_id = None
        self._auth_token = None
        logger.info("Linux communication identity cleared (session terminated).")

    def set_unauthorized_callback(self, callback) -> None:
        """Register a callback to be invoked when Master returns 401 Unauthorized."""
        self._unauthorized_callback = callback

    @property
    def is_authenticated(self) -> bool:
        return bool(self._device_id and self._auth_token)

    # ── Master Health & Diagnostics ──────────────────────────────

    def check_master_connectivity(self, tcp_timeout: float = 3.0) -> dict:
        """
        Perform a comprehensive pre-flight connectivity check from Linux client:
        1. Parse host and port from configured URL.
        2. Detect if configured to localhost / loopback.
        3. Test TCP socket connection to target host and port.
        4. Test HTTP GET /api/health endpoint.

        Returns:
            dict containing host, port, is_loopback, tcp_ok, http_ok, health_data, error.
        """
        parsed = urlparse(self.master_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 9100)
        is_loopback = is_loopback_url(self.master_url)

        report = {
            "master_url": self.master_url,
            "host": host,
            "port": port,
            "is_loopback": is_loopback,
            "tcp_ok": False,
            "http_ok": False,
            "health_data": {},
            "error": None,
        }

        # 1. Test TCP port connection
        try:
            with socket.create_connection((host, port), timeout=tcp_timeout):
                report["tcp_ok"] = True
        except Exception as exc:
            report["tcp_ok"] = False
            report["error"] = f"TCP port {port} unreachable on {host}: {exc}"

        # 2. Test HTTP GET /api/health
        is_healthy, health_data = self.check_master_health()
        report["http_ok"] = is_healthy
        report["health_data"] = health_data
        if is_healthy:
            report["error"] = None
        elif not report["error"]:
            report["error"] = health_data.get("error") or "HTTP health check failed"

        return report

    def check_master_health(self) -> tuple[bool, dict]:
        """
        Authoritative connectivity and health check against the Master API.
        Calls GET /api/health (unauthenticated).

        Returns:
            (is_healthy: bool, details: dict)
        """
        status, data = self._request("GET", "/api/health", authenticated=False)
        if status == 200 and data.get("status") == "healthy":
            return True, data
        return False, data

    def format_diagnostics(self, reason: str = "", details: dict | None = None) -> str:
        """
        Produce a clear, user-facing diagnostic block when connection fails.
        Does not expose tokens or secrets.
        """
        parsed = urlparse(self.master_url)
        host = parsed.hostname or config.target_host or "127.0.0.1"
        port = parsed.port or config.target_port or (443 if parsed.scheme == "https" else 9100)
        is_loopback = is_loopback_url(self.master_url)

        if details is None:
            details = {
                "host": host,
                "port": port,
                "is_loopback": is_loopback,
                "tcp_ok": False,
                "http_ok": False,
                "error": reason or "Master unreachable",
            }

        tcp_ok = details.get("tcp_ok", False)
        http_ok = details.get("http_ok", False)

        lines = [
            "=" * 60,
            "APEXEYE LINUX AGENT CONNECTIVITY DIAGNOSTIC",
            "=" * 60,
            f"Configured Master    : {self.master_url}",
            f"Configuration Source : {getattr(config, 'source', 'unknown')}",
            f"Loaded .env Path     : {getattr(config, 'loaded_env_path', None) or 'NONE'}",
            f"Target Host/Port     : {host}:{port}",
            f"TCP {port} Reachable    : {'PASS (Port Open)' if tcp_ok else 'FAIL (Port Closed / Blocked)'}",
            f"HTTP /api/health     : {'PASS (Healthy)' if http_ok else 'FAIL'}",
            f"Failure Reason       : {reason or details.get('error') or 'Master unreachable'}",
            "",
        ]

        if is_loopback:
            lines.extend([
                "=" * 60,
                "CRITICAL CONFIGURATION WARNING",
                "=" * 60,
                f"Master URL is currently:",
                f"{self.master_url}",
                "",
                "127.0.0.1 means THIS LINUX COMPUTER.",
                "It does NOT refer to the remote Master PC.",
                "",
                "For a two-PC LAN deployment configure:",
                "APEXEYE_MASTER_URL=http://<MASTER-LAN-IP>:9100",
                "",
                "Current expected physical Master:",
                "http://10.177.134.109:9100",
                "",
                f"Configuration Source:",
                f"{getattr(config, 'source', 'default (localhost)')}",
                "",
                f"Loaded .env:",
                f"{getattr(config, 'loaded_env_path', None) or 'NONE'}",
                "=" * 60,
                "",
            ])

        lines.extend([
            "Possible Causes:",
            "  1. Master server is not running on the Master PC.",
            "  2. Master server is bound only to localhost (127.0.0.1) instead of 0.0.0.0.",
            "  3. Host firewall on Master PC blocks inbound TCP 9100.",
            "  4. Master LAN IP changed (e.g. DHCP renewal or Wi-Fi reconnect).",
            "  5. Using VirtualBox Host-Only IP (192.168.56.1) instead of active Wi-Fi/Ethernet IP.",
            "  6. Client and Master are on different Wi-Fi networks / subnets without a VPN.",
            "",
            "Troubleshooting Steps:",
            "  Step 1: On Master PC, verify Master is running: python -m master.main",
            "  Step 2: On Master PC, find actual active LAN IPv4 address with ipconfig / ip addr",
            "  Step 3: On Master PC, verify inbound firewall rule allows TCP 9100",
            "  Step 4: On Linux client, test with curl:",
            f"          curl {self.master_url}/api/health",
            "  Step 5: Set APEXEYE_MASTER_URL=http://<MASTER-LAN-IP>:9100 in .env",
            "=" * 60,
        ])
        return "\n".join(lines)

    # ── Core HTTP ───────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        authenticated: bool = False,
        timeout: float = 15.0,
    ) -> tuple[int, dict]:
        """
        Make an HTTP request to the Master API.
        Returns (status_code, response_body_dict).
        """
        url = f"{self.master_url}{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        headers = {}
        if body:
            headers["Content-Type"] = "application/json"

        # Add authentication headers if requested
        if authenticated and self._device_id and self._auth_token:
            headers["X-Device-ID"] = self._device_id
            headers["X-Auth-Token"] = self._auth_token

        req = urllib.request.Request(
            url, data=body, method=method, headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                return resp.status, resp_data
        except urllib.error.HTTPError as exc:
            try:
                resp_data = json.loads(exc.read().decode("utf-8"))
            except Exception:
                resp_data = {"error": exc.reason}
            return exc.code, resp_data
        except urllib.error.URLError as exc:
            diag = self.format_diagnostics(str(exc.reason))
            logger.error("Connection to Master failed:\n%s", diag)
            return 0, {
                "error": f"Connection failed: {exc.reason}",
                "target_url": self.master_url,
                "diagnostic": diag,
            }
        except Exception as exc:
            logger.error("Unexpected communication error: %s", exc)
            return 0, {"error": str(exc)}

    # ── Master Endpoint & Rediscovery ────────────────────────────

    def set_master_url(self, new_url: str, source: str = "rediscovery") -> None:
        """Update the active Master URL on this connection and config."""
        self.master_url = new_url.rstrip("/")
        try:
            config.update_master(new_url, new_source=source)
        except Exception:
            pass
        logger.info("Linux Client active Master URL updated to %s", self.master_url)

    def attempt_rediscovery(self) -> bool:
        """
        Attempt to rediscover Master endpoint on the network when current endpoint fails.
        Preserves authentication credentials.
        Returns True if a valid Master is found and configured.
        """
        try:
            from client_linux.app.discovery import master_discoverer
            lan_res = master_discoverer.discover_via_udp_lan(timeout=1.5)
            if lan_res:
                url, src = lan_res
                if url != self.master_url:
                    logger.info("Master rediscovered at %s via %s", url, src)
                    self.set_master_url(url, source=src)
                    return True

            host_res = master_discoverer.discover_via_hostnames()
            if host_res:
                url, src = host_res
                if url != self.master_url:
                    logger.info("Master rediscovered at %s via %s", url, src)
                    self.set_master_url(url, source=src)
                    return True
        except Exception as exc:
            logger.debug("Rediscovery attempt encountered error: %s", exc)

        return False

    def _request_with_retry(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        authenticated: bool = True,
    ) -> tuple[int, dict]:
        """
        Make an HTTP request with exponential backoff retry on failure.
        Attempts automatic rediscovery if Master endpoint is unreachable.
        """
        max_retries = config.MAX_RETRY_ATTEMPTS
        base_delay = config.RETRY_BASE_DELAY

        for attempt in range(max_retries + 1):
            status, resp = self._request(method, path, data, authenticated)

            if status == 401 and authenticated:
                logger.warning(
                    "Master returned 401 Unauthorized for %s %s. Authentication revoked or invalid.",
                    method, path,
                )
                if self._unauthorized_callback:
                    try:
                        self._unauthorized_callback(resp)
                    except Exception as exc:
                        logger.error("Error invoking unauthorized callback: %s", exc)
                return status, resp

            if status != 0:
                return status, resp

            # Attempt automatic rediscovery
            if attempt == 0 or (attempt == 1):
                if self.attempt_rediscovery():
                    status, resp = self._request(method, path, data, authenticated)
                    if status != 0:
                        return status, resp

            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt), 60)
                logger.warning(
                    "Master unavailable at %s. Retry %d/%d in %ds \u2026",
                    self.master_url, attempt + 1, max_retries, delay,
                )
                time.sleep(delay)

        logger.error(
            "All %d retry attempts failed for %s %s",
            max_retries, method, path,
        )
        return 0, {"error": "Master unreachable after retries"}

    # ── Offline Buffer ──────────────────────────────────────────

    def _buffer_payload(self, path: str, payload: dict) -> None:
        """Buffer a failed payload for later retry."""
        if len(self._offline_buffer) >= _MAX_BUFFER_SIZE:
            logger.warning(
                "Offline buffer full (%d items). Oldest entry discarded.",
                _MAX_BUFFER_SIZE,
            )
        self._offline_buffer.append((path, payload))
        logger.info(
            "Buffered payload for %s (%d items in buffer)",
            path, len(self._offline_buffer),
        )

    def flush_buffer(self) -> None:
        """Attempt to send all buffered payloads to Master."""
        if not self._offline_buffer:
            return

        flushed = 0
        remaining = deque(maxlen=_MAX_BUFFER_SIZE)

        while self._offline_buffer:
            path, payload = self._offline_buffer.popleft()
            status, _ = self._request("POST", path, payload, authenticated=True)
            if status in (200, 201):
                flushed += 1
            elif status == 0:
                remaining.append((path, payload))
                remaining.extend(self._offline_buffer)
                self._offline_buffer = remaining
                logger.warning(
                    "Master went offline during buffer flush. %d sent, %d remaining.",
                    flushed, len(self._offline_buffer),
                )
                return
            else:
                logger.warning(
                    "Buffered payload for %s rejected (%d). Discarding.",
                    path, status,
                )
                flushed += 1

        if flushed:
            logger.info("Flushed %d buffered payload(s) to Master", flushed)

    def _send_with_buffer(self, path: str, payload: dict) -> bool:
        """Send a payload to Master with retry and offline buffering."""
        status, resp = self._request_with_retry("POST", path, payload)

        if status in (200, 201):
            self.flush_buffer()
            return True
        elif status == 0:
            self._buffer_payload(path, payload)
            return False
        else:
            logger.warning(
                "%s failed (%d): %s", path, status, resp.get("error", ""),
            )
            return False

    # ── Phase 1: Registration & Pairing ─────────────────────────

    def register_self(self, device_info: dict) -> tuple[int, dict]:
        """
        Client-initiated self-registration with the Master.
        POST /api/client/register
        """
        logger.info("Linux client requesting registration with Master at %s \u2026", self.master_url)
        return self._request("POST", "/api/client/register", device_info)

    def authenticate(self, device_id: str, token: str, device_info: dict | None = None) -> tuple[int, dict]:
        """
        Authenticate this device with a pairing token and optional device identity metadata.
        POST /api/devices/<device_id>/authenticate
        """
        logger.info("Authenticating Linux device %s with Master …", device_id)
        payload = {"token": token}
        if device_info:
            payload["device_info"] = device_info
            for k in ("device_name", "device_type", "operating_system", "hostname", "ip_address", "location"):
                if k in device_info and k not in payload:
                    payload[k] = device_info[k]
        return self._request(
            "POST",
            f"/api/devices/{device_id}/authenticate",
            payload,
        )

    def verify_identity(self, device_id: str) -> tuple[int, dict]:
        """
        Check if this device is still registered and paired.
        GET /api/devices/<device_id>/auth
        """
        return self._request("GET", f"/api/devices/{device_id}/auth")

    def get_device(self, device_id: str) -> tuple[int, dict]:
        """
        Get this device's record from the Master.
        GET /api/devices/<device_id>
        """
        return self._request("GET", f"/api/devices/{device_id}")

    # ── Phase 2/3: Telemetry ────────────────────────────────────

    def send_telemetry(self, payload: dict) -> bool:
        """
        Send telemetry data to Master.
        POST /api/telemetry
        """
        if not self.is_authenticated:
            logger.error("Cannot send telemetry: not authenticated")
            return False
        payload["device_id"] = self._device_id
        return self._send_with_buffer("/api/telemetry", payload)

    # ── Phase 2/3: Heartbeat ────────────────────────────────────

    def send_heartbeat(self, client_status: str = "running") -> bool:
        """
        Send a heartbeat to Master.
        POST /api/heartbeat
        """
        if not self.is_authenticated:
            logger.error("Cannot send heartbeat: not authenticated")
            return False

        from datetime import datetime, timezone
        payload = {
            "device_id": self._device_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "client_status": client_status,
        }
        status, resp = self._request_with_retry("POST", "/api/heartbeat", payload)
        if status in (200, 201):
            self.flush_buffer()
            return True
        logger.warning("Heartbeat failed (%d): %s", status, resp.get("error", ""))
        return False

    # ── Phase 2/3: Events ───────────────────────────────────────

    def send_events(self, events: list[dict]) -> bool:
        """
        Send process/application events to Master.
        POST /api/events
        """
        if not self.is_authenticated:
            logger.error("Cannot send events: not authenticated")
            return False
        if not events:
            return True
        payload = {
            "device_id": self._device_id,
            "events": events,
        }
        return self._send_with_buffer("/api/events", payload)

    # ── Phase 5: Centralized Logs & Activity ────────────────────

    def send_logs(self, logs: list[dict]) -> bool:
        """
        Send centralized log/activity events to Master.
        POST /api/logs
        """
        if not self.is_authenticated:
            logger.error("Cannot send logs: not authenticated")
            return False
        if not logs:
            return True
        payload = {
            "device_id": self._device_id,
            "logs": logs,
        }
        return self._send_with_buffer("/api/logs", payload)

    # ── Phase 2/3: Host Information ─────────────────────────────

    def send_host_info(self, host_info: dict) -> bool:
        """
        Send host/OS information to Master.
        POST /api/host-info
        """
        if not self.is_authenticated:
            logger.error("Cannot send host info: not authenticated")
            return False
        host_info["device_id"] = self._device_id
        return self._send_with_buffer("/api/host-info", host_info)

    # ── Firewall: Policy Sync ───────────────────────────────────────

    def get_firewall_policy(self) -> dict | None:
        """
        Retrieve the current firewall policy from Master.
        GET /api/firewall/policy
        """
        if not self.is_authenticated:
            return None
        status, resp = self._request("GET", "/api/firewall/policy", authenticated=True)
        if status == 200 and "version" in resp:
            return resp
        if status not in (0, 401):
            logger.warning("Firewall policy fetch failed (%d): %s", status, resp.get("error", ""))
        return None

    def report_firewall_status(
        self,
        enforcement_state: str,
        policy_version: int,
        error: str | None = None,
    ) -> bool:
        """
        Report this client's current firewall enforcement state to Master.
        POST /api/firewall/status
        """
        if not self.is_authenticated:
            return False
        payload = {
            "device_id": self._device_id,
            "enforcement_state": enforcement_state,
            "policy_version": policy_version,
        }
        if error:
            payload["error"] = error
        status, _ = self._request("POST", "/api/firewall/status", payload, authenticated=True)
        return status in (200, 201)

    def report_blocked_attempt(
        self,
        device_name: str,
        domain: str,
        url: str = "",
        platform: str = "Linux",
        policy_version: int = 0,
        destination_ip: str = "",
        metadata: dict | None = None,
    ) -> bool:
        """
        Report a blocked connection attempt to Master.
        POST /api/firewall/log
        """
        if not self.is_authenticated:
            return False
        payload = {
            "device_id": self._device_id,
            "device_name": device_name,
            "domain": domain,
            "url": url,
            "platform": platform,
            "policy_version": policy_version,
            "destination_ip": destination_ip,
        }
        if metadata:
            payload["metadata"] = metadata
        status, _ = self._request("POST", "/api/firewall/log", payload, authenticated=True)
        return status in (200, 201)

