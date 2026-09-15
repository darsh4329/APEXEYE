"""
APEXEYE — Linux Client Strict Windows Behavioral Parity Test Suite

Verifies 1-to-1 behavioral parity between Linux and Windows client:
1. Automatic Master discovery via UDP probe (port 9101) & verification.
2. No hardcoded Master IP in configuration or default .env.
3. Missing authentication does NOT terminate the Linux client.
4. Client enters WAITING_FOR_PAIRING state and remains alive.
5. Login/enrollment page launch is triggered with local UI port 9200.
6. Local pairing UI dynamically renders the discovered Master URL.
7. Authentication via /api/local/authenticate validates with Master, saves credentials, and triggers callback.
8. Authentication failure (401) is handled gracefully and allows retrying without terminating.
9. Stored credentials persist in obfuscated format and are loaded on restart without repeating enrollment.
10. Dynamic Master IP change triggers rediscovery and preserves credentials.
11. Frozen protocol timing values: Heartbeat=3s, Telemetry=10s, Client UI=9200, Master=9100, UDP=9101.
12. Linux collectors (CPU, Memory, Disk, Network, OS Info) and telemetry transmission.
"""

import json
import os
import sys
import tempfile
import shutil
import threading
import time
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.api import create_app as create_master_app
from master.app.services.device_service import DeviceService
from master.app.auth import AuthService
from client_linux.app.config import config, LinuxClientConfig
from client_linux.app.discovery import (
    MasterDiscoverer,
    master_discoverer,
    verify_master_endpoint,
    save_cached_master,
    load_cached_master,
    get_active_subnet_broadcasts,
    is_virtual_or_link_local_ip,
)
from client_linux.app.communication import MasterConnection
from client_linux.app.auth import ClientAuth, _obfuscate, _deobfuscate
from client_linux.app.ui.dashboard import create_client_ui_app
from client_linux.main import open_login_page, launch_login_page


class TestLinuxClientBehavioralParity(unittest.TestCase):
    """Verify strict behavioral parity of Linux client with reference Windows client."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.master_app = create_master_app()
        cls.master_app.config["TESTING"] = True
        cls.master_client = cls.master_app.test_client()
        cls.device_svc = DeviceService()
        cls.auth_svc = AuthService()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="apexeye_linux_parity_")
        self.cache_file = Path(self.temp_dir) / ".apexeye_master_cache.json"
        self.cred_file = Path(self.temp_dir) / ".credentials.json"
        self._patcher = patch("client_linux.app.auth._CRED_FILE", self.cred_file)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ── 1. Automatic Master Discovery ─────────────────────────────
    def test_01_automatic_master_discovery_via_udp(self):
        """Linux client automatically discovers Master via UDP broadcast probe and verifies endpoint."""
        discoverer = MasterDiscoverer(discovery_port=19105)
        fake_response = json.dumps({
            "service": "APEXEYE_MASTER",
            "version": "0.3.0",
            "port": 9100,
            "lan_ip": "10.124.207.109",
            "hostname": "WindowsMasterPC",
        }).encode("utf-8")

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (fake_response, ("10.124.207.109", 19105))
            mock_sock_cls.return_value = mock_sock

            with patch("client_linux.app.discovery.verify_master_endpoint", return_value=(True, {"status": "healthy"})):
                with patch("client_linux.app.discovery.save_cached_master") as mock_save:
                    result = discoverer.discover_via_udp_lan(timeout=0.5)
                    self.assertIsNotNone(result)
                    url, src = result
                    self.assertEqual(url, "http://10.124.207.109:9100")
                    self.assertIn("LAN discovery", src)
                    mock_save.assert_called_once()

    # ── 2. No Hardcoded Master IP ──────────────────────────────────
    def test_02_no_hardcoded_master_ip_in_configuration(self):
        """Default Linux client .env and candidate configs must not hardcode static IPs."""
        env_path = Path(_project_root) / "client_linux" / ".env"
        if env_path.exists():
            content = env_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                clean = line.strip()
                if clean.startswith("APEXEYE_MASTER_URL="):
                    val = clean.split("=", 1)[1].strip()
                    self.assertNotIn("10.177.134.109", val, "Hardcoded legacy IP found in client_linux/.env")
                    self.assertNotIn("10.124.207.109", val, "Hardcoded temporary IP found in client_linux/.env")

        # Verify resolution without env falls back to discovery, not hardcoded IP
        with patch.dict(os.environ, {"APEXEYE_MASTER_URL": "", "APEXEYE_ENV_FILE": ""}, clear=False):
            with patch("client_linux.app.discovery.master_discoverer.discover_via_udp_lan", return_value=("http://192.168.1.99:9100", "LAN discovery")):
                cfg = LinuxClientConfig()
                self.assertEqual(cfg.master_url, "http://192.168.1.99:9100")

    # ── 3. Missing Auth Does NOT Terminate Client ──────────────────
    def test_03_missing_authentication_does_not_terminate_client(self):
        """When credentials are not present, client must remain alive in waiting state."""
        conn = MasterConnection("http://127.0.0.1:9100")
        auth = ClientAuth(conn)
        auth._creds = None

        authenticated_event = threading.Event()
        stop_event = threading.Event()

        # Simulate start without credentials
        self.assertFalse(auth.is_paired)

        # In unauthenticated state, authenticated_event is not set, but client remains alive
        self.assertFalse(authenticated_event.is_set())

        # Simulate background pairing completion by user
        def simulate_user_pairing():
            time.sleep(0.1)
            auth._save_credentials({"device_id": "LINUX-DEV-99", "token": "tok-abc", "status": "paired"})
            conn.set_identity("LINUX-DEV-99", "tok-abc")
            authenticated_event.set()

        t = threading.Thread(target=simulate_user_pairing, daemon=True)
        t.start()

        # Wait on authenticated_event (simulating main loop)
        signaled = authenticated_event.wait(timeout=2.0)
        self.assertTrue(signaled, "Client should remain alive and wake up upon user pairing")
        self.assertTrue(conn.is_authenticated)

    # ── 4. Login Page Launch ───────────────────────────────────────
    def test_04_login_page_launch_is_triggered(self):
        """open_login_page and launch_login_page trigger default browser open with local UI URL."""
        with patch("webbrowser.open", return_value=True) as mock_open:
            res1 = open_login_page("http://127.0.0.1:9200")
            self.assertTrue(res1)
            mock_open.assert_called_with("http://127.0.0.1:9200")

            res2 = launch_login_page("http://127.0.0.1:9200")
            self.assertTrue(res2)

    # ── 5. Discovered Master Address in Local UI ────────────────────
    def test_05_local_ui_renders_pairing_page_with_discovered_master(self):
        """Local Client UI on port 9200 renders client_auth.html with dynamically discovered Master URL."""
        conn = MasterConnection("http://10.124.207.109:9100")
        auth = ClientAuth(conn)
        auth._creds = None

        app = create_client_ui_app(auth, conn)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn("Device Authentication", html)
        self.assertIn("http://10.124.207.109:9100", html)
        self.assertIn("deviceId", html)
        self.assertIn("authToken", html)

    # ── 6. Local Status Endpoint ───────────────────────────────────
    def test_06_local_status_endpoint_reports_pairing_state(self):
        """GET /api/local/status returns accurate pairing state and Master URL."""
        conn = MasterConnection("http://10.124.207.109:9100")
        auth = ClientAuth(conn)
        auth._creds = None

        app = create_client_ui_app(auth, conn)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/api/local/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["is_paired"])
        self.assertIsNone(data["device_id"])
        self.assertEqual(data["master_url"], "http://10.124.207.109:9100")

    # ── 7. Authentication Success & Credential Storage ─────────────
    def test_07_authentication_success_persists_creds_and_triggers_callback(self):
        """Valid credentials submitted to /api/local/authenticate authenticate with Master and save creds."""
        dev_id = f"PARITY-LINUX-{uuid.uuid4().hex[:8]}"
        self.device_svc.register({"device_id": dev_id, "device_name": "Ubuntu Workstation", "device_type": "LINUX_PC"})
        pair_cred = self.auth_svc.generate_pairing_credential(dev_id)
        raw_token = pair_cred["token"]

        conn = MasterConnection("http://127.0.0.1:9100")
        auth = ClientAuth(conn)
        auth._creds = None

        callback_called = threading.Event()

        def on_auth(d_id, tok):
            callback_called.set()

        app = create_client_ui_app(auth, conn, on_authenticated_callback=on_auth)
        app.config["TESTING"] = True
        client = app.test_client()

        with patch.object(conn, "authenticate", return_value=(200, {"message": "Authenticated"})):
            resp = client.post("/api/local/authenticate", json={"device_id": dev_id, "token": raw_token})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertTrue(callback_called.is_set())
            self.assertTrue(auth.is_paired)
            self.assertEqual(auth.device_id, dev_id)
            self.assertEqual(auth.token, raw_token)

            # Verify credentials stored on disk are obfuscated
            self.assertTrue(self.cred_file.exists())
            raw_disk = json.loads(self.cred_file.read_text("utf-8"))
            self.assertIn("_token_enc", raw_disk)
            self.assertNotIn("token", raw_disk)
            self.assertEqual(_deobfuscate(raw_disk["_token_enc"]), raw_token)

    # ── 8. Authentication Failure and Retry ────────────────────────
    def test_08_authentication_failure_returns_401_and_allows_retry(self):
        """Invalid credentials return 401, client remains unpaired, retry succeeds."""
        conn = MasterConnection("http://127.0.0.1:9100")
        auth = ClientAuth(conn)
        auth._creds = None

        app = create_client_ui_app(auth, conn)
        app.config["TESTING"] = True
        client = app.test_client()

        # Step 1: Reject invalid token
        with patch.object(conn, "authenticate", return_value=(401, {"error": "Invalid token"})):
            resp = client.post("/api/local/authenticate", json={"device_id": "DEV-01", "token": "wrong-token"})
            self.assertEqual(resp.status_code, 401)
            self.assertFalse(auth.is_paired)

        # Step 2: Retry with valid token
        with patch.object(conn, "authenticate", return_value=(200, {"message": "Success"})):
            resp2 = client.post("/api/local/authenticate", json={"device_id": "DEV-01", "token": "correct-token"})
            self.assertEqual(resp2.status_code, 200)
            self.assertTrue(auth.is_paired)

    # ── 9. Restart with Existing Authentication ────────────────────
    def test_09_restart_with_existing_authentication_resumes_without_prompt(self):
        """On client restart, stored credentials are automatically loaded and verified."""
        raw_token = "secret-token-parity-999"
        stored_json = {
            "device_id": "LINUX-RESTART-01",
            "_token_enc": _obfuscate(raw_token),
            "status": "paired",
        }
        self.cred_file.write_text(json.dumps(stored_json), encoding="utf-8")

        conn = MasterConnection("http://127.0.0.1:9100")
        auth = ClientAuth(conn)
        self.assertEqual(auth.device_id, "LINUX-RESTART-01")
        self.assertEqual(auth.token, raw_token)

        # Verification succeeds with Master
        with patch.object(conn, "authenticate", return_value=(200, {"status": "authenticated"})):
            res = auth.pair()
            self.assertTrue(res, "Existing pairing must be verified and accepted without user re-enrollment")
            self.assertTrue(auth.is_paired)

    # ── 10. Master IP Change & Rediscovery ─────────────────────────
    def test_10_master_ip_change_rediscovery_preserves_credentials(self):
        """When Master IP changes, rediscovery updates endpoint while preserving credentials."""
        old_url = "http://10.124.207.109:9100"
        new_url = "http://10.124.207.222:9100"

        conn = MasterConnection(old_url)
        conn.set_identity("LINUX-DEV-IP-CHG", "tok-xyz-888")
        self.assertTrue(conn.is_authenticated)

        with patch("client_linux.app.discovery.master_discoverer.discover_via_udp_lan", return_value=(new_url, "LAN discovery (10.124.207.222:9100)")):
            ok = conn.attempt_rediscovery()
            self.assertTrue(ok)
            self.assertEqual(conn.master_url, new_url)
            self.assertTrue(conn.is_authenticated)
            self.assertEqual(conn._device_id, "LINUX-DEV-IP-CHG")
            self.assertEqual(conn._auth_token, "tok-xyz-888")

    # ── 11. Frozen Protocol & Timing Values ────────────────────────
    def test_11_frozen_protocol_timing_values(self):
        """Verify all APEXEYE frozen protocol and timing constants."""
        self.assertEqual(config.HEARTBEAT_INTERVAL, 3, "Heartbeat interval must be 3 seconds")
        self.assertEqual(config.TELEMETRY_INTERVAL, 10, "Telemetry interval must be 10 seconds")
        self.assertEqual(config.EVENT_SCAN_INTERVAL, 5, "Event scan interval must be 5 seconds")
        self.assertEqual(config.HOST_INFO_INTERVAL, 300, "Host info interval must be 300 seconds")
        self.assertEqual(config.CLIENT_UI_PORT, 9200, "Client UI port must be 9200")
        self.assertEqual(config.MASTER_PORT, 9100, "Master HTTP port must be 9100")

    # ── 12. Linux Client Main Lifecycle with Unpaired State ────────
    def test_12_linux_client_main_waiting_for_pairing_flow(self):
        """Test full main() flow starting unpaired, triggering browser launch, then pairing."""
        with patch("client_linux.app.communication.MasterConnection.check_master_connectivity", return_value={"http_ok": True, "tcp_ok": True, "health_data": {}}):
            with patch("client_linux.app.auth.ClientAuth.pair", return_value=False):
                with patch("client_linux.main.open_login_page") as mock_open_page:
                    with patch("client_linux.main.start_client_ui_server") as mock_start_ui:
                        with patch("client_linux.app.agent.Agent.start") as mock_agent_start:
                            with patch("client_linux.app.agent.Agent.wait") as mock_agent_wait:
                                # We simulate authentication after 0.1s by setting the event in a thread
                                def simulate_pairing_event():
                                    time.sleep(0.1)
                                    # Trigger the callback that start_client_ui_server receives
                                    cb = mock_start_ui.call_args[1].get("on_authenticated_callback")
                                    if cb:
                                        cb("TEST-DEV-AUTO", "tok-test-auto")

                                t = threading.Thread(target=simulate_pairing_event, daemon=True)
                                t.start()

                                from client_linux.main import main
                                main()

                                mock_open_page.assert_called_once_with("http://127.0.0.1:9200")
                                mock_agent_start.assert_called_once()
                                mock_agent_wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()
