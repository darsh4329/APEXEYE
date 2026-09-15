"""
APEXEYE — Network Connectivity & Health Endpoint Test Suite

Tests:
1. Master /api/health endpoint
2. Master host/port configurability and IP override (APEXEYE_ADVERTISE_IP / APEXEYE_MASTER_ADVERTISE_IP)
3. Client MASTER_URL resolution & precedence (env var > .env > legacy address > default)
4. Client .env discovery in diverse paths (CWD, client directory, APEXEYE_ENV_FILE, standalone extraction)
5. Configuration source and target host/port reporting
6. Prominent localhost detection and warning
7. Master LAN discovery filtering (192.168.56.1, 127.0.0.1, 169.254.x.x rejected)
8. Client pre-flight health check (MasterConnection.check_master_connectivity)
9. Client connection failure diagnostic formatting
10. Full pairing & authenticated communication over resolved MASTER_URL
11. Authentication security verification (invalid credentials rejected)
"""

import os
import sys
import tempfile
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure project root is on sys.path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.config import MasterConfig, config as master_config
from master.app.database import init_database
from master.app.api import create_app
from master.app.utils.network import is_virtual_or_link_local_ip, get_primary_lan_ip, format_network_banner
from client.app.config import _resolve_master_configuration, _resolve_master_url, find_env_file, is_loopback_url, ClientConfig
from client.app.communication import MasterConnection
from master.app.auth import AuthService
from master.app.services.device_service import DeviceService


class TestHealthEndpoint(unittest.TestCase):
    """Test Master /api/health endpoint functionality."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.flask_app = create_app()
        cls.flask_app.config["TESTING"] = True
        cls.client = cls.flask_app.test_client()

    def test_health_endpoint_success(self):
        """GET /api/health returns 200 with status=healthy and app metadata."""
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("app"), "APEXEYE Master")
        self.assertIn("version", data)
        self.assertIn("timestamp", data)
        self.assertIn("bind_address", data)

    def test_health_endpoint_no_auth_required(self):
        """GET /api/health is accessible without any X-Device-ID / X-Auth-Token headers."""
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)


class TestConfigResolutionAndDiscovery(unittest.TestCase):
    """Test Client configuration URL resolution, deterministic .env discovery, and precedence."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="apexeye_cfg_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_explicit_process_env_overrides_all(self):
        """Process environment variable APEXEYE_MASTER_URL takes highest precedence."""
        env_file = Path(self.temp_dir) / ".env"
        env_file.write_text("APEXEYE_MASTER_URL=http://192.168.1.50:9100\n", encoding="utf-8")

        with patch.dict(os.environ, {
            "APEXEYE_MASTER_URL": "http://10.177.134.109:9100",
            "APEXEYE_ENV_FILE": str(env_file),
            "APEXEYE_MASTER_ADDRESS": "127.0.0.1",
        }):
            url, src, path, host, port = _resolve_master_configuration()
            self.assertEqual(url, "http://10.177.134.109:9100")
            self.assertIn("environment (APEXEYE_MASTER_URL)", src)
            self.assertEqual(host, "10.177.134.109")
            self.assertEqual(port, 9100)

    def test_env_file_discovery_via_apexeye_env_file(self):
        """APEXEYE_ENV_FILE explicit path correctly loads .env."""
        env_file = Path(self.temp_dir) / "custom.env"
        env_file.write_text("APEXEYE_MASTER_URL=http://10.200.1.1:9100\n", encoding="utf-8")

        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env["APEXEYE_ENV_FILE"] = str(env_file)

        with patch.dict(os.environ, clean_env, clear=True):
            url, src, path, host, port = _resolve_master_configuration()
            self.assertEqual(url, "http://10.200.1.1:9100")
            self.assertIn(str(env_file), src)
            self.assertEqual(host, "10.200.1.1")
            self.assertEqual(port, 9100)

    def test_cwd_env_discovery(self):
        """Current working directory .env is discovered."""
        env_file = Path(self.temp_dir) / ".env"
        env_file.write_text("APEXEYE_MASTER_URL=http://172.16.0.10:9100\n", encoding="utf-8")

        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env.pop("APEXEYE_ENV_FILE", None)

        with patch("pathlib.Path.cwd", return_value=Path(self.temp_dir)):
            with patch.dict(os.environ, clean_env, clear=True):
                url, src, path, host, port = _resolve_master_configuration()
                self.assertEqual(url, "http://172.16.0.10:9100")
                self.assertIn(".env", src)
                self.assertEqual(host, "172.16.0.10")

    def test_legacy_address_fallback(self):
        """Legacy APEXEYE_MASTER_ADDRESS is used when APEXEYE_MASTER_URL is absent."""
        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_ENV_FILE", None)
        clean_env["APEXEYE_MASTER_ADDRESS"] = "192.168.1.200"
        clean_env["APEXEYE_MASTER_SERVER_PORT"] = "9300"

        with patch("client.app.config.find_env_file", return_value=None):
            with patch.dict(os.environ, clean_env, clear=True):
                url, src, path, host, port = _resolve_master_configuration()
                self.assertEqual(url, "http://192.168.1.200:9300")
                self.assertIn("APEXEYE_MASTER_ADDRESS", src)
                self.assertEqual(host, "192.168.1.200")
                self.assertEqual(port, 9300)

    def test_missing_env_produces_default_localhost(self):
        """When no env var and no .env exists, safe default localhost is used and reported."""
        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env.pop("APEXEYE_ENV_FILE", None)

        with patch("client.app.config.find_env_file", return_value=None):
            with patch.dict(os.environ, clean_env, clear=True):
                url, src, path, host, port = _resolve_master_configuration()
                self.assertEqual(url, "http://127.0.0.1:9100")
                self.assertIn("default (localhost", src)
                self.assertIsNone(path)
                self.assertEqual(host, "127.0.0.1")
                self.assertEqual(port, 9100)

    def test_trailing_slash_stripped(self):
        """Trailing slashes are cleanly stripped."""
        with patch.dict(os.environ, {
            "APEXEYE_MASTER_URL": "http://10.177.134.109:9100///",
        }):
            url = _resolve_master_url()
            self.assertEqual(url, "http://10.177.134.109:9100")

    def test_invalid_url_raises_error(self):
        """Invalid URL format in APEXEYE_MASTER_URL raises ValueError."""
        with patch.dict(os.environ, {
            "APEXEYE_MASTER_URL": "not_a_valid_url",
        }):
            with self.assertRaises(ValueError):
                _resolve_master_configuration()

    def test_is_loopback_url_detection(self):
        """Loopback detection identifies 127.0.0.1, localhost, ::1, 0.0.0.0."""
        self.assertTrue(is_loopback_url("http://127.0.0.1:9100"))
        self.assertTrue(is_loopback_url("http://localhost:9100"))
        self.assertTrue(is_loopback_url("http://::1:9100"))
        self.assertTrue(is_loopback_url("http://0.0.0.0:9100"))
        self.assertFalse(is_loopback_url("http://10.177.134.109:9100"))
        self.assertFalse(is_loopback_url("http://192.168.1.50:9100"))

    def test_nested_standalone_client_structure_discovery(self):
        """
        Reproduce exact physical failure scenario:
        Downloads/client/client/main.py
        Downloads/client/client/.env
        Invoked from outside working directory.
        """
        # Create nested structure: temp_dir/Downloads/client/client
        nested_client_dir = Path(self.temp_dir) / "Downloads" / "client" / "client"
        nested_client_dir.mkdir(parents=True, exist_ok=True)
        nested_main = nested_client_dir / "main.py"
        nested_main.write_text("# entrypoint\n", encoding="utf-8")
        nested_env = nested_client_dir / ".env"
        nested_env.write_text("APEXEYE_MASTER_URL=http://10.177.134.109:9100\n", encoding="utf-8")

        outside_cwd = Path(self.temp_dir) / "other_workdir"
        outside_cwd.mkdir(parents=True, exist_ok=True)

        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env.pop("APEXEYE_ENV_FILE", None)

        with patch("sys.argv", [str(nested_main)]):
            with patch("pathlib.Path.cwd", return_value=outside_cwd):
                with patch.dict(os.environ, clean_env, clear=True):
                    cfg = ClientConfig()
                    self.assertEqual(cfg.master_url, "http://10.177.134.109:9100")
                    self.assertFalse(cfg.is_localhost_target)
                    self.assertEqual(cfg.target_host, "10.177.134.109")
                    self.assertEqual(cfg.target_port, 9100)
                    self.assertIsNotNone(cfg.loaded_env_path)
                    self.assertEqual(Path(cfg.loaded_env_path).resolve(), nested_env.resolve())
                    self.assertIn(".env", cfg.source)

    def test_pure_python_env_parsing_without_dotenv(self):
        """Pure-Python parse_env_file handles quotes, comments, export prefixes properly."""
        from client.app.config import parse_env_file

        env_file = Path(self.temp_dir) / "test_pure.env"
        env_file.write_text(
            "# Comment line\n"
            "export APEXEYE_MASTER_URL=\"http://10.177.134.109:9100\" # inline comment\n"
            "APEXEYE_CLIENT_UI_PORT='9200'\n"
            "UNQUOTED_VAL=some_value\n"
            "EMPTY_VAL=\n",
            encoding="utf-8",
        )

        parsed = parse_env_file(env_file)
        self.assertEqual(parsed.get("APEXEYE_MASTER_URL"), "http://10.177.134.109:9100")
        self.assertEqual(parsed.get("APEXEYE_CLIENT_UI_PORT"), "9200")
        self.assertEqual(parsed.get("UNQUOTED_VAL"), "some_value")
        self.assertEqual(parsed.get("EMPTY_VAL"), "")



class TestMasterNetworkDiscoveryAndOverrides(unittest.TestCase):
    """Test Master network interface discovery, IP filtering, and advertise IP overrides."""

    def test_virtualbox_host_only_rejected(self):
        """192.168.56.x (VirtualBox default subnet) is rejected as virtual."""
        self.assertTrue(is_virtual_or_link_local_ip("192.168.56.1"))
        self.assertTrue(is_virtual_or_link_local_ip("192.168.56.100"))

    def test_link_local_rejected(self):
        """169.254.x.x (APIPA / link-local) is rejected."""
        self.assertTrue(is_virtual_or_link_local_ip("169.254.19.4"))
        self.assertTrue(is_virtual_or_link_local_ip("169.254.116.161"))

    def test_loopback_rejected(self):
        """127.0.0.1 is rejected from physical LAN candidates."""
        self.assertTrue(is_virtual_or_link_local_ip("127.0.0.1"))

    def test_physical_lan_accepted(self):
        """Real LAN IPs (10.x, 192.168.1.x, 172.16.x) are accepted."""
        self.assertFalse(is_virtual_or_link_local_ip("10.177.134.109"))
        self.assertFalse(is_virtual_or_link_local_ip("192.168.1.45"))
        self.assertFalse(is_virtual_or_link_local_ip("172.20.10.5"))

    def test_advertise_ip_override_apexeye_advertise_ip(self):
        """APEXEYE_ADVERTISE_IP explicitly overrides discovered IP."""
        with patch.dict(os.environ, {"APEXEYE_ADVERTISE_IP": "10.0.0.99"}):
            self.assertEqual(get_primary_lan_ip(), "10.0.0.99")

    def test_advertise_ip_override_apexeye_master_advertise_ip(self):
        """APEXEYE_MASTER_ADVERTISE_IP explicitly overrides discovered IP."""
        with patch.dict(os.environ, {"APEXEYE_MASTER_ADVERTISE_IP": "10.0.0.88", "APEXEYE_ADVERTISE_IP": ""}):
            self.assertEqual(get_primary_lan_ip(), "10.0.0.88")

    def test_master_network_banner_contents(self):
        """format_network_banner produces comprehensive diagnostic output."""
        banner = format_network_banner("0.0.0.0", 9100)
        self.assertIn("0.0.0.0:9100", banner)
        self.assertIn("http://127.0.0.1:9100", banner)
        self.assertIn("Client PC Configuration Guideline", banner)
        self.assertIn("APEXEYE_MASTER_URL", banner)


class TestMasterConnectionDiagnostics(unittest.TestCase):
    """Test MasterConnection health check, connectivity report, and diagnostic formatting."""

    def test_format_diagnostics_content(self):
        """Diagnostic string contains target URL, configuration source, possible causes, and troubleshooting."""
        conn = MasterConnection("http://192.168.1.88:9100")
        diag = conn.format_diagnostics("Connection refused")
        self.assertIn("192.168.1.88:9100", diag)
        self.assertIn("Configuration Source", diag)
        self.assertIn("Possible Causes:", diag)
        self.assertIn("Troubleshooting Steps:", diag)
        self.assertIn("curl http://192.168.1.88:9100/api/health", diag)
        self.assertIn("Windows Defender Firewall", diag)
        self.assertNotIn("secret", diag.lower())
        self.assertNotIn("token", diag.lower())

    def test_format_diagnostics_warns_on_localhost(self):
        """Diagnostic explicitly warns when pointing to localhost."""
        conn = MasterConnection("http://127.0.0.1:9100")
        diag = conn.format_diagnostics("Connection refused")
        self.assertIn("CRITICAL CONFIGURATION WARNING", diag)
        self.assertIn("127.0.0.1 means THIS CLIENT COMPUTER", diag)
        self.assertIn("APEXEYE_MASTER_URL=http://<MASTER-LAN-IP>:9100", diag)

    def test_check_master_connectivity_with_mock(self):
        """check_master_connectivity runs TCP and HTTP checks and returns structured report."""
        conn = MasterConnection("http://10.177.134.109:9100")
        with patch("socket.create_connection") as mock_sock:
            with patch.object(conn, "check_master_health") as mock_health:
                mock_health.return_value = (True, {"status": "healthy", "version": "0.1.0"})
                report = conn.check_master_connectivity()
                self.assertTrue(report["tcp_ok"])
                self.assertTrue(report["http_ok"])
                self.assertEqual(report["host"], "10.177.134.109")
                self.assertEqual(report["port"], 9100)
                self.assertFalse(report["is_loopback"])


class TestAuthenticationSecurityPreserved(unittest.TestCase):
    """Verify that authentication mechanisms remain fully functional and strict."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.flask_app = create_app()
        cls.flask_app.config["TESTING"] = True
        cls.client = cls.flask_app.test_client()
        cls.auth_svc = AuthService()
        cls.device_svc = DeviceService()

    def test_protected_endpoints_reject_unauthenticated(self):
        """Protected API endpoints return 401 when unauthenticated."""
        resp = self.client.post("/api/heartbeat", json={"status": "running"})
        self.assertEqual(resp.status_code, 401)

        resp = self.client.post("/api/telemetry", json={"cpu": {}})
        self.assertEqual(resp.status_code, 401)

    def test_full_registration_pairing_and_auth_workflow(self):
        """Client-initiated registration, pairing, and authenticated communication."""
        device_id = "test-net-device-001"

        reg_resp = self.client.post("/api/client/register", json={
            "device_id": device_id,
            "device_name": "Test Laptop",
            "device_type": "WINDOWS_PC",
            "operating_system": "Windows 11",
            "hostname": "test-laptop",
            "ip_address": "192.168.1.120",
        })
        self.assertEqual(reg_resp.status_code, 201)
        reg_data = reg_resp.get_json()
        token = reg_data["token"]

        # Authenticate with wrong token -> fails
        bad_auth = self.client.post(f"/api/devices/{device_id}/authenticate", json={
            "token": "wrong-token-value"
        })
        self.assertEqual(bad_auth.status_code, 401)

        # Authenticate with correct token -> succeeds
        good_auth = self.client.post(f"/api/devices/{device_id}/authenticate", json={
            "token": token
        })
        self.assertEqual(good_auth.status_code, 200)

        # Access protected endpoint with valid headers -> succeeds
        hb_resp = self.client.post(
            "/api/heartbeat",
            json={"device_id": device_id, "client_status": "running"},
            headers={
                "X-Device-ID": device_id,
                "X-Auth-Token": token,
            }
        )
        self.assertEqual(hb_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
