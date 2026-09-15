"""
APEXEYE — Master / Client Boundary & Security Isolation Regression Suite

Mandatory permanent invariant tests:
1. Master Dashboard (GET /) is strictly restricted to localhost / loopback interfaces.
2. Remote LAN clients (192.168.x.x, 10.x.x.x, 172.16.x.x) receive 403 Forbidden on GET / and NEVER receive dashboard.html.
3. Master Administrative APIs (devices, pairing, revoke, summary, CCTV, log search, telemetry history) reject remote clients with 403 Forbidden.
4. Client Authentication (POST /api/devices/<id>/authenticate) succeeds only with valid Master-issued credentials and rejects invalid/revoked tokens with 401.
5. Device-scoped authorization: Authenticated client A can only access its own data; attempting to access device B's data returns 403 Forbidden.
6. Public endpoints (/api/health) are accessible to remote clients.
7. Client Dashboard (port 9200) contains zero Master administration features.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure project root is on sys.path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.api import create_app
from master.app.auth import AuthService
from master.app.services.device_service import DeviceService
from client.app.config import ClientConfig
from client.app.ui.dashboard import create_client_ui_app
from client.app.communication import MasterConnection
from client.app.auth import ClientAuth


class TestMasterClientBoundary(unittest.TestCase):
    """Rigorous boundary and authorization tests for Master and Client."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.flask_app = create_app()
        cls.flask_app.config["TESTING"] = True
        cls.auth_svc = AuthService()
        cls.device_svc = DeviceService()

    def setUp(self):
        """Clean tables before each test."""
        conn = get_connection()
        try:
            for table in ("telemetry_detail", "telemetry", "events",
                          "host_info", "logs", "device_auth", "devices",
                          "cctv_telemetry", "cctv_devices"):
                conn.execute(f"DELETE FROM {table};")
            conn.commit()
        finally:
            conn.close()

    # ── Helper for remote requests ───────────────────────────────
    def _remote_client(self, ip="192.168.1.50"):
        """Returns a test client simulating a remote LAN PC IP."""
        c = self.flask_app.test_client()
        c.environ_base["REMOTE_ADDR"] = ip
        return c

    def _local_client(self, ip="127.0.0.1"):
        """Returns a test client simulating Master localhost."""
        c = self.flask_app.test_client()
        c.environ_base["REMOTE_ADDR"] = ip
        return c


    # ═══════════════════════════════════════════════════════════════
    # 1. MASTER DASHBOARD ISOLATION (GET /)
    # ═══════════════════════════════════════════════════════════════

    def test_master_dashboard_allowed_from_ipv4_loopback(self):
        """Master host accessing GET / from 127.0.0.1 receives 200 OK and dashboard HTML."""
        client = self._local_client("127.0.0.1")
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"APEXEYE", resp.data)

    def test_master_dashboard_allowed_from_ipv6_loopback(self):
        """Master host accessing GET / from ::1 receives 200 OK and dashboard HTML."""
        client = self._local_client("::1")
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"APEXEYE", resp.data)

    def test_master_dashboard_blocked_from_lan_192_168(self):
        """Remote LAN client at 192.168.1.50 requesting GET / receives 403 Forbidden."""
        client = self._remote_client("192.168.1.50")
        resp = client.get("/")
        self.assertEqual(resp.status_code, 403)
        # CRITICAL: Must NEVER return dashboard.html or device data
        self.assertNotIn(b"<!DOCTYPE html>", resp.data)
        self.assertNotIn(b"dashboard.html", resp.data)
        data = resp.get_json()
        self.assertIn("Forbidden", data.get("error", ""))
        self.assertIn("no-store", resp.headers.get("Cache-Control", ""))

    def test_master_dashboard_blocked_from_lan_10_x(self):
        """Remote client at 10.242.0.109 requesting GET / receives 403 Forbidden."""
        client = self._remote_client("10.242.0.109")
        resp = client.get("/")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"<!DOCTYPE html>", resp.data)

    def test_master_dashboard_blocked_from_lan_172_16(self):
        """Remote client at 172.16.5.20 requesting GET / receives 403 Forbidden."""
        client = self._remote_client("172.16.5.20")
        resp = client.get("/")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"<!DOCTYPE html>", resp.data)

    # ═══════════════════════════════════════════════════════════════
    # 2. MASTER ADMINISTRATIVE ENDPOINTS PROTECTION
    # ═══════════════════════════════════════════════════════════════

    def test_remote_client_cannot_list_devices(self):
        """Remote client cannot list devices via GET /api/devices."""
        client = self._remote_client()
        resp = client.get("/api/devices")
        self.assertEqual(resp.status_code, 403)

    def test_remote_client_cannot_register_device(self):
        """Remote client cannot register arbitrary devices via POST /api/devices."""
        client = self._remote_client()
        resp = client.post("/api/devices", json={
            "device_id": "ROGUE-01",
            "device_name": "Rogue PC",
            "device_type": "WINDOWS_PC",
        })
        self.assertEqual(resp.status_code, 403)

    def test_remote_client_can_self_register(self):
        """Remote client can call POST /api/client/register for automated enrollment."""
        client = self._remote_client()
        resp = client.post("/api/client/register", json={
            "device_id": "ROGUE-02",
            "device_name": "Rogue PC",
            "device_type": "WINDOWS_PC",
        })
        self.assertEqual(resp.status_code, 201)
        self.assertIn("token", resp.get_json())

    def test_remote_client_cannot_generate_pairing_token(self):
        """Remote client cannot generate pairing tokens via POST /api/devices/<id>/pair."""
        # Setup device via master
        self.device_svc.register({"device_id": "DEV-01", "device_name": "Test PC", "device_type": "WINDOWS_PC"})
        
        client = self._remote_client()
        resp = client.post("/api/devices/DEV-01/pair")
        self.assertEqual(resp.status_code, 403)

    def test_remote_client_cannot_revoke_device(self):
        """Remote client cannot revoke credentials via POST /api/devices/<id>/revoke."""
        self.device_svc.register({"device_id": "DEV-01", "device_name": "Test PC", "device_type": "WINDOWS_PC"})
        client = self._remote_client()
        resp = client.post("/api/devices/DEV-01/revoke")
        self.assertEqual(resp.status_code, 403)

    def test_remote_client_cannot_get_device_summary(self):
        """Remote client cannot access administrative summary GET /api/devices/summary."""
        client = self._remote_client()
        resp = client.get("/api/devices/summary")
        self.assertEqual(resp.status_code, 403)

    def test_remote_client_cannot_access_cctv(self):
        """Remote client cannot access CCTV endpoints."""
        client = self._remote_client()
        self.assertEqual(client.get("/api/cctv").status_code, 403)
        self.assertEqual(client.post("/api/cctv", json={"name": "cam"}).status_code, 403)
        self.assertEqual(client.get("/api/cctv/summary").status_code, 403)

    def test_remote_client_cannot_search_all_logs(self):
        """Remote client cannot query Master log search GET /api/logs."""
        client = self._remote_client()
        resp = client.get("/api/logs")
        self.assertEqual(resp.status_code, 403)

    def test_remote_client_cannot_get_log_summary(self):
        """Remote client cannot query Master log summary GET /api/logs/summary."""
        client = self._remote_client()
        resp = client.get("/api/logs/summary")
        self.assertEqual(resp.status_code, 403)

    def test_remote_client_cannot_get_telemetry_history(self):
        """Remote client cannot query system-wide telemetry history GET /api/telemetry/history."""
        client = self._remote_client()
        resp = client.get("/api/telemetry/history")
        self.assertEqual(resp.status_code, 403)

    # ═══════════════════════════════════════════════════════════════
    # 3. PUBLIC & CLIENT AUTHENTICATION FLOW
    # ═══════════════════════════════════════════════════════════════

    def test_public_health_check_accessible_remotely(self):
        """Public health check GET /api/health is accessible without authentication from LAN."""
        client = self._remote_client()
        resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "healthy")

    def test_client_authentication_with_valid_token(self):
        """Client can authenticate with valid Master-issued Device ID + Token."""
        # 1. Master registers & pairs device
        device_id = "WIN-AUTH-01"
        self.device_svc.register({"device_id": device_id, "device_name": "Auth PC", "device_type": "WINDOWS_PC"})
        cred = self.auth_svc.generate_pairing_credential(device_id)
        token = cred["token"]

        # 2. Remote Client submits authentication
        client = self._remote_client()
        resp = client.post(f"/api/devices/{device_id}/authenticate", json={"token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json().get("status"), "paired")

    def test_client_authentication_with_invalid_token(self):
        """Authentication with wrong token returns 401 Unauthorized."""
        device_id = "WIN-AUTH-02"
        self.device_svc.register({"device_id": device_id, "device_name": "Auth PC", "device_type": "WINDOWS_PC"})
        self.auth_svc.generate_pairing_credential(device_id)

        client = self._remote_client()
        resp = client.post(f"/api/devices/{device_id}/authenticate", json={"token": "invalid-token-12345"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json().get("error"), "Authentication failed.")

    def test_client_authentication_with_nonexistent_device(self):
        """Authentication with unknown device ID returns 401 Unauthorized without leaking details."""
        client = self._remote_client()
        resp = client.post("/api/devices/NONEXISTENT-DEV/authenticate", json={"token": "some-token"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json().get("error"), "Authentication failed.")

    def test_client_authentication_with_revoked_device(self):
        """Authentication for a revoked device returns 401 Unauthorized."""
        device_id = "WIN-AUTH-REVOKED"
        self.device_svc.register({"device_id": device_id, "device_name": "Auth PC", "device_type": "WINDOWS_PC"})
        cred = self.auth_svc.generate_pairing_credential(device_id)
        token = cred["token"]
        
        # Revoke device
        self.auth_svc.revoke_device(device_id)

        client = self._remote_client()
        resp = client.post(f"/api/devices/{device_id}/authenticate", json={"token": token})
        self.assertEqual(resp.status_code, 401)

    # ═══════════════════════════════════════════════════════════════
    # 4. DEVICE-SCOPED ISOLATION & CROSS-DEVICE ACCESS PREVENTION
    # ═══════════════════════════════════════════════════════════════

    def test_authenticated_client_own_telemetry_allowed(self):
        """Authenticated client can post telemetry and access its own latest telemetry."""
        device_id = "WIN-SCOPED-01"
        self.device_svc.register({"device_id": device_id, "device_name": "Scoped PC", "device_type": "WINDOWS_PC"})
        cred = self.auth_svc.generate_pairing_credential(device_id)
        token = cred["token"]
        self.auth_svc.authenticate_device(device_id, token)

        client = self._remote_client()
        headers = {"X-Device-ID": device_id, "X-Auth-Token": token}

        # POST telemetry -> 201
        resp = client.post("/api/telemetry", json={
            "device_id": device_id,
            "cpu": {"cpu_usage": 35.0},
            "memory": {"memory_usage_percent": 50.0},
            "disk": {"disk_usage_percent": 40.0},
            "network": {"network_bytes_sent_mb": 1.0, "network_bytes_recv_mb": 2.0},
        }, headers=headers)
        self.assertEqual(resp.status_code, 201)

        # GET own latest telemetry -> 200
        get_resp = client.get(f"/api/telemetry/latest/{device_id}", headers=headers)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.get_json().get("device_id"), device_id)

    def test_cross_device_data_access_blocked(self):
        """Client A cannot access Client B's latest telemetry or activity."""
        # Setup Device A
        dev_a = "DEVICE-ALPHA"
        self.device_svc.register({"device_id": dev_a, "device_name": "Alpha", "device_type": "WINDOWS_PC"})
        cred_a = self.auth_svc.generate_pairing_credential(dev_a)
        token_a = cred_a["token"]
        self.auth_svc.authenticate_device(dev_a, token_a)

        # Setup Device B
        dev_b = "DEVICE-BETA"
        self.device_svc.register({"device_id": dev_b, "device_name": "Beta", "device_type": "WINDOWS_PC"})
        cred_b = self.auth_svc.generate_pairing_credential(dev_b)
        token_b = cred_b["token"]
        self.auth_svc.authenticate_device(dev_b, token_b)

        client = self._remote_client()
        headers_a = {"X-Device-ID": dev_a, "X-Auth-Token": token_a}

        # Device A attempts to query Device B's telemetry -> 403 Forbidden
        resp = client.get(f"/api/telemetry/latest/{dev_b}", headers=headers_a)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Cannot access data belonging to another device", resp.get_json().get("error", ""))

        # Device A attempts to query Device B's activity -> 403 Forbidden
        resp_act = client.get(f"/api/logs/activity/{dev_b}", headers=headers_a)
        self.assertEqual(resp_act.status_code, 403)

        # Device A attempts to query Device B's metadata -> 403 Forbidden
        resp_dev = client.get(f"/api/devices/{dev_b}", headers=headers_a)
        self.assertEqual(resp_dev.status_code, 403)

    # ═══════════════════════════════════════════════════════════════
    # 5. CLIENT DASHBOARD ISOLATION (PORT 9200)
    # ═══════════════════════════════════════════════════════════════

    def test_client_ui_unauthenticated_shows_auth_screen(self):
        """When unauthenticated, Client local UI serves Client Authentication Screen."""
        conn = MasterConnection("http://127.0.0.1:9100")
        auth = ClientAuth(conn)
        auth._clear_credentials()

        ui_app = create_client_ui_app(auth, conn)
        client = ui_app.test_client()

        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"APEXEYE CLIENT", resp.data)
        self.assertIn(b"Device Authentication", resp.data)
        self.assertIn(b"Authenticate & Connect", resp.data)
        # MUST NOT contain Master dashboard elements
        self.assertNotIn(b"Register Device", resp.data)
        self.assertNotIn(b"CCTV Management", resp.data)

    def test_client_ui_authenticated_shows_client_dashboard(self):
        """When authenticated, Client local UI serves dedicated Client Dashboard."""
        conn = MasterConnection("http://127.0.0.1:9100")
        auth = ClientAuth(conn)
        auth._creds = {"device_id": "CLIENT-PC-01", "token": "mock-token", "status": "paired"}

        ui_app = create_client_ui_app(auth, conn)
        client = ui_app.test_client()

        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"ApexEye Client Dashboard", resp.data)
        self.assertIn(b"CLIENT-PC-01", resp.data)
        self.assertIn(b"CPU Utilization", resp.data)
        self.assertIn(b"AUTHENTICATED / ONLINE", resp.data)
        # MUST NOT contain Master administration features
        self.assertNotIn(b"Register Device", resp.data)
        self.assertNotIn(b"Generate Pairing Token", resp.data)
        self.assertNotIn(b"CCTV Camera", resp.data)
        self.assertNotIn(b"All Devices", resp.data)

    # ═══════════════════════════════════════════════════════════════
    # 6. NETWORK DISCOVERY & CLIENT DIAGNOSTICS TESTS
    # ═══════════════════════════════════════════════════════════════

    def test_unauthenticated_telemetry_rejected(self):
        """Telemetry submitted without valid device authentication headers is rejected with 401."""
        client = self._remote_client()
        resp = client.post("/api/telemetry", json={
            "device_id": "UNAUTH-DEV",
            "cpu": {"cpu_usage": 10.0},
        })
        self.assertEqual(resp.status_code, 401)

    def test_master_network_discovery_ignores_virtual_and_link_local(self):
        """Network discovery correctly filters out loopback, VirtualBox host-only (192.168.56.x), and link-local (169.254.x.x)."""
        from master.app.utils.network import is_virtual_or_link_local_ip, get_primary_lan_ip

        # Virtual / Link-local / Loopback must be flagged as True
        self.assertTrue(is_virtual_or_link_local_ip("127.0.0.1"))
        self.assertTrue(is_virtual_or_link_local_ip("169.254.19.4"))
        self.assertTrue(is_virtual_or_link_local_ip("192.168.56.1"))
        self.assertTrue(is_virtual_or_link_local_ip("192.168.56.100"))

        # Real LAN IPs must NOT be flagged as virtual
        self.assertFalse(is_virtual_or_link_local_ip("192.168.1.50"))
        self.assertFalse(is_virtual_or_link_local_ip("10.177.134.109"))
        self.assertFalse(is_virtual_or_link_local_ip("172.20.10.5"))

        primary_ip = get_primary_lan_ip()
        self.assertIsNotNone(primary_ip)
        self.assertNotEqual(primary_ip, "192.168.56.1")

    def test_master_network_banner_generation(self):
        """Master network banner clearly includes listener, local admin URL, and client guidance."""
        from master.app.utils.network import format_network_banner
        banner = format_network_banner("0.0.0.0", 9100)
        self.assertIn("0.0.0.0:9100", banner)
        self.assertIn("http://127.0.0.1:9100", banner)
        self.assertIn("Client PC Configuration Guideline", banner)
        self.assertIn("APEXEYE_MASTER_URL", banner)

    def test_client_loopback_url_detection(self):
        """Client accurately detects when APEXEYE_MASTER_URL points to localhost vs LAN IP."""
        from client.app.config import is_loopback_url

        self.assertTrue(is_loopback_url("http://127.0.0.1:9100"))
        self.assertTrue(is_loopback_url("http://localhost:9100"))
        self.assertTrue(is_loopback_url("http://::1:9100"))
        self.assertTrue(is_loopback_url("http://0.0.0.0:9100"))

        self.assertFalse(is_loopback_url("http://192.168.1.45:9100"))
        self.assertFalse(is_loopback_url("http://10.177.134.109:9100"))
        self.assertFalse(is_loopback_url("http://master.local:9100"))

    def test_client_diagnostics_formatting_warns_on_localhost(self):
        """Diagnostics output clearly flags 127.0.0.1 as a multi-PC configuration error."""
        conn = MasterConnection("http://127.0.0.1:9100")
        diag = conn.format_diagnostics(reason="Connection refused")
        self.assertIn("CRITICAL CONFIGURATION WARNING", diag)
        self.assertIn("127.0.0.1 means THIS CLIENT COMPUTER", diag)
        self.assertIn("APEXEYE_MASTER_URL=http://<MASTER-LAN-IP>:9100", diag)
        self.assertIn("TCP 9100", diag)
        self.assertIn("HTTP /api/health", diag)

    def test_standalone_extraction_directory_resolution(self):
        """Standalone client extracted to nested folder resolves Master LAN IP from .env without relying on CWD."""
        import os
        import tempfile
        import shutil

        temp_dir = tempfile.mkdtemp(prefix="apexeye_standalone_")
        try:
            # Recreate Downloads/client/client structure
            install_dir = Path(temp_dir) / "Downloads" / "client" / "client"
            install_dir.mkdir(parents=True, exist_ok=True)
            main_script = install_dir / "main.py"
            main_script.write_text("# main\n", encoding="utf-8")
            env_file = install_dir / ".env"
            env_file.write_text("APEXEYE_MASTER_URL=http://10.177.134.109:9100\n", encoding="utf-8")

            clean_env = dict(os.environ)
            clean_env.pop("APEXEYE_MASTER_URL", None)
            clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
            clean_env.pop("APEXEYE_ENV_FILE", None)

            # Invoke as if running python C:\Users\prade\Downloads\client\client\main.py from C:\
            with patch("sys.argv", [str(main_script)]):
                with patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                    with patch.dict(os.environ, clean_env, clear=True):
                        cfg = ClientConfig()
                        self.assertEqual(cfg.master_url, "http://10.177.134.109:9100")
                        self.assertFalse(cfg.is_localhost_target)
                        self.assertEqual(cfg.target_host, "10.177.134.109")
                        self.assertEqual(cfg.target_port, 9100)
                        self.assertIn(".env", cfg.source)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

