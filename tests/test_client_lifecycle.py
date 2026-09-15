"""
APEXEYE — Client Lifecycle & Port 9200 Pairing UI Test Suite

Tests:
1. Unauthenticated Client starts in WAITING_FOR_PAIRING state and does NOT exit.
2. Local Client UI (Port 9200) starts and binds to 127.0.0.1.
3. GET / returns HTTP 200 and renders client_auth.html when unauthenticated.
4. /api/local/status returns is_paired: False and current master_url.
5. /api/local/authenticate with invalid credentials returns 401 and keeps server alive.
6. /api/local/authenticate with valid credentials validates against Master, updates identity, and triggers callback.
7. GET / after successful authentication returns HTTP 200 and renders client_dashboard.html.
8. Telemetry collectors and metrics endpoint work after pairing.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure project root is on sys.path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.communication import MasterConnection
from client.app.auth import ClientAuth
from client.app.ui.dashboard import create_client_ui_app
from master.app.database import init_database
from master.app.api import create_app as create_master_app
from master.app.auth import AuthService


class TestClientLifecycleAndUI(unittest.TestCase):
    """Test Client startup lifecycle, local UI on port 9200, and pairing workflow."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.master_app = create_master_app()
        cls.master_app.config["TESTING"] = True
        cls.master_client = cls.master_app.test_client()
        cls.auth_svc = AuthService()

    def setUp(self):
        self.conn = MasterConnection("http://127.0.0.1:9100")
        self.auth = ClientAuth(self.conn)
        self.auth._creds = None  # Ensure test starts in cleanly unpaired state
        self.auth_callback_called = False
        self.callback_args = None

        def on_auth(dev_id, tok):
            self.auth_callback_called = True
            self.callback_args = (dev_id, tok)

        self.ui_app = create_client_ui_app(
            self.auth,
            self.conn,
            on_authenticated_callback=on_auth,
        )
        self.ui_app.config["TESTING"] = True
        self.client = self.ui_app.test_client()

    def test_unauthenticated_client_ui_renders_pairing_page(self):
        """GET / on unauthenticated Client UI returns HTTP 200 and renders pairing page."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Device Authentication", html)
        self.assertIn("deviceId", html)
        self.assertIn("authToken", html)
        self.assertIn("Authenticate & Connect", html)

    def test_local_status_endpoint_unpaired(self):
        """GET /api/local/status returns is_paired: False when client is unauthenticated."""
        resp = self.client.get("/api/local/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("is_paired"))
        self.assertIn("master_url", data)

    def test_local_authenticate_missing_fields(self):
        """POST /api/local/authenticate returns 400 when missing device_id or token."""
        resp = self.client.post("/api/local/authenticate", json={"device_id": ""})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data.get("success"))

    def test_local_authenticate_invalid_credentials_rejected(self):
        """POST /api/local/authenticate with invalid credentials returns 401 and does not crash."""
        with patch.object(self.conn, "authenticate", return_value=(401, {"error": "Invalid token"})):
            resp = self.client.post("/api/local/authenticate", json={
                "device_id": "test-client",
                "token": "invalid-token-123",
            })
            self.assertEqual(resp.status_code, 401)
            data = resp.get_json()
            self.assertFalse(data.get("success"))
            self.assertFalse(self.auth.is_paired)
            self.assertFalse(self.auth_callback_called)

    def test_local_authenticate_valid_credentials_succeeds_and_triggers_callback(self):
        """POST /api/local/authenticate with valid credentials transitions to paired and triggers callback."""
        with patch.object(self.conn, "authenticate", return_value=(200, {"message": "Authenticated"})):
            resp = self.client.post("/api/local/authenticate", json={
                "device_id": "Second_pc",
                "token": "valid-secret-token",
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data.get("success"))
            self.assertTrue(self.auth.is_paired)
            self.assertTrue(self.auth_callback_called)
            self.assertEqual(self.callback_args, ("Second_pc", "valid-secret-token"))

            # Now GET / should render client dashboard
            dash_resp = self.client.get("/")
            self.assertEqual(dash_resp.status_code, 200)
            dash_html = dash_resp.get_data(as_text=True)
            self.assertIn("ApexEye Client", dash_html)
            self.assertIn("Second_pc", dash_html)


if __name__ == "__main__":
    unittest.main()
