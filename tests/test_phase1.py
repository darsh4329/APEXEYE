"""
APEXEYE — Phase 1 Test Suite

Tests:
  - Device registration / CRUD
  - Duplicate Device ID rejection
  - Validation
  - Pairing credential generation
  - Authentication with token
  - Revocation
  - Device status
  - Dashboard summary
  - REST API endpoints
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.services.device_service import DeviceService, ValidationError
from master.app.auth import AuthService
from master.app.api import create_app
from master.app.config import config

# Ensure we use the real config DB path (set by prior env or default)
_db_path = config.DB_PATH

# Make sure DB is initialized
init_database()


def _clean():
    """Remove all test data between tests."""
    conn = get_connection()
    conn.execute("DELETE FROM device_auth;")
    conn.execute("DELETE FROM devices;")
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════
# SERVICE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDeviceRegistration(unittest.TestCase):
    def setUp(self):
        _clean()
        self.svc = DeviceService()

    def test_register_device(self):
        d = self.svc.register({
            "device_id": "WIN-001",
            "device_name": "Office PC",
            "device_type": "WINDOWS_PC",
            "hostname": "DESKTOP-A1",
            "ip_address": "192.168.1.10",
        })
        self.assertEqual(d["device_id"], "WIN-001")
        self.assertEqual(d["status"], "pending")
        self.assertEqual(d["authentication_status"], "unauthenticated")

    def test_duplicate_device_id_rejected(self):
        self.svc.register({
            "device_id": "DUP-001",
            "device_name": "First",
            "device_type": "LINUX_PC",
        })
        with self.assertRaises(ValidationError):
            self.svc.register({
                "device_id": "DUP-001",
                "device_name": "Second",
                "device_type": "LINUX_PC",
            })

    def test_missing_device_id(self):
        with self.assertRaises(ValidationError):
            self.svc.register({"device_name": "X", "device_type": "CCTV"})

    def test_missing_device_name(self):
        with self.assertRaises(ValidationError):
            self.svc.register({"device_id": "X", "device_type": "CCTV"})

    def test_invalid_device_type(self):
        with self.assertRaises(ValidationError):
            self.svc.register({
                "device_id": "X", "device_name": "X", "device_type": "TOASTER"
            })

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValidationError):
            self.svc.register({
                "device_id": "X", "device_name": "X",
                "device_type": "WINDOWS_PC", "ip_address": "not-an-ip"
            })


class TestDeviceCRUD(unittest.TestCase):
    def setUp(self):
        _clean()
        self.svc = DeviceService()
        self.svc.register({
            "device_id": "CRUD-001",
            "device_name": "Test Device",
            "device_type": "WINDOWS_PC",
            "hostname": "HOST-1",
            "ip_address": "10.0.0.1",
            "location": "Lab A",
        })

    def test_get_device(self):
        d = self.svc.get_device("CRUD-001")
        self.assertIsNotNone(d)
        self.assertEqual(d["device_name"], "Test Device")

    def test_get_nonexistent(self):
        self.assertIsNone(self.svc.get_device("NOPE"))

    def test_list_devices(self):
        devices = self.svc.list_devices()
        self.assertEqual(len(devices), 1)

    def test_update_device(self):
        d = self.svc.update_device("CRUD-001", {"device_name": "Updated"})
        self.assertEqual(d["device_name"], "Updated")

    def test_update_nonexistent(self):
        self.assertIsNone(self.svc.update_device("NOPE", {"device_name": "X"}))

    def test_remove_device(self):
        self.assertTrue(self.svc.remove_device("CRUD-001"))
        self.assertIsNone(self.svc.get_device("CRUD-001"))

    def test_remove_nonexistent(self):
        self.assertFalse(self.svc.remove_device("NOPE"))


class TestDeviceStatus(unittest.TestCase):
    def setUp(self):
        _clean()
        self.svc = DeviceService()
        self.svc.register({
            "device_id": "STATUS-001",
            "device_name": "Status Test",
            "device_type": "LINUX_PC",
        })

    def test_update_status(self):
        self.svc.update_status("STATUS-001", "online")
        d = self.svc.get_device("STATUS-001")
        self.assertEqual(d["status"], "online")

    def test_invalid_status(self):
        with self.assertRaises(ValidationError):
            self.svc.update_status("STATUS-001", "EXPLODING")

    def test_update_last_seen(self):
        self.svc.update_last_seen("STATUS-001")
        d = self.svc.get_device("STATUS-001")
        self.assertIsNotNone(d["last_seen"])


class TestDashboardSummary(unittest.TestCase):
    def setUp(self):
        _clean()
        self.svc = DeviceService()

    def test_empty_summary(self):
        s = self.svc.get_summary()
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["online"], 0)

    def test_summary_counts(self):
        self.svc.register({"device_id": "S1", "device_name": "A", "device_type": "WINDOWS_PC"})
        self.svc.register({"device_id": "S2", "device_name": "B", "device_type": "LINUX_PC"})
        self.svc.update_status("S1", "online")
        s = self.svc.get_summary()
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["online"], 1)
        self.assertEqual(s["pending"], 1)


# ═══════════════════════════════════════════════════════════════════
# AUTH / PAIRING TESTS
# ═══════════════════════════════════════════════════════════════════

class TestPairingCredentials(unittest.TestCase):
    def setUp(self):
        _clean()
        self.svc = DeviceService()
        self.auth = AuthService()
        self.svc.register({
            "device_id": "AUTH-001",
            "device_name": "Auth Test",
            "device_type": "WINDOWS_PC",
        })

    def test_generate_credential(self):
        result = self.auth.generate_pairing_credential("AUTH-001")
        self.assertIn("token", result)
        self.assertEqual(result["status"], "pending")
        self.assertTrue(len(result["token"]) > 20)

    def test_generate_for_nonexistent_device(self):
        with self.assertRaises(ValueError):
            self.auth.generate_pairing_credential("NOPE")

    def test_authenticate_with_valid_token(self):
        result = self.auth.generate_pairing_credential("AUTH-001")
        token = result["token"]
        ok = self.auth.authenticate_device("AUTH-001", token)
        self.assertTrue(ok)
        d = self.svc.get_device("AUTH-001")
        self.assertEqual(d["authentication_status"], "paired")

    def test_authenticate_with_wrong_token(self):
        self.auth.generate_pairing_credential("AUTH-001")
        ok = self.auth.authenticate_device("AUTH-001", "wrong-token")
        self.assertFalse(ok)

    def test_revoke_credentials(self):
        self.auth.generate_pairing_credential("AUTH-001")
        revoked = self.auth.revoke_device("AUTH-001")
        self.assertTrue(revoked)
        d = self.svc.get_device("AUTH-001")
        self.assertEqual(d["authentication_status"], "unauthenticated")

    def test_auth_status(self):
        status = self.auth.get_auth_status("AUTH-001")
        self.assertEqual(status["status"], "no_credentials")
        self.auth.generate_pairing_credential("AUTH-001")
        status = self.auth.get_auth_status("AUTH-001")
        self.assertEqual(status["status"], "pending")

    def test_regenerate_revokes_old(self):
        r1 = self.auth.generate_pairing_credential("AUTH-001")
        r2 = self.auth.generate_pairing_credential("AUTH-001")
        # Old token should no longer work
        ok = self.auth.authenticate_device("AUTH-001", r1["token"])
        self.assertFalse(ok)
        # New token should work
        ok = self.auth.authenticate_device("AUTH-001", r2["token"])
        self.assertTrue(ok)


# ═══════════════════════════════════════════════════════════════════
# API TESTS
# ═══════════════════════════════════════════════════════════════════

class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        _clean()

    def _register(self, device_id="API-001", **kwargs):
        payload = {
            "device_id": device_id,
            "device_name": kwargs.get("device_name", "API Test"),
            "device_type": kwargs.get("device_type", "WINDOWS_PC"),
        }
        payload.update(kwargs)
        return self.client.post("/api/devices", json=payload)

    def test_register_and_list(self):
        res = self._register()
        self.assertEqual(res.status_code, 201)
        res = self.client.get("/api/devices")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(data), 1)

    def test_get_device(self):
        self._register()
        res = self.client.get("/api/devices/API-001")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["device_id"], "API-001")

    def test_get_device_not_found(self):
        res = self.client.get("/api/devices/NOPE")
        self.assertEqual(res.status_code, 404)

    def test_update_device(self):
        self._register()
        res = self.client.put("/api/devices/API-001", json={"device_name": "Renamed"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["device_name"], "Renamed")

    def test_delete_device(self):
        self._register()
        res = self.client.delete("/api/devices/API-001")
        self.assertEqual(res.status_code, 200)

    def test_duplicate_registration_400(self):
        self._register()
        res = self._register()
        self.assertEqual(res.status_code, 400)

    def test_validation_error_400(self):
        res = self.client.post("/api/devices", json={"device_id": "X"})
        self.assertEqual(res.status_code, 400)

    def test_summary(self):
        self._register()
        res = self.client.get("/api/devices/summary")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total"], 1)

    def test_pair_device(self):
        self._register()
        res = self.client.post("/api/devices/API-001/pair")
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertIn("token", data)

    def test_authenticate_device(self):
        self._register()
        pair_res = self.client.post("/api/devices/API-001/pair")
        token = pair_res.get_json()["token"]
        res = self.client.post("/api/devices/API-001/authenticate", json={"token": token})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "paired")

    def test_authenticate_bad_token(self):
        self._register()
        self.client.post("/api/devices/API-001/pair")
        res = self.client.post("/api/devices/API-001/authenticate", json={"token": "bad"})
        self.assertEqual(res.status_code, 401)

    def test_revoke(self):
        self._register()
        self.client.post("/api/devices/API-001/pair")
        res = self.client.post("/api/devices/API-001/revoke")
        self.assertEqual(res.status_code, 200)

    def test_auth_status(self):
        self._register()
        res = self.client.get("/api/devices/API-001/auth")
        self.assertEqual(res.status_code, 200)

    def test_dashboard_renders(self):
        self._register()
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"APEXEYE", res.data)
        self.assertIn(b"API-001", res.data)


if __name__ == "__main__":
    unittest.main()
