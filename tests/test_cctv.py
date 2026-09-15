"""
APEXEYE — Phase 4 CCTV Monitoring Test Suite

Tests:
1. CCTV device registration & field validation
2. Password obfuscation & API credential masking
3. CCTV CRUD operations, enable/disable, delete
4. TCP connectivity probing (success, refused, timeout, DNS failure)
5. RTSP availability probing (200 OK, 401 Auth, Basic auth, 404, invalid, timeout)
6. Combined probe_cctv status calculation (ONLINE, ONLINE_NETWORK, OFFLINE)
7. Telemetry recording & database updates
8. State transition detection & audit/event logging
9. Background Monitor Engine lifecycle & on-demand checks
10. CCTV REST API endpoints & error responses
11. Dashboard rendering with CCTV integration
"""

import json
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.config import config
from master.app.database import init_database, get_connection
from master.app.api import create_app
from master.app.services.cctv_service import (
    CCTVService,
    ValidationError,
    _obfuscate,
    _deobfuscate,
)
from master.app.services.cctv_prober import (
    check_tcp_connectivity,
    check_rtsp_availability,
    probe_cctv,
)
from master.app.services.cctv_monitor import CCTVMonitorEngine


class FakeRTSPServer:
    """Lightweight test TCP/RTSP server for testing network probes."""

    def __init__(self, mode="200_OK"):
        self.mode = mode
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind(("127.0.0.1", 0))
        self.port = self.server_sock.getsockname()[1]
        self.server_sock.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        self.server_sock.settimeout(0.5)
        while self._running:
            try:
                client, _ = self.server_sock.accept()
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_client(self, client: socket.socket):
        try:
            client.settimeout(2.0)
            req = client.recv(1024).decode("utf-8", errors="replace")

            if self.mode == "200_OK":
                resp = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, PLAY, SETUP, TEARDOWN\r\n\r\n"
                client.sendall(resp.encode("utf-8"))

            elif self.mode == "401_AUTH_REQUIRED":
                if "Authorization:" in req and "Basic YWRtaW46c2VjcmV0MTIz" in req:  # admin:secret123
                    resp = "RTSP/1.0 200 OK\r\nCSeq: 2\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
                else:
                    resp = "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"ApexEyeCamera\"\r\n\r\n"
                client.sendall(resp.encode("utf-8"))

            elif self.mode == "401_DIGEST_AUTH":
                if "Authorization: Digest" in req:
                    resp = "RTSP/1.0 200 OK\r\nCSeq: 2\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
                    client.sendall(resp.encode("utf-8"))
                else:
                    resp = 'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm="HikvisionCamera", nonce="4f8a12bc9d03"\r\n\r\n'
                    client.sendall(resp.encode("utf-8"))
                    req2 = client.recv(1024).decode("utf-8", errors="replace")
                    if "Authorization: Digest" in req2:
                        client.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n")

            elif self.mode == "401_DIGEST_QOP_AUTH":
                if "Authorization: Digest" in req and 'qop="auth"' in req and 'cnonce=' in req:
                    resp = "RTSP/1.0 200 OK\r\nCSeq: 2\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
                    client.sendall(resp.encode("utf-8"))
                else:
                    resp = 'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm="DahuaNVR", nonce="d89ef32a1", qop="auth", opaque="opq5581"\r\n\r\n'
                    client.sendall(resp.encode("utf-8"))
                    req2 = client.recv(1024).decode("utf-8", errors="replace")
                    if "Authorization: Digest" in req2 and 'qop="auth"' in req2:
                        client.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n")

            elif self.mode == "405_METHOD_NOT_ALLOWED":
                if "DESCRIBE" in req:
                    resp = "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\n"
                else:
                    resp = "RTSP/1.0 405 Method Not Allowed\r\nCSeq: 1\r\nAllow: DESCRIBE, SETUP, PLAY\r\n\r\n"
                client.sendall(resp.encode("utf-8"))
                if "OPTIONS" in req:
                    req2 = client.recv(1024).decode("utf-8", errors="replace")
                    if "DESCRIBE" in req2:
                        client.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n")

            elif self.mode == "403_FORBIDDEN":
                resp = "RTSP/1.0 403 Forbidden\r\nCSeq: 1\r\n\r\n"
                client.sendall(resp.encode("utf-8"))

            elif self.mode == "454_SESSION_NOT_FOUND":
                resp = "RTSP/1.0 454 Session Not Found\r\nCSeq: 1\r\n\r\n"
                client.sendall(resp.encode("utf-8"))

            elif self.mode == "404_NOT_FOUND":
                resp = "RTSP/1.0 404 Stream Not Found\r\nCSeq: 1\r\n\r\n"
                client.sendall(resp.encode("utf-8"))

            elif self.mode == "NON_RTSP_GARBAGE":
                client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

            elif self.mode == "HANG":
                time.sleep(1.0)
                client.close()

        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    def stop(self):
        self._running = False
        try:
            self.server_sock.close()
        except Exception:
            pass
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)


def _clean_cctv_tables():
    conn = get_connection()
    try:
        conn.execute("DELETE FROM cctv_telemetry;")
        conn.execute("DELETE FROM cctv_devices;")
        conn.commit()
    finally:
        conn.close()


class TestCCTVRegistrationAndValidation(unittest.TestCase):
    """Test CCTV registration, input validation, and password obfuscation."""

    def setUp(self):
        init_database()
        _clean_cctv_tables()
        self.service = CCTVService()

    def tearDown(self):
        _clean_cctv_tables()

    def test_register_valid_cctv(self):
        cctv = self.service.register_cctv({
            "cctv_id": "TEST-CCTV-01",
            "name": "Entrance Camera",
            "ip_address": "192.168.1.120",
            "port": 554,
            "rtsp_path": "/live/ch0",
            "location": "Main Entrance",
            "username": "admin",
            "password": "secretPassword123!",
        })
        self.assertEqual(cctv["cctv_id"], "TEST-CCTV-01")
        self.assertEqual(cctv["name"], "Entrance Camera")
        self.assertEqual(cctv["ip_address"], "192.168.1.120")
        self.assertEqual(cctv["port"], 554)
        self.assertEqual(cctv["rtsp_path"], "/live/ch0")
        self.assertEqual(cctv["rtsp_url"], "rtsp://192.168.1.120:554/live/ch0")
        self.assertEqual(cctv["location"], "Main Entrance")
        self.assertTrue(cctv["has_password"])
        # Crucial security check: password must NEVER be in unprivileged returned dict
        self.assertNotIn("password", cctv)
        self.assertNotIn("password_enc", cctv)

    def test_missing_cctv_id_raises(self):
        with self.assertRaises(ValidationError):
            self.service.register_cctv({"name": "Cam 1", "ip_address": "192.168.1.50"})

    def test_invalid_cctv_id_chars_raises(self):
        with self.assertRaises(ValidationError):
            self.service.register_cctv({"cctv_id": "Cam#1/bad", "name": "Cam 1", "ip_address": "192.168.1.50"})

    def test_missing_name_raises(self):
        with self.assertRaises(ValidationError):
            self.service.register_cctv({"cctv_id": "CAM-02", "name": "", "ip_address": "192.168.1.50"})

    def test_invalid_ip_raises(self):
        with self.assertRaises(ValidationError):
            self.service.register_cctv({"cctv_id": "CAM-03", "name": "Cam 3", "ip_address": "not_an_ip@_or_host!"})

    def test_invalid_port_raises(self):
        with self.assertRaises(ValidationError):
            self.service.register_cctv({"cctv_id": "CAM-04", "name": "Cam 4", "ip_address": "192.168.1.50", "port": 70000})

    def test_duplicate_cctv_id_raises(self):
        self.service.register_cctv({"cctv_id": "CAM-DUP", "name": "Cam Dup", "ip_address": "192.168.1.50"})
        with self.assertRaises(ValidationError):
            self.service.register_cctv({"cctv_id": "CAM-DUP", "name": "Cam Dup 2", "ip_address": "192.168.1.51"})

    def test_password_obfuscation(self):
        original = "SuperSecret_CCTV_Pass!#9"
        obfuscated = _obfuscate(original)
        self.assertNotEqual(original, obfuscated)
        self.assertNotIn(original, obfuscated)
        recovered = _deobfuscate(obfuscated)
        self.assertEqual(original, recovered)


class TestCCTVServicesAndDatabase(unittest.TestCase):
    """Test CRUD, telemetry storage, and summary metrics."""

    def setUp(self):
        init_database()
        _clean_cctv_tables()
        self.service = CCTVService()

    def tearDown(self):
        _clean_cctv_tables()

    def test_crud_lifecycle(self):
        cctv_id = "LIFECYCLE-CAM-01"
        self.service.register_cctv({
            "cctv_id": cctv_id,
            "name": "Warehouse",
            "ip_address": "10.0.0.100",
            "port": 554,
            "location": "Zone A",
        })

        # Get
        cctv = self.service.get_cctv(cctv_id)
        self.assertIsNotNone(cctv)
        self.assertEqual(cctv["name"], "Warehouse")

        # Update
        updated = self.service.update_cctv(cctv_id, {
            "name": "Warehouse North",
            "location": "Zone A North",
            "port": 8554,
        })
        self.assertEqual(updated["name"], "Warehouse North")
        self.assertEqual(updated["port"], 8554)
        self.assertEqual(updated["location"], "Zone A North")

        # Enable / Disable
        self.service.set_enabled(cctv_id, False)
        disabled_cam = self.service.get_cctv(cctv_id)
        self.assertFalse(disabled_cam["is_enabled"])

        self.service.set_enabled(cctv_id, True)
        enabled_cam = self.service.get_cctv(cctv_id)
        self.assertTrue(enabled_cam["is_enabled"])

        # Delete
        success = self.service.delete_cctv(cctv_id)
        self.assertTrue(success)
        self.assertIsNone(self.service.get_cctv(cctv_id))

    def test_store_telemetry_and_updates(self):
        cctv_id = "TEL-CAM-01"
        self.service.register_cctv({
            "cctv_id": cctv_id,
            "name": "Parking Lot",
            "ip_address": "192.168.1.200",
        })

        # Store Online telemetry
        self.service.store_telemetry(cctv_id, {
            "timestamp": "2026-08-25 10:00:00",
            "tcp_reachable": True,
            "tcp_response_time_ms": 12.5,
            "rtsp_reachable": True,
            "rtsp_response_time_ms": 25.0,
            "status": "ONLINE",
            "failure_reason": "Healthy",
            "details": {"test": True},
        })

        cam = self.service.get_cctv(cctv_id)
        self.assertEqual(cam["status"], "ONLINE")
        self.assertEqual(cam["consecutive_failures"], 0)
        self.assertEqual(cam["last_successful_check"], "2026-08-25 10:00:00")

        # Query recent telemetry
        records = self.service.get_recent_telemetry(cctv_id)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "ONLINE")
        self.assertEqual(records[0]["tcp_reachable"], 1)
        self.assertEqual(records[0]["rtsp_reachable"], 1)

    def test_get_summary(self):
        self.service.register_cctv({"cctv_id": "SUM-CAM-01", "name": "Cam 1", "ip_address": "192.168.1.1"})
        self.service.register_cctv({"cctv_id": "SUM-CAM-02", "name": "Cam 2", "ip_address": "192.168.1.2", "is_enabled": False})

        summary = self.service.get_summary()
        self.assertGreaterEqual(summary["total"], 2)
        self.assertGreaterEqual(summary["disabled"], 1)


class TestCCTVProber(unittest.TestCase):
    """Test TCP & RTSP network probing with fake socket servers and edge cases."""

    def test_tcp_connectivity_success(self):
        server = FakeRTSPServer(mode="200_OK")
        try:
            is_reachable, latency, error = check_tcp_connectivity("127.0.0.1", server.port, timeout=1.0)
            self.assertTrue(is_reachable)
            self.assertIsNotNone(latency)
            self.assertGreater(latency, 0)
            self.assertIsNone(error)
        finally:
            server.stop()

    def test_tcp_connectivity_refused(self):
        # Pick an unallocated port
        is_reachable, latency, error = check_tcp_connectivity("127.0.0.1", 59999, timeout=0.5)
        self.assertFalse(is_reachable)
        self.assertIsNone(latency)
        self.assertTrue(any(x in error for x in ("TCP_CONNECTION_REFUSED", "TCP_TIMEOUT", "TCP_UNREACHABLE")))

    def test_tcp_dns_failure(self):
        is_reachable, latency, error = check_tcp_connectivity("nonexistent.invalid.hostname.xyz", 554, timeout=0.5)
        self.assertFalse(is_reachable)
        self.assertIn("DNS_FAILURE", error)

    def test_rtsp_options_200_ok(self):
        server = FakeRTSPServer(mode="200_OK")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/stream1"
            is_avail, latency, status_code, msg = check_rtsp_availability("127.0.0.1", server.port, url, timeout=1.0)
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_AVAILABLE")
            self.assertIn("200", msg)
        finally:
            server.stop()

    def test_rtsp_401_with_valid_auth(self):
        server = FakeRTSPServer(mode="401_AUTH_REQUIRED")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/stream1"
            is_avail, latency, status_code, msg = check_rtsp_availability(
                "127.0.0.1", server.port, url, username="admin", password="secret123", timeout=1.0
            )
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_AVAILABLE")
        finally:
            server.stop()

    def test_rtsp_401_with_invalid_auth(self):
        server = FakeRTSPServer(mode="401_AUTH_REQUIRED")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/stream1"
            is_avail, latency, status_code, msg = check_rtsp_availability(
                "127.0.0.1", server.port, url, username="wronguser", password="badpassword", timeout=1.0
            )
            self.assertFalse(is_avail)
            self.assertEqual(status_code, "RTSP_AUTH_FAILED")
        finally:
            server.stop()

    def test_rtsp_digest_auth(self):
        server = FakeRTSPServer(mode="401_DIGEST_AUTH")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/Streaming/Channels/101"
            is_avail, latency, status_code, msg = check_rtsp_availability(
                "127.0.0.1", server.port, url, username="admin", password="hikvisionPassword", timeout=1.0
            )
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_AVAILABLE")
        finally:
            server.stop()

    def test_rtsp_digest_qop_auth(self):
        server = FakeRTSPServer(mode="401_DIGEST_QOP_AUTH")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/cam/realmonitor?channel=1&subtype=0"
            is_avail, latency, status_code, msg = check_rtsp_availability(
                "127.0.0.1", server.port, url, username="admin", password="dahuaPassword", timeout=1.0
            )
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_AVAILABLE")
        finally:
            server.stop()

    def test_rtsp_405_describe_fallback(self):
        server = FakeRTSPServer(mode="405_METHOD_NOT_ALLOWED")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/axis-media/media.amp"
            is_avail, latency, status_code, msg = check_rtsp_availability("127.0.0.1", server.port, url, timeout=1.0)
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_AVAILABLE")
        finally:
            server.stop()

    def test_rtsp_403_forbidden(self):
        server = FakeRTSPServer(mode="403_FORBIDDEN")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/secure_channel"
            is_avail, latency, status_code, msg = check_rtsp_availability("127.0.0.1", server.port, url, timeout=1.0)
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_FORBIDDEN")
        finally:
            server.stop()

    def test_rtsp_454_session_not_found(self):
        server = FakeRTSPServer(mode="454_SESSION_NOT_FOUND")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/stream1"
            is_avail, latency, status_code, msg = check_rtsp_availability("127.0.0.1", server.port, url, timeout=1.0)
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_AVAILABLE")
        finally:
            server.stop()

    def test_rtsp_401_without_creds(self):
        server = FakeRTSPServer(mode="401_AUTH_REQUIRED")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/stream1"
            is_avail, latency, status_code, msg = check_rtsp_availability("127.0.0.1", server.port, url, timeout=1.0)
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_AUTH_REQUIRED")
        finally:
            server.stop()

    def test_rtsp_404_stream_not_found(self):
        server = FakeRTSPServer(mode="404_NOT_FOUND")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/badpath"
            is_avail, latency, status_code, msg = check_rtsp_availability("127.0.0.1", server.port, url, timeout=1.0)
            self.assertTrue(is_avail)
            self.assertEqual(status_code, "RTSP_PATH_INVALID")
            self.assertIn("404", msg)
        finally:
            server.stop()

    def test_rtsp_non_rtsp_protocol(self):
        server = FakeRTSPServer(mode="NON_RTSP_GARBAGE")
        try:
            url = f"rtsp://127.0.0.1:{server.port}/live"
            is_avail, latency, status_code, msg = check_rtsp_availability("127.0.0.1", server.port, url, timeout=1.0)
            self.assertFalse(is_avail)
            self.assertEqual(status_code, "RTSP_INVALID_PROTOCOL")
        finally:
            server.stop()

    def test_probe_cctv_full_online_flow(self):
        server = FakeRTSPServer(mode="200_OK")
        try:
            record = {
                "cctv_id": "PROBE-01",
                "ip_address": "127.0.0.1",
                "port": server.port,
                "rtsp_path": "/stream1",
                "rtsp_url": f"rtsp://127.0.0.1:{server.port}/stream1",
            }
            tel = probe_cctv(record)
            self.assertEqual(tel["status"], "ONLINE")
            self.assertTrue(tel["tcp_reachable"])
            self.assertTrue(tel["rtsp_reachable"])
        finally:
            server.stop()

    def test_probe_cctv_offline_flow(self):
        record = {
            "cctv_id": "PROBE-OFFLINE",
            "ip_address": "127.0.0.1",
            "port": 59999,
        }
        tel = probe_cctv(record)
        self.assertEqual(tel["status"], "OFFLINE")
        self.assertFalse(tel["tcp_reachable"])
        self.assertFalse(tel["rtsp_reachable"])


class TestCCTVMonitorEngine(unittest.TestCase):
    """Test background CCTV monitor engine and transition logging."""

    def setUp(self):
        init_database()
        _clean_cctv_tables()
        self.service = CCTVService()
        self.engine = CCTVMonitorEngine(self.service)

    def tearDown(self):
        _clean_cctv_tables()

    def test_check_now_and_state_logging(self):
        server = FakeRTSPServer(mode="200_OK")
        try:
            cctv = self.service.register_cctv({
                "cctv_id": "MON-CAM-01",
                "name": "Lobby",
                "ip_address": "127.0.0.1",
                "port": server.port,
            })

            tel = self.engine.check_now("MON-CAM-01")
            self.assertIsNotNone(tel)
            self.assertEqual(tel["status"], "ONLINE")

            # Check DB updated
            cam = self.service.get_cctv("MON-CAM-01")
            self.assertEqual(cam["status"], "ONLINE")
        finally:
            server.stop()

    def test_state_transition_logging_to_db(self):
        cctv = self.service.register_cctv({
            "cctv_id": "TRANS-CAM-01",
            "name": "Dock",
            "ip_address": "127.0.0.1",
            "port": 554,
        })
        # Mock transition from ONLINE -> OFFLINE
        self.engine._last_known_status["TRANS-CAM-01"] = "ONLINE"
        mock_tel = {
            "cctv_id": "TRANS-CAM-01",
            "timestamp": "2026-08-25 10:15:00",
            "tcp_reachable": False,
            "rtsp_reachable": False,
            "status": "OFFLINE",
            "failure_reason": "TCP_TIMEOUT",
            "details": {},
        }
        self.engine._process_result(cctv, mock_tel)

        # Verify log entry created in logs table
        conn = get_connection()
        log_row = conn.execute(
            "SELECT * FROM logs WHERE event_type = 'cctv_status_change' ORDER BY id DESC LIMIT 1;"
        ).fetchone()
        conn.close()

        self.assertIsNotNone(log_row)
        self.assertIn("went OFFLINE", log_row["message"])
        self.assertEqual(log_row["source"], "cctv_monitor")


class TestCCTVAPI(unittest.TestCase):
    """Test Master CCTV REST API endpoints."""

    @classmethod
    def setUpClass(cls):
        init_database()
        _clean_cctv_tables()
        cls.flask_app = create_app()
        cls.flask_app.config["TESTING"] = True
        cls.client = cls.flask_app.test_client()

    def tearDown(self):
        _clean_cctv_tables()

    def test_cctv_api_crud_flow(self):
        cctv_id = "API-CAM-01"

        # 1. Register
        resp = self.client.post("/api/cctv", json={
            "cctv_id": cctv_id,
            "name": "Gate 1 Camera",
            "ip_address": "192.168.10.50",
            "port": 554,
            "location": "North Gate",
            "username": "security",
            "password": "GatePassSecret!",
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["cctv_id"], cctv_id)
        self.assertNotIn("password", data)

        # 2. List
        list_resp = self.client.get("/api/cctv")
        self.assertEqual(list_resp.status_code, 200)
        items = list_resp.get_json()
        self.assertTrue(any(x["cctv_id"] == cctv_id for x in items))

        # 3. Get Details
        get_resp = self.client.get(f"/api/cctv/{cctv_id}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.get_json()["location"], "North Gate")

        # 4. Summary
        sum_resp = self.client.get("/api/cctv/summary")
        self.assertEqual(sum_resp.status_code, 200)
        self.assertIn("total", sum_resp.get_json())

        # 5. Update
        put_resp = self.client.put(f"/api/cctv/{cctv_id}", json={
            "name": "Gate 1 Main Camera",
            "location": "North Gate Main",
        })
        self.assertEqual(put_resp.status_code, 200)
        self.assertEqual(put_resp.get_json()["name"], "Gate 1 Main Camera")

        # 6. Disable & Enable
        dis_resp = self.client.post(f"/api/cctv/{cctv_id}/disable")
        self.assertEqual(dis_resp.status_code, 200)
        self.assertFalse(dis_resp.get_json()["is_enabled"])

        en_resp = self.client.post(f"/api/cctv/{cctv_id}/enable")
        self.assertEqual(en_resp.status_code, 200)
        self.assertTrue(en_resp.get_json()["is_enabled"])

        # 7. Check Now
        check_resp = self.client.post(f"/api/cctv/{cctv_id}/check")
        self.assertEqual(check_resp.status_code, 200)
        self.assertIn("status", check_resp.get_json())

        # 8. Historical Telemetry
        tel_resp = self.client.get(f"/api/cctv/{cctv_id}/telemetry")
        self.assertEqual(tel_resp.status_code, 200)
        self.assertIsInstance(tel_resp.get_json(), list)

        # 9. Delete
        del_resp = self.client.delete(f"/api/cctv/{cctv_id}")
        self.assertEqual(del_resp.status_code, 200)

        # 10. Confirm 404
        get_404 = self.client.get(f"/api/cctv/{cctv_id}")
        self.assertEqual(get_404.status_code, 404)

    def test_dashboard_renders_cctv_section(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("CCTV & IP Camera Monitoring", html)
        self.assertIn("Register CCTV", html)


if __name__ == "__main__":
    unittest.main()
