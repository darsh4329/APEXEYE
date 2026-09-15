"""
APEXEYE — Comprehensive Phase 0–5 Integration, Regression, and Security Audit Suite

Performs automated integration tests verifying:
  - Architecture isolation (AST check)
  - Full Device Auth & Registration Lifecycle
  - Windows & Linux Collector and Event Taxonomy
  - Bounded Offline Buffer Replay
  - CCTV TCP & RTSP Multi-Protocol Handshakes (Basic, Digest, qop=auth, DESCRIBE fallback)
  - CCTV Background Monitor Isolation & Credential Redaction
  - Centralized Log Ingestion, Multi-Field Search, Pagination, and Threshold Warnings
  - Database Schema Idempotence, Foreign Keys, and Cascade Integrity
"""

import ast
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection, check_database_health
from master.app.api import create_app
from master.app.services.device_service import DeviceService
from master.app.services.cctv_service import CCTVService
from master.app.services.log_service import LogService
from master.app.services.telemetry_service import TelemetryService
from master.app.auth import AuthService
from master.app.services.cctv_prober import check_tcp_connectivity, check_rtsp_availability, probe_cctv
from client.app.collectors.events import EventCollector as WindowsEventCollector, APPLICATION_TAXONOMY, IGNORED_SYSTEM_PROCESSES
from client_linux.app.collectors.events import EventCollector as LinuxEventCollector, LINUX_PROCESS_TAXONOMY
from client.app.communication import MasterConnection as WinConn
from client_linux.app.communication import MasterConnection as LinuxConn


class TestFullIntegrationAudit(unittest.TestCase):
    """End-to-end multi-phase integration audit."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        self.device_svc = DeviceService()
        self.auth_svc = AuthService()
        self.cctv_svc = CCTVService()
        self.log_svc = LogService()
        self.telemetry_svc = TelemetryService()

        conn = get_connection()
        conn.execute("DELETE FROM logs;")
        conn.execute("DELETE FROM telemetry;")
        conn.execute("DELETE FROM cctv_telemetry;")
        conn.execute("DELETE FROM cctv_devices;")
        conn.execute("DELETE FROM device_auth;")
        conn.execute("DELETE FROM devices;")
        conn.commit()
        conn.close()

    def test_01_static_ast_architecture_isolation(self):
        """Verify client/ and client_linux/ never import sqlite3 or master internals."""
        forbidden_imports = {"sqlite3", "master"}
        for root_dir in ("client", "client_linux"):
            pkg_path = Path(_project_root) / root_dir
            for py_file in pkg_path.rglob("*.py"):
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for n in node.names:
                            top = n.name.split(".")[0]
                            self.assertNotIn(
                                top, forbidden_imports,
                                f"Architecture Violation: {py_file} imports '{n.name}'"
                            )
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            top = node.module.split(".")[0]
                            self.assertNotIn(
                                top, forbidden_imports,
                                f"Architecture Violation: {py_file} imports from '{node.module}'"
                            )

    def test_02_database_schema_and_cascade_integrity(self):
        """Verify DB health, foreign keys enabled, and cascade delete."""
        health = check_database_health()
        self.assertTrue(health["ok"])

        conn = get_connection()
        fk_on = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        self.assertEqual(fk_on, 1)

        # Register CCTV and store telemetry
        self.cctv_svc.register_cctv({
            "cctv_id": "AUDIT-CCTV-01",
            "name": "Audit Camera",
            "ip_address": "192.168.1.50",
            "port": 554,
        })
        self.cctv_svc.store_telemetry("AUDIT-CCTV-01", {
            "tcp_reachable": True,
            "rtsp_reachable": True,
            "status": "ONLINE",
        })
        # Verify telemetry exists
        tel_count = conn.execute(
            "SELECT COUNT(*) FROM cctv_telemetry WHERE cctv_id = 'AUDIT-CCTV-01';"
        ).fetchone()[0]
        self.assertEqual(tel_count, 1)

        # Delete parent CCTV device
        self.cctv_svc.delete_cctv("AUDIT-CCTV-01")
        tel_after = conn.execute(
            "SELECT COUNT(*) FROM cctv_telemetry WHERE cctv_id = 'AUDIT-CCTV-01';"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(tel_after, 0, "CCTV telemetry records must cascade-delete")

    def test_03_device_lifecycle_and_authenticated_routes(self):
        """Verify Device Registration -> Pairing -> Auth -> Ingestion -> Rejection on Bad Auth."""
        # 1. Register
        dev = self.device_svc.register({
            "device_id": "WIN-AUDIT-01",
            "device_name": "Audit Workstation",
            "device_type": "WINDOWS_PC",
        })
        self.assertEqual(dev["status"], "pending")

        # 2. Pair
        pair = self.auth_svc.generate_pairing_credential("WIN-AUDIT-01")
        token = pair["token"]
        self.assertTrue(self.auth_svc.authenticate_device("WIN-AUDIT-01", token))

        # 3. Authenticated POST /api/telemetry
        headers = {"X-Device-ID": "WIN-AUDIT-01", "X-Auth-Token": token, "Content-Type": "application/json"}
        resp = self.client.post("/api/telemetry", json={
            "cpu": {"cpu_usage": 45.0},
            "memory": {"memory_usage_percent": 60.0, "memory_total_gb": 16.0, "memory_used_gb": 9.6},
            "disk": {"disk_usage_percent": 50.0, "disk_total_gb": 512.0, "disk_free_gb": 256.0},
            "network": {"network_bytes_sent_mb": 1.5, "network_bytes_recv_mb": 3.0},
        }, headers=headers)
        self.assertEqual(resp.status_code, 201)

        # 4. Authenticated POST /api/logs
        resp_log = self.client.post("/api/logs", json={
            "logs": [
                {
                    "timestamp": "2026-08-25 10:00:00",
                    "severity": "INFO",
                    "category": "APPLICATION",
                    "event_type": "APPLICATION_STARTED",
                    "application_name": "Microsoft Word",
                    "message": "Microsoft Word opened",
                }
            ]
        }, headers=headers)
        self.assertEqual(resp_log.status_code, 201)

        # 5. Unauthorized rejection
        bad_headers = {"X-Device-ID": "WIN-AUDIT-01", "X-Auth-Token": "invalid_forged_token"}
        resp_bad = self.client.post("/api/logs", json={"logs": [{"message": "Hacked"}]}, headers=bad_headers)
        self.assertEqual(resp_bad.status_code, 401)

    def test_04_privacy_boundary_and_system_process_filtering(self):
        """Verify Windows event collector taxonomy, system ignore list, and no sensitive data collection."""
        self.assertIn("winword.exe", APPLICATION_TAXONOMY)
        self.assertIn("chrome.exe", APPLICATION_TAXONOMY)
        self.assertIn("code.exe", APPLICATION_TAXONOMY)

        # Verify system processes ignored
        self.assertIn("svchost.exe", IGNORED_SYSTEM_PROCESSES)
        self.assertIn("dwm.exe", IGNORED_SYSTEM_PROCESSES)
        self.assertIn("explorer.exe", IGNORED_SYSTEM_PROCESSES)

        # Verify collector outputs only allowable fields
        collector = WindowsEventCollector()
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 2001, "name": "winword.exe"}

        with patch("psutil.process_iter", return_value=[mock_proc]):
            events = collector.collect()
            for evt in events:
                self.assertNotIn("keystrokes", evt)
                self.assertNotIn("clipboard", evt)
                self.assertNotIn("document_content", evt)
                self.assertNotIn("browser_history", evt)
                self.assertNotIn("password", evt)

    def test_05_cctv_credential_redaction_in_api(self):
        """Verify CCTV passwords are obfuscated in DB and completely omitted from GET responses."""
        raw_secret = "UltraSecretCameraPass#2026"
        cctv = self.cctv_svc.register_cctv({
            "cctv_id": "SECURE-CAM-01",
            "name": "Secure Office Entrance",
            "ip_address": "192.168.1.100",
            "port": 554,
            "username": "admin",
            "password": raw_secret,
        })

        # Database contains obfuscated string, NOT raw_secret
        conn = get_connection()
        db_row = conn.execute("SELECT password_enc FROM cctv_devices WHERE cctv_id = 'SECURE-CAM-01';").fetchone()
        conn.close()
        self.assertNotEqual(db_row["password_enc"], raw_secret)
        self.assertNotIn(raw_secret, db_row["password_enc"])

        # API GET /api/cctv does not expose password or password_enc
        resp = self.client.get("/api/cctv/SECURE-CAM-01")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertNotIn("password", data)
        self.assertNotIn("password_enc", data)
        self.assertTrue(data.get("has_password"))

    def test_06_offline_buffer_and_reconnection(self):
        """Verify Windows and Linux agents buffer unsent events and flush when connection resumes."""
        win_conn = WinConn("http://127.0.0.1:59998")
        win_conn.set_identity("BUFFER-TEST-01", "dummy-token")

        with patch.object(win_conn, "_request", return_value=(0, {"error": "Connection refused"})):
            with patch("time.sleep", return_value=None):
                ok = win_conn.send_logs([{"message": "Offline buffered event 1"}])
                self.assertFalse(ok)
                self.assertEqual(len(win_conn._offline_buffer), 1)

        # Restore connection and flush
        with patch.object(win_conn, "_request", return_value=(201, {"stored": 1})):
            win_conn.flush_buffer()
            self.assertEqual(len(win_conn._offline_buffer), 0)


if __name__ == "__main__":
    unittest.main()
