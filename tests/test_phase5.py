"""
APEXEYE MASTER & CLIENT — Phase 5 Test Suite
Centralized Logging & Activity Monitoring
"""

import os
import sys
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from master.app.database import init_database, get_connection
from master.app.api import create_app
from master.app.services.device_service import DeviceService
from master.app.services.log_service import LogService, LogValidationError
from master.app.services.telemetry_service import TelemetryService
from master.app.auth import AuthService
from client.app.collectors.events import EventCollector as WindowsEventCollector, APPLICATION_TAXONOMY, IGNORED_SYSTEM_PROCESSES
from client_linux.app.collectors.events import EventCollector as LinuxEventCollector, LINUX_PROCESS_TAXONOMY
from client.app.communication import MasterConnection as WinMasterConnection
from client_linux.app.communication import MasterConnection as LinuxMasterConnection


class TestPhase5LogsDatabaseAndService(unittest.TestCase):
    """Test Master LogService and SQLite schema."""

    def setUp(self):
        init_database()
        self.log_svc = LogService()
        self.device_svc = DeviceService()
        self.conn = get_connection()
        # Clean test tables
        self.conn.execute("DELETE FROM logs;")
        self.conn.execute("DELETE FROM telemetry;")
        self.conn.execute("DELETE FROM device_auth;")
        self.conn.execute("DELETE FROM devices;")
        self.conn.commit()

        # Register test devices
        self.device_svc.register({
            "device_id": "LOG-PC-01",
            "device_name": "Office PC 1",
            "device_type": "WINDOWS_PC",
        })
        self.device_svc.register({
            "device_id": "LOG-SRV-02",
            "device_name": "Linux Web Server",
            "device_type": "LINUX_PC",
        })

    def tearDown(self):
        self.conn.close()

    def test_ingest_and_search_logs(self):
        entries = [
            {
                "timestamp": "2026-08-25 10:00:00",
                "severity": "INFO",
                "category": "APPLICATION",
                "event_type": "APPLICATION_STARTED",
                "application_name": "Microsoft Word",
                "message": "Microsoft Word opened",
            },
            {
                "timestamp": "2026-08-25 10:05:00",
                "severity": "INFO",
                "category": "APPLICATION",
                "event_type": "APPLICATION_ACTIVE",
                "application_name": "Microsoft Word",
                "message": "Microsoft Word became active",
            },
            {
                "timestamp": "2026-08-25 10:15:00",
                "severity": "WARNING",
                "category": "SYSTEM",
                "event_type": "MEMORY_WARNING",
                "message": "High RAM utilization: 92.5%",
            },
            {
                "timestamp": "2026-08-25 10:20:00",
                "severity": "ERROR",
                "category": "SECURITY",
                "event_type": "AUTHENTICATION_FAILED",
                "message": "Repeated failed login attempt",
            },
        ]
        stored = self.log_svc.ingest_logs("LOG-PC-01", entries)
        self.assertEqual(stored, 4)

        # 1. Search all
        res = self.log_svc.search_logs()
        self.assertEqual(res["total"], 4)
        self.assertEqual(len(res["logs"]), 4)

        # 2. Filter by device
        res_dev = self.log_svc.search_logs(device_id="LOG-PC-01")
        self.assertEqual(res_dev["total"], 4)

        # 3. Filter by severity
        res_warn = self.log_svc.search_logs(severity="WARNING")
        self.assertEqual(res_warn["total"], 1)
        self.assertEqual(res_warn["logs"][0]["event_type"], "MEMORY_WARNING")

        # 4. Filter by category
        res_app = self.log_svc.search_logs(category="APPLICATION")
        self.assertEqual(res_app["total"], 2)

        # 5. Filter by application name
        res_word = self.log_svc.search_logs(application_name="Word")
        self.assertEqual(res_word["total"], 2)

        # 6. Filter by keyword query
        res_q = self.log_svc.search_logs(query="login")
        self.assertEqual(res_q["total"], 1)
        self.assertEqual(res_q["logs"][0]["severity"], "ERROR")

        # 7. Filter by time range
        res_time = self.log_svc.search_logs(
            start_time="2026-08-25 10:04:00", end_time="2026-08-25 10:16:00"
        )
        self.assertEqual(res_time["total"], 2)

        # 8. Pagination
        res_page = self.log_svc.search_logs(limit=2, offset=0)
        self.assertEqual(len(res_page["logs"]), 2)
        self.assertEqual(res_page["total"], 4)

    def test_log_summary(self):
        self.log_svc.ingest_logs("LOG-PC-01", [
            {"severity": "INFO", "category": "APPLICATION", "application_name": "Google Chrome", "message": "Chrome active"},
            {"severity": "WARNING", "category": "SYSTEM", "message": "High CPU"},
            {"severity": "ERROR", "category": "NETWORK", "message": "Network timeout"},
        ])
        summary = self.log_svc.get_log_summary()
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["info"], 1)
        self.assertEqual(summary["warning"], 1)
        self.assertEqual(summary["error"], 1)
        self.assertIn("APPLICATION", summary["categories"])

    def test_batch_size_limit(self):
        oversized = [{"message": f"Log {i}"} for i in range(501)]
        with self.assertRaises(LogValidationError):
            self.log_svc.ingest_logs("LOG-PC-01", oversized)

    def test_persistence_across_restart(self):
        self.log_svc.ingest_logs("LOG-PC-01", [{"message": "Persistent event", "severity": "INFO"}])
        # Re-initialize DB
        init_database()
        res = self.log_svc.search_logs(query="Persistent event")
        self.assertEqual(res["total"], 1)


class TestPhase5RESTAPI(unittest.TestCase):
    """Test Master Phase 5 REST API Endpoints."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        self.device_svc = DeviceService()
        self.auth_svc = AuthService()
        conn = get_connection()
        conn.execute("DELETE FROM logs;")
        conn.execute("DELETE FROM telemetry;")
        conn.execute("DELETE FROM device_auth;")
        conn.execute("DELETE FROM devices;")
        conn.commit()
        conn.close()

        # Register & pair test device
        self.device_svc.register({"device_id": "API-PC-01", "device_name": "API PC", "device_type": "WINDOWS_PC"})
        pair_res = self.auth_svc.generate_pairing_credential("API-PC-01")
        self.token = pair_res["token"]
        self.auth_svc.authenticate_device("API-PC-01", self.token)

    def test_post_logs_authenticated_success(self):
        payload = {
            "logs": [
                {
                    "timestamp": "2026-08-25 11:00:00",
                    "severity": "INFO",
                    "category": "APPLICATION",
                    "event_type": "APPLICATION_STARTED",
                    "application_name": "VS Code",
                    "message": "Visual Studio Code opened",
                }
            ]
        }
        headers = {
            "X-Device-ID": "API-PC-01",
            "X-Auth-Token": self.token,
            "Content-Type": "application/json",
        }
        resp = self.client.post("/api/logs", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["stored"], 1)

    def test_post_logs_unauthenticated_rejected(self):
        payload = {"logs": [{"message": "Unauthenticated injection"}]}
        resp = self.client.post("/api/logs", json=payload)
        self.assertEqual(resp.status_code, 401)

        # Bad token
        headers = {"X-Device-ID": "API-PC-01", "X-Auth-Token": "bad_token"}
        resp = self.client.post("/api/logs", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_get_logs_search_and_filter(self):
        log_svc = LogService()
        log_svc.ingest_logs("API-PC-01", [
            {"severity": "INFO", "category": "APPLICATION", "application_name": "Slack", "message": "Slack opened"},
            {"severity": "ERROR", "category": "SYSTEM", "message": "Service crashed"},
        ])

        # Search without filter
        resp = self.client.get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["total"], 2)

        # Filter by severity
        resp_err = self.client.get("/api/logs?severity=ERROR")
        self.assertEqual(resp_err.status_code, 200)
        data = resp_err.get_json()
        self.assertEqual(data["total"], 1)
        self.assertIn("crashed", data["logs"][0]["message"])

        # Summary endpoint
        resp_sum = self.client.get("/api/logs/summary")
        self.assertEqual(resp_sum.status_code, 200)
        self.assertEqual(resp_sum.get_json()["total"], 2)

    def test_telemetry_threshold_warnings(self):
        headers = {
            "X-Device-ID": "API-PC-01",
            "X-Auth-Token": self.token,
            "Content-Type": "application/json",
        }
        # Send telemetry with 95% CPU, 91% RAM, 94% Disk
        high_telemetry = {
            "timestamp": "2026-08-25 11:30:00",
            "cpu": {"cpu_usage": 95.5},
            "memory": {"memory_usage_percent": 91.2, "memory_total_gb": 16.0, "memory_used_gb": 14.6},
            "disk": {"disk_usage_percent": 94.0, "disk_total_gb": 500.0, "disk_free_gb": 30.0},
            "network": {"network_bytes_sent_mb": 10.0, "network_bytes_recv_mb": 20.0},
        }
        resp = self.client.post("/api/telemetry", json=high_telemetry, headers=headers)
        self.assertEqual(resp.status_code, 201)

        # Verify automatic warnings in logs
        log_svc = LogService()
        warnings = log_svc.search_logs(severity="WARNING")
        self.assertEqual(warnings["total"], 3)  # CPU, Memory, Disk warnings generated

        # Check telemetry history API
        resp_hist = self.client.get("/api/telemetry/history?device_id=API-PC-01")
        self.assertEqual(resp_hist.status_code, 200)
        data = resp_hist.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["telemetry"][0]["cpu_usage"], 95.5)
        self.assertEqual(data["telemetry"][0]["memory_total_gb"], 16.0)


class TestPhase5WindowsAndLinuxCollectors(unittest.TestCase):
    """Test Application Taxonomy, Ignore Lists, and Active Window State Transitions."""

    def test_windows_application_taxonomy_and_ignore_list(self):
        self.assertIn("winword.exe", APPLICATION_TAXONOMY)
        self.assertIn("chrome.exe", APPLICATION_TAXONOMY)
        self.assertIn("code.exe", APPLICATION_TAXONOMY)

        # Ignore list verification
        self.assertIn("svchost.exe", IGNORED_SYSTEM_PROCESSES)
        self.assertIn("dwm.exe", IGNORED_SYSTEM_PROCESSES)
        self.assertIn("explorer.exe", IGNORED_SYSTEM_PROCESSES)

    def test_windows_event_collector_transitions(self):
        collector = WindowsEventCollector()

        # Simulate running processes snapshot
        with patch("psutil.process_iter") as mock_procs, patch("client.app.collectors.events._get_active_window_process_name", return_value="winword.exe"):
            mock_proc = MagicMock()
            mock_proc.info = {"pid": 4001, "name": "winword.exe"}
            mock_procs.return_value = [mock_proc]

            events = collector.collect()
            # Should detect started and active
            started = [e for e in events if e["event_type"] == "APPLICATION_STARTED"]
            active = [e for e in events if e["event_type"] == "APPLICATION_ACTIVE"]
            self.assertTrue(len(started) >= 1)
            self.assertEqual(started[0]["application_name"], "Microsoft Word")
            self.assertEqual(started[0]["category"], "PRODUCTIVITY")

            # Subsequent collection without state change -> active event suppressed
            events_next = collector.collect()
            active_next = [e for e in events_next if e["event_type"] == "APPLICATION_ACTIVE"]
            self.assertEqual(len(active_next), 0, "Duplicate active event must be suppressed")

    def test_linux_event_collector_taxonomy(self):
        self.assertIn("nginx", LINUX_PROCESS_TAXONOMY)
        self.assertIn("postgres", LINUX_PROCESS_TAXONOMY)
        self.assertIn("dockerd", LINUX_PROCESS_TAXONOMY)

        mock_nginx = MagicMock()
        mock_nginx.info = {"pid": 5001, "name": "nginx"}

        with patch("psutil.process_iter", return_value=[]):
            collector = LinuxEventCollector()

        with patch("psutil.process_iter", return_value=[mock_nginx]):
            events = collector.collect()
            started = [e for e in events if e["event_type"] == "APPLICATION_STARTED"]
            self.assertTrue(len(started) >= 1)
            self.assertEqual(started[0]["application_name"], "NGINX Web Server")
            self.assertEqual(started[0]["category"], "SYSTEM")


class TestPhase5AgentOfflineBuffer(unittest.TestCase):
    """Test Windows and Linux Agent Offline Buffering and Replay."""

    @patch("time.sleep", return_value=None)
    def test_windows_send_logs_offline_buffer(self, _mock_sleep):
        conn = WinMasterConnection("http://127.0.0.1:59999")
        conn.set_identity("BUFFER-PC", "dummy-token")

        # Mock connection failure (Master unreachable)
        with patch.object(conn, "_request", return_value=(0, {"error": "Connection refused"})):
            success = conn.send_logs([{"message": "Offline log 1"}])
            self.assertFalse(success)
            self.assertEqual(len(conn._offline_buffer), 1)

        # Mock connection restoration -> flush
        with patch.object(conn, "_request", return_value=(201, {"stored": 1})):
            conn.flush_buffer()
            self.assertEqual(len(conn._offline_buffer), 0)

    @patch("time.sleep", return_value=None)
    def test_linux_send_logs_offline_buffer(self, _mock_sleep):
        conn = LinuxMasterConnection("http://127.0.0.1:59999")
        conn.set_identity("BUFFER-LINUX", "dummy-token")

        with patch.object(conn, "_request", return_value=(0, {"error": "Connection refused"})):
            success = conn.send_logs([{"message": "Linux offline log"}])
            self.assertFalse(success)
            self.assertEqual(len(conn._offline_buffer), 1)

        with patch.object(conn, "_request", return_value=(201, {"stored": 1})):
            conn.flush_buffer()
            self.assertEqual(len(conn._offline_buffer), 0)


if __name__ == "__main__":
    unittest.main()
