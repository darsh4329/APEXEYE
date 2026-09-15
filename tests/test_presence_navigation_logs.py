"""
APEXEYE — Comprehensive Presence, Navigation, and Telemetry/Log Cleanup Test Suite

Validates:
1. Online status on heartbeat/telemetry receipt
2. Automatic OFFLINE transition on heartbeat timeout (without deleting records)
3. Automatic ONLINE recovery when client reconnects and sends heartbeat
4. Preservation of last_seen, pairing, device identity, telemetry history
5. Online and Offline device listing with latest/last-known telemetry
6. Per-client log and telemetry data isolation (Client A does not leak into Client B)
7. Client-side multi-process event deduplication (single event per application launch)
8. Master-side idempotent log/event ingestion (safe against transmission retries)
9. Preservation of legitimate repeated events across different timestamps
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.api import create_app
from master.app.services.device_service import DeviceService
from master.app.services.heartbeat_service import HeartbeatService
from master.app.services.telemetry_service import TelemetryService
from master.app.services.event_service import EventService
from master.app.services.log_service import LogService
from master.app.services.presence_service import PresenceMonitorEngine
from master.app.auth import AuthService
from client.app.collectors.events import EventCollector as WinEventCollector


class TestPresenceNavigationAndLogs(unittest.TestCase):
    """Integration test suite for presence, dashboard navigation, and log cleanup."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        self.device_svc = DeviceService()
        self.heartbeat_svc = HeartbeatService()
        self.telemetry_svc = TelemetryService()
        self.event_svc = EventService()
        self.log_svc = LogService()
        self.auth_svc = AuthService()

        conn = get_connection()
        conn.execute("DELETE FROM logs;")
        conn.execute("DELETE FROM telemetry;")
        conn.execute("DELETE FROM device_auth;")
        conn.execute("DELETE FROM devices;")
        conn.commit()
        conn.close()

    def _setup_device(self, device_id: str, name: str, dtype: str = "WINDOWS_PC") -> tuple[dict, str]:
        dev = self.device_svc.register({
            "device_id": device_id,
            "device_name": name,
            "device_type": dtype,
            "hostname": f"{name}-HOST",
            "ip_address": "192.168.1.150",
            "operating_system": "Windows 11 Pro",
        })
        pair = self.auth_svc.generate_pairing_credential(device_id)
        token = pair["token"]
        self.auth_svc.authenticate_device(device_id, token)
        return dev, token

    # ── Test 1 & 2 & 3: Presence, Hard Offline, Recovery ────────

    def test_01_online_status_heartbeat_telemetry(self):
        """Client becomes ONLINE when sending heartbeat or telemetry."""
        dev, token = self._setup_device("WIN-PC-01", "Primary Workstation")
        self.assertEqual(dev["status"], "pending")

        # Send heartbeat
        hb_res = self.heartbeat_svc.process_heartbeat("WIN-PC-01", {"client_status": "running"})
        self.assertEqual(hb_res["status"], "acknowledged")

        dev_after = self.device_svc.get_device("WIN-PC-01")
        self.assertEqual(dev_after["status"], "online")
        self.assertIsNotNone(dev_after["last_seen"])

    def test_02_hard_offline_timeout_transition(self):
        """Unresponsive client automatically transitions to OFFLINE after timeout."""
        dev, token = self._setup_device("WIN-PC-02", "Second_pc")
        
        # Client sends heartbeat and is online
        self.heartbeat_svc.process_heartbeat("WIN-PC-02", {"client_status": "running"})
        dev_online = self.device_svc.get_device("WIN-PC-02")
        self.assertEqual(dev_online["status"], "online")
        last_seen_initial = dev_online["last_seen"]

        # Simulate time passage beyond 90s timeout (e.g. 120s ago)
        old_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = 'WIN-PC-02';", (old_time,))
        conn.commit()
        conn.close()

        # Reconcile presence (simulating monitor tick or query)
        transitioned = self.device_svc.reconcile_presence(timeout_seconds=90)
        self.assertEqual(transitioned, 1)

        dev_offline = self.device_svc.get_device("WIN-PC-02")
        self.assertEqual(dev_offline["status"], "offline")
        # Ensure device was NOT deleted and last_seen is preserved
        self.assertEqual(dev_offline["device_id"], "WIN-PC-02")
        self.assertEqual(dev_offline["last_seen"], old_time)

    def test_03_recovery_reconnection_preserves_identity(self):
        """When offline client reconnects and resumes heartbeats, it becomes ONLINE again."""
        dev, token = self._setup_device("WIN-PC-03", "Second_pc")
        
        # Make it offline first
        self.device_svc.update_status("WIN-PC-03", "offline")
        self.assertEqual(self.device_svc.get_device("WIN-PC-03")["status"], "offline")

        # Ingest historical log while offline
        self.log_svc.ingest_logs("WIN-PC-03", [
            {"timestamp": "2026-08-25 08:00:00", "severity": "INFO", "message": "Historical system boot"}
        ])

        # Client starts up again and sends heartbeat
        self.heartbeat_svc.process_heartbeat("WIN-PC-03", {"client_status": "running"})

        dev_recovered = self.device_svc.get_device("WIN-PC-03")
        self.assertEqual(dev_recovered["status"], "online")
        self.assertEqual(dev_recovered["device_name"], "Second_pc")
        
        # Verify historical logs and auth remain intact
        logs = self.log_svc.search_logs(device_id="WIN-PC-03")["logs"]
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["message"], "Historical system boot")
        self.assertEqual(self.auth_svc.get_auth_status("WIN-PC-03")["status"], "paired")

    # ── Test 4: Online / Offline Listing and Telemetry Presentation ──

    def test_04_devices_with_telemetry_and_navigation(self):
        """Online & Offline views return accurate telemetry metrics and historical labels."""
        # Setup Online Client A
        dev_a, _ = self._setup_device("WIN-A", "Client_A")
        self.heartbeat_svc.process_heartbeat("WIN-A", {})
        self.telemetry_svc.ingest("WIN-A", {
            "timestamp": "2026-08-27 10:00:00",
            "cpu": {"cpu_usage": 45.5},
            "memory": {"memory_usage_percent": 60.2, "memory_used_gb": 4.8, "memory_total_gb": 8.0},
            "disk": {"disk_usage_percent": 55.0, "disk_total_gb": 256.0, "disk_free_gb": 115.2},
            "network": {"network_bytes_sent_mb": 12.5, "network_bytes_recv_mb": 25.0},
        })

        # Setup Offline Client B
        dev_b, _ = self._setup_device("WIN-B", "Client_B")
        self.heartbeat_svc.process_heartbeat("WIN-B", {})
        self.telemetry_svc.ingest("WIN-B", {
            "timestamp": "2026-08-27 08:30:00",
            "cpu": {"cpu_usage": 88.6},
            "memory": {"memory_usage_percent": 83.6, "memory_used_gb": 6.7, "memory_total_gb": 8.0},
            "disk": {"disk_usage_percent": 61.8, "disk_total_gb": 236.0, "disk_free_gb": 90.0},
        })
        # Force Client B to offline
        old_time = (datetime.now(timezone.utc) - timedelta(seconds=300)).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = 'WIN-B';", (old_time,))
        conn.commit()
        conn.close()
        self.device_svc.reconcile_presence(timeout_seconds=90)

        # 1. Fetch devices with telemetry
        devices = self.device_svc.list_devices_with_telemetry()
        self.assertEqual(len(devices), 2)

        dev_a_res = next(d for d in devices if d["device_id"] == "WIN-A")
        dev_b_res = next(d for d in devices if d["device_id"] == "WIN-B")

        self.assertEqual(dev_a_res["status"], "online")
        self.assertAlmostEqual(dev_a_res["cpu_usage"], 45.5, places=1)
        self.assertAlmostEqual(dev_a_res["memory_usage"], 60.2, places=1)

        self.assertEqual(dev_b_res["status"], "offline")
        self.assertAlmostEqual(dev_b_res["cpu_usage"], 88.6, places=1)
        self.assertAlmostEqual(dev_b_res["memory_usage"], 83.6, places=1)

        # 2. Test REST API endpoint
        resp = self.client.get("/api/devices?with_telemetry=true")
        self.assertEqual(resp.status_code, 200)
        api_data = resp.get_json()
        self.assertEqual(len(api_data), 2)

        # 3. Test single device endpoint with telemetry
        resp_single = self.client.get("/api/devices/WIN-A?with_telemetry=true")
        self.assertEqual(resp_single.status_code, 200)
        single_data = resp_single.get_json()
        self.assertIn("latest_telemetry", single_data)
        self.assertAlmostEqual(single_data["latest_telemetry"]["cpu_usage"], 45.5, places=1)

    # ── Test 5: Isolation between multiple clients ──────────────

    def test_05_multi_client_isolation(self):
        """Client A's logs and telemetry never leak into Client B's views."""
        self._setup_device("CLIENT-A", "Alpha Workstation")
        self._setup_device("CLIENT-B", "Beta Workstation")

        # Ingest separate logs
        self.log_svc.ingest_logs("CLIENT-A", [
            {"timestamp": "2026-08-27 10:00:00", "severity": "INFO", "application_name": "Word", "message": "Word opened on A"},
            {"timestamp": "2026-08-27 10:01:00", "severity": "WARNING", "application_name": "Word", "message": "High CPU on A"},
        ])
        self.log_svc.ingest_logs("CLIENT-B", [
            {"timestamp": "2026-08-27 10:00:00", "severity": "INFO", "application_name": "Chrome", "message": "Chrome opened on B"},
            {"timestamp": "2026-08-27 10:02:00", "severity": "ERROR", "application_name": "Service", "message": "Crash on B"},
        ])

        # Search for Client A
        logs_a = self.log_svc.search_logs(device_id="CLIENT-A")["logs"]
        self.assertEqual(len(logs_a), 2)
        for log in logs_a:
            self.assertEqual(log["device_id"], "CLIENT-A")
            self.assertNotIn("on B", log["message"])

        # Search for Client B
        logs_b = self.log_svc.search_logs(device_id="CLIENT-B")["logs"]
        self.assertEqual(len(logs_b), 2)
        for log in logs_b:
            self.assertEqual(log["device_id"], "CLIENT-B")
            self.assertNotIn("on A", log["message"])

    # ── Test 6: Client-Side Multi-Process Event Deduplication ────

    def test_06_client_multi_process_event_deduplication(self):
        """Multi-process apps (like Edge/Chrome) produce single start/stop events."""
        collector = WinEventCollector()
        collector._previous.processes = {}
        collector._last_active_app = None

        # Simulate Microsoft Edge launching 4 subprocesses simultaneously
        mock_p1 = MagicMock()
        mock_p1.info = {"pid": 1001, "name": "msedge.exe"}
        mock_p2 = MagicMock()
        mock_p2.info = {"pid": 1002, "name": "msedge.exe"}
        mock_p3 = MagicMock()
        mock_p3.info = {"pid": 1003, "name": "msedge.exe"}
        mock_p4 = MagicMock()
        mock_p4.info = {"pid": 1004, "name": "msedge.exe"}

        with patch("psutil.process_iter", return_value=[mock_p1, mock_p2, mock_p3, mock_p4]), \
             patch("client.app.collectors.events._get_active_window_process_name", return_value="msedge.exe"):
            
            events = collector.collect()
            started = [e for e in events if e["event_type"] == "APPLICATION_STARTED"]
            self.assertEqual(len(started), 1, "Must emit exactly ONE start event for multi-process app launch")
            self.assertEqual(started[0]["application_name"], "Microsoft Edge")
            self.assertEqual(started[0]["message"], "Microsoft Edge opened")

            # 2. While running, open a 5th tab (PID 1005)
            mock_p5 = MagicMock()
            mock_p5.info = {"pid": 1005, "name": "msedge.exe"}
            with patch("psutil.process_iter", return_value=[mock_p1, mock_p2, mock_p3, mock_p4, mock_p5]):
                events_tab = collector.collect()
                started_tab = [e for e in events_tab if e["event_type"] == "APPLICATION_STARTED"]
                self.assertEqual(len(started_tab), 0, "No duplicate start event when internal tabs/workers spawn")

            # 3. Terminate all Edge processes
            with patch("psutil.process_iter", return_value=[]), \
                 patch("client.app.collectors.events._get_active_window_process_name", return_value=None):
                events_close = collector.collect()
                stopped = [e for e in events_close if e["event_type"] == "APPLICATION_STOPPED"]
                self.assertEqual(len(stopped), 1, "Must emit exactly ONE stop event when app terminates")
                self.assertEqual(stopped[0]["application_name"], "Microsoft Edge")
                self.assertEqual(stopped[0]["message"], "Microsoft Edge closed")

    # ── Test 7 & 8: Master Log Ingestion Safe Deduplication ──────

    def test_07_master_ingestion_safe_deduplication(self):
        """Retrying transmission of identical event batch does not insert duplicate rows."""
        self._setup_device("WIN-DEDUP", "Dedup Test PC")

        batch = [
            {
                "timestamp": "2026-08-27 10:00:01",
                "severity": "INFO",
                "category": "APPLICATION",
                "event_type": "APPLICATION_STARTED",
                "application_name": "Microsoft Edge",
                "message": "Microsoft Edge opened",
            },
            {
                "timestamp": "2026-08-27 10:00:01",
                "severity": "INFO",
                "category": "DEVELOPMENT",
                "event_type": "APPLICATION_STARTED",
                "application_name": "Command Prompt",
                "message": "Command Prompt opened",
            }
        ]

        # First ingestion
        stored_1 = self.log_svc.ingest_logs("WIN-DEDUP", batch)
        self.assertEqual(stored_1, 2)
        total_1 = self.log_svc.search_logs(device_id="WIN-DEDUP")["total"]
        self.assertEqual(total_1, 2)

        # Retry exact same batch (simulating network retry / buffer replay)
        stored_2 = self.log_svc.ingest_logs("WIN-DEDUP", batch)
        self.assertEqual(stored_2, 0, "Duplicate batch should insert 0 new records")
        total_2 = self.log_svc.search_logs(device_id="WIN-DEDUP")["total"]
        self.assertEqual(total_2, 2, "Total logs must remain stable without duplicates")

    def test_08_legitimate_repeated_events_preserved(self):
        """Legitimate repeated events at different timestamps are properly stored and preserved."""
        self._setup_device("WIN-LEGIT", "Legitimate Repeat PC")

        events = [
            {"timestamp": "2026-08-27 10:00:01", "severity": "INFO", "application_name": "Microsoft Edge", "message": "Microsoft Edge opened"},
            {"timestamp": "2026-08-27 10:05:12", "severity": "INFO", "application_name": "Microsoft Edge", "message": "Microsoft Edge opened"},
            {"timestamp": "2026-08-27 10:10:43", "severity": "INFO", "application_name": "Microsoft Edge", "message": "Microsoft Edge opened"},
        ]

        stored = self.log_svc.ingest_logs("WIN-LEGIT", events)
        self.assertEqual(stored, 3)

        logs = self.log_svc.search_logs(device_id="WIN-LEGIT")["logs"]
        self.assertEqual(len(logs), 3, "All 3 legitimate separate events must remain visible")


if __name__ == "__main__":
    unittest.main()
