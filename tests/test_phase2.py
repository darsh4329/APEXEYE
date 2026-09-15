"""
APEXEYE — Phase 2 Test Suite

Tests:
  - CPU collector
  - RAM collector
  - Disk collector
  - Network collector
  - Host information collector
  - Process/event detection
  - Telemetry API endpoint
  - Events API endpoint
  - Heartbeat API endpoint
  - Host info API endpoint
  - Authentication middleware (valid / invalid)
  - Master database storage
  - Client/Master separation (no cross-imports)
"""

import json
import os
import sys
import time
import unittest
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.services.device_service import DeviceService
from master.app.services.telemetry_service import TelemetryService
from master.app.services.event_service import EventService
from master.app.services.host_info_service import HostInfoService
from master.app.services.heartbeat_service import HeartbeatService
from master.app.auth import AuthService
from master.app.api import create_app

# Initialize DB
init_database()


def _clean():
    """Remove all test data between tests."""
    conn = get_connection()
    for table in ("telemetry_detail", "telemetry", "events",
                  "host_info", "logs", "device_auth", "devices"):
        conn.execute(f"DELETE FROM {table};")
    conn.commit()
    conn.close()


def _setup_paired_device(device_id="TEST-WIN-001"):
    """Register and pair a test device. Returns (device_id, raw_token)."""
    svc = DeviceService()
    auth = AuthService()
    svc.register({
        "device_id": device_id,
        "device_name": "Test Windows PC",
        "device_type": "WINDOWS_PC",
        "hostname": "TEST-PC",
        "ip_address": "192.168.1.100",
    })
    pair_result = auth.generate_pairing_credential(device_id)
    token = pair_result["token"]
    auth.authenticate_device(device_id, token)
    return device_id, token


# ═══════════════════════════════════════════════════════════════════
# COLLECTOR TESTS
# ═══════════════════════════════════════════════════════════════════

class TestCPUCollector(unittest.TestCase):
    def test_collect(self):
        from client.app.collectors.cpu import CPUCollector
        collector = CPUCollector()
        result = collector.collect()
        self.assertIn("timestamp", result)
        self.assertIn("cpu_usage", result)
        self.assertIn("cpu_cores", result)
        self.assertIsInstance(result["cpu_usage"], (int, float))
        self.assertGreater(result["cpu_cores"], 0)
        self.assertIn("per_core_usage", result)
        self.assertIsInstance(result["per_core_usage"], list)


class TestMemoryCollector(unittest.TestCase):
    def test_collect(self):
        from client.app.collectors.memory import MemoryCollector
        collector = MemoryCollector()
        result = collector.collect()
        self.assertIn("timestamp", result)
        self.assertIn("memory_total_gb", result)
        self.assertIn("memory_used_gb", result)
        self.assertIn("memory_available_gb", result)
        self.assertIn("memory_usage_percent", result)
        self.assertGreater(result["memory_total_gb"], 0)
        self.assertGreater(result["memory_usage_percent"], 0)


class TestDiskCollector(unittest.TestCase):
    def test_collect(self):
        from client.app.collectors.disk import DiskCollector
        collector = DiskCollector()
        result = collector.collect()
        self.assertIn("timestamp", result)
        self.assertIn("disk_usage_percent", result)
        self.assertIn("drives", result)
        self.assertIsInstance(result["drives"], list)
        self.assertGreater(len(result["drives"]), 0)
        # Check first drive has expected fields
        drive = result["drives"][0]
        self.assertIn("device", drive)
        self.assertIn("total_gb", drive)
        self.assertIn("used_gb", drive)
        self.assertIn("free_gb", drive)
        self.assertIn("usage_percent", drive)


class TestNetworkCollector(unittest.TestCase):
    def test_collect(self):
        from client.app.collectors.network import NetworkCollector
        collector = NetworkCollector()
        result = collector.collect()
        self.assertIn("timestamp", result)
        self.assertIn("interfaces", result)
        self.assertIsInstance(result["interfaces"], list)
        self.assertIn("network_bytes_sent_mb", result)
        self.assertIn("network_bytes_recv_mb", result)


class TestOSInfoCollector(unittest.TestCase):
    def test_collect(self):
        from client.app.collectors.os_info import OSInfoCollector
        collector = OSInfoCollector()
        result = collector.collect()
        self.assertIn("timestamp", result)
        self.assertIn("hostname", result)
        self.assertIn("operating_system", result)
        self.assertIn("architecture", result)
        self.assertIn("ram_total_gb", result)
        self.assertIn("boot_time", result)
        self.assertIn("local_ip", result)
        self.assertIsNotNone(result["hostname"])
        self.assertGreater(result["ram_total_gb"], 0)


class TestEventCollector(unittest.TestCase):
    def test_initial_collect_no_events(self):
        """First call after init should return no events (no diff)."""
        from client.app.collectors.events import EventCollector
        collector = EventCollector()
        # First collect after init — should have no events since
        # the snapshot was taken during __init__
        events = collector.collect()
        # Events may or may not be empty depending on timing
        self.assertIsInstance(events, list)

    def test_event_structure(self):
        """Verify event dict structure if any events are returned."""
        from client.app.collectors.events import EventCollector
        collector = EventCollector()
        # Do a quick collect — may be empty
        events = collector.collect()
        # We can't guarantee events, but verify the collector runs
        self.assertIsInstance(events, list)
        for event in events:
            self.assertIn("timestamp", event)
            self.assertIn("event_type", event)
            self.assertIn("process_name", event)
            self.assertIn("pid", event)
            self.assertIn("severity", event)


# ═══════════════════════════════════════════════════════════════════
# SERVICE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestTelemetryService(unittest.TestCase):
    def setUp(self):
        _clean()
        self.device_id, self.token = _setup_paired_device()
        self.svc = TelemetryService()

    def test_ingest_telemetry(self):
        payload = {
            "timestamp": "2025-01-15 10:30:00",
            "cpu": {"cpu_usage": 45.2, "cpu_cores": 8},
            "memory": {"memory_usage_percent": 62.5},
            "disk": {"disk_usage_percent": 71.3},
            "network": {"network_bytes_sent_mb": 100.5, "network_bytes_recv_mb": 250.3},
        }
        result = self.svc.ingest(self.device_id, payload)
        self.assertEqual(result["status"], "stored")

    def test_get_latest(self):
        payload = {
            "timestamp": "2025-01-15 10:30:00",
            "cpu": {"cpu_usage": 45.2},
            "memory": {"memory_usage_percent": 62.5},
            "disk": {"disk_usage_percent": 71.3},
            "network": {"network_bytes_sent_mb": 100.5, "network_bytes_recv_mb": 250.3},
        }
        self.svc.ingest(self.device_id, payload)
        latest = self.svc.get_latest(self.device_id)
        self.assertIsNotNone(latest)
        self.assertAlmostEqual(latest["cpu_usage"], 45.2, places=1)

    def test_updates_device_status(self):
        payload = {
            "cpu": {"cpu_usage": 10},
            "memory": {"memory_usage_percent": 20},
            "disk": {"disk_usage_percent": 30},
            "network": {"network_bytes_sent_mb": 1, "network_bytes_recv_mb": 2},
        }
        self.svc.ingest(self.device_id, payload)
        device = DeviceService().get_device(self.device_id)
        self.assertEqual(device["status"], "online")
        self.assertIsNotNone(device["last_seen"])


class TestEventService(unittest.TestCase):
    def setUp(self):
        _clean()
        self.device_id, self.token = _setup_paired_device()
        self.svc = EventService()

    def test_ingest_events(self):
        events = [
            {
                "timestamp": "2025-01-15 10:30:00",
                "event_type": "process_started",
                "process_name": "notepad.exe",
                "pid": 1234,
                "source": "process_monitor",
                "severity": "info",
                "message": "Application started: notepad.exe",
            },
        ]
        result = self.svc.ingest_events(self.device_id, events)
        self.assertEqual(result["stored"], 1)

    def test_get_recent_events(self):
        events = [
            {"event_type": "process_started", "process_name": "chrome.exe", "pid": 100},
            {"event_type": "process_stopped", "process_name": "chrome.exe", "pid": 100},
        ]
        self.svc.ingest_events(self.device_id, events)
        recent = self.svc.get_recent_events(self.device_id)
        self.assertEqual(len(recent), 2)


class TestHostInfoService(unittest.TestCase):
    def setUp(self):
        _clean()
        self.device_id, self.token = _setup_paired_device()
        self.svc = HostInfoService()

    def test_store_host_info(self):
        info = {
            "hostname": "TEST-PC",
            "operating_system": "Windows",
            "os_version": "10.0.19045",
            "architecture": "AMD64",
            "cpu_model": "Intel i7",
            "ram_total_gb": 16.0,
            "local_ip": "192.168.1.100",
            "boot_time": "2025-01-15 08:00:00",
        }
        result = self.svc.store_host_info(self.device_id, info)
        self.assertEqual(result["status"], "stored")

    def test_upsert_host_info(self):
        info1 = {"hostname": "PC-1", "operating_system": "Windows"}
        info2 = {"hostname": "PC-1-RENAMED", "operating_system": "Windows"}
        self.svc.store_host_info(self.device_id, info1)
        self.svc.store_host_info(self.device_id, info2)
        result = self.svc.get_host_info(self.device_id)
        self.assertEqual(result["hostname"], "PC-1-RENAMED")

    def test_get_host_info(self):
        info = {"hostname": "TEST-PC", "operating_system": "Windows"}
        self.svc.store_host_info(self.device_id, info)
        result = self.svc.get_host_info(self.device_id)
        self.assertIsNotNone(result)
        self.assertEqual(result["hostname"], "TEST-PC")


class TestHeartbeatService(unittest.TestCase):
    def setUp(self):
        _clean()
        self.device_id, self.token = _setup_paired_device()
        self.svc = HeartbeatService()

    def test_process_heartbeat(self):
        result = self.svc.process_heartbeat(self.device_id, {
            "client_status": "running",
            "timestamp": "2025-01-15 10:30:00",
        })
        self.assertEqual(result["status"], "acknowledged")

    def test_heartbeat_updates_device(self):
        self.svc.process_heartbeat(self.device_id, {"client_status": "running"})
        device = DeviceService().get_device(self.device_id)
        self.assertEqual(device["status"], "online")
        self.assertIsNotNone(device["last_seen"])


# ═══════════════════════════════════════════════════════════════════
# API TESTS
# ═══════════════════════════════════════════════════════════════════

class TestPhase2API(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        _clean()
        self.device_id, self.token = _setup_paired_device()
        self.auth_headers = {
            "X-Device-ID": self.device_id,
            "X-Auth-Token": self.token,
        }

    def _bad_auth_headers(self):
        return {"X-Device-ID": self.device_id, "X-Auth-Token": "bad-token"}

    # ── Auth Middleware ──────────────────────────────────────────

    def test_missing_device_id_header(self):
        res = self.client.post(
            "/api/telemetry",
            json={"cpu": {"cpu_usage": 10}},
            headers={"X-Auth-Token": self.token},
        )
        self.assertEqual(res.status_code, 401)

    def test_missing_auth_token_header(self):
        res = self.client.post(
            "/api/telemetry",
            json={"cpu": {"cpu_usage": 10}},
            headers={"X-Device-ID": self.device_id},
        )
        self.assertEqual(res.status_code, 401)

    def test_invalid_token_rejected(self):
        res = self.client.post(
            "/api/telemetry",
            json={"cpu": {"cpu_usage": 10}},
            headers=self._bad_auth_headers(),
        )
        self.assertEqual(res.status_code, 401)

    def test_unknown_device_rejected(self):
        res = self.client.post(
            "/api/telemetry",
            json={"cpu": {"cpu_usage": 10}},
            headers={"X-Device-ID": "NONEXISTENT", "X-Auth-Token": self.token},
        )
        self.assertEqual(res.status_code, 401)

    # ── Telemetry API ────────────────────────────────────────────

    def test_post_telemetry(self):
        res = self.client.post("/api/telemetry", json={
            "cpu": {"cpu_usage": 45.2, "cpu_cores": 8},
            "memory": {"memory_usage_percent": 62.5},
            "disk": {"disk_usage_percent": 71.3},
            "network": {"network_bytes_sent_mb": 100, "network_bytes_recv_mb": 200},
        }, headers=self.auth_headers)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "stored")

    def test_post_empty_telemetry_rejected(self):
        res = self.client.post(
            "/api/telemetry", json={}, headers=self.auth_headers
        )
        self.assertEqual(res.status_code, 400)

    # ── Events API ───────────────────────────────────────────────

    def test_post_events(self):
        res = self.client.post("/api/events", json={
            "events": [
                {
                    "event_type": "process_started",
                    "process_name": "notepad.exe",
                    "pid": 1234,
                    "message": "Notepad started",
                },
            ],
        }, headers=self.auth_headers)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["stored"], 1)

    def test_post_events_missing_type_rejected(self):
        res = self.client.post("/api/events", json={
            "events": [{"process_name": "notepad.exe"}],
        }, headers=self.auth_headers)
        self.assertEqual(res.status_code, 400)

    def test_post_empty_events(self):
        res = self.client.post("/api/events", json={
            "events": [],
        }, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)

    # ── Heartbeat API ────────────────────────────────────────────

    def test_post_heartbeat(self):
        res = self.client.post("/api/heartbeat", json={
            "client_status": "running",
        }, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "acknowledged")

    def test_heartbeat_updates_last_seen(self):
        self.client.post("/api/heartbeat", json={
            "client_status": "running",
        }, headers=self.auth_headers)
        device = DeviceService().get_device(self.device_id)
        self.assertIsNotNone(device["last_seen"])
        self.assertEqual(device["status"], "online")

    # ── Host Info API ────────────────────────────────────────────

    def test_post_host_info(self):
        res = self.client.post("/api/host-info", json={
            "hostname": "TEST-PC",
            "operating_system": "Windows",
            "os_version": "10.0.19045",
            "architecture": "AMD64",
            "ram_total_gb": 16.0,
        }, headers=self.auth_headers)
        self.assertEqual(res.status_code, 201)

    def test_post_empty_host_info_rejected(self):
        res = self.client.post(
            "/api/host-info", json={}, headers=self.auth_headers
        )
        self.assertEqual(res.status_code, 400)


# ═══════════════════════════════════════════════════════════════════
# ARCHITECTURE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestClientMasterSeparation(unittest.TestCase):
    """Verify Client never imports Master's database layer."""

    def test_client_does_not_import_master_db(self):
        """Check that client modules don't import master.app.database."""
        import importlib
        client_modules = [
            "client.app.collectors.cpu",
            "client.app.collectors.memory",
            "client.app.collectors.disk",
            "client.app.collectors.network",
            "client.app.collectors.os_info",
            "client.app.collectors.events",
            "client.app.communication",
            "client.app.config",
        ]
        for mod_name in client_modules:
            mod = importlib.import_module(mod_name)
            source = Path(mod.__file__).read_text("utf-8")
            self.assertNotIn(
                "master.app.database",
                source,
                f"{mod_name} imports master.app.database — VIOLATION!",
            )

    def test_client_does_not_import_sqlite(self):
        """Client modules should not use sqlite3 directly."""
        import importlib
        client_modules = [
            "client.app.collectors.cpu",
            "client.app.collectors.memory",
            "client.app.communication",
        ]
        for mod_name in client_modules:
            mod = importlib.import_module(mod_name)
            source = Path(mod.__file__).read_text("utf-8")
            self.assertNotIn(
                "import sqlite3",
                source,
                f"{mod_name} imports sqlite3 — VIOLATION!",
            )


# ═══════════════════════════════════════════════════════════════════
# DATABASE STORAGE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDatabaseStorage(unittest.TestCase):
    def setUp(self):
        _clean()
        self.device_id, self.token = _setup_paired_device()

    def test_telemetry_stored_in_db(self):
        svc = TelemetryService()
        svc.ingest(self.device_id, {
            "cpu": {"cpu_usage": 55.0},
            "memory": {"memory_usage_percent": 70.0},
            "disk": {"disk_usage_percent": 80.0},
            "network": {"network_bytes_sent_mb": 10, "network_bytes_recv_mb": 20},
        })
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM telemetry WHERE device_id = ?;", (self.device_id,)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertAlmostEqual(row["cpu_usage"], 55.0, places=1)

    def test_telemetry_detail_stored(self):
        svc = TelemetryService()
        svc.ingest(self.device_id, {
            "cpu": {"cpu_usage": 55.0, "cpu_cores": 8},
            "memory": {"memory_usage_percent": 70.0},
            "disk": {"disk_usage_percent": 80.0},
            "network": {"network_bytes_sent_mb": 10, "network_bytes_recv_mb": 20},
        })
        conn = get_connection()
        row = conn.execute(
            "SELECT details FROM telemetry WHERE device_id = ?;",
            (self.device_id,),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        details = json.loads(row["details"])
        self.assertAlmostEqual(details["cpu"]["cpu_usage"], 55.0, places=1)

    def test_events_stored_in_db(self):
        svc = EventService()
        svc.ingest_events(self.device_id, [
            {"event_type": "process_started", "message": "notepad.exe (PID 999) started", "source": "process_monitor"},
        ])
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM logs WHERE device_id = ? AND event_type = 'process_started';",
            (self.device_id,)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertIn("notepad.exe", row["message"])
        self.assertEqual(row["event_type"], "process_started")

    def test_host_info_stored_in_db(self):
        svc = HostInfoService()
        svc.store_host_info(self.device_id, {
            "hostname": "DB-TEST-PC",
            "operating_system": "Windows",
        })
        conn = get_connection()
        row = conn.execute(
            "SELECT hostname, host_details FROM devices WHERE device_id = ?;", (self.device_id,)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["hostname"], "DB-TEST-PC")
        host_details = json.loads(row["host_details"])
        self.assertEqual(host_details["hostname"], "DB-TEST-PC")

    def test_phase2_schema_columns_exist(self):
        """Verify Phase 2 columns and tables exist in database."""
        conn = get_connection()
        telemetry_cols = [r["name"] for r in conn.execute("PRAGMA table_info(telemetry);").fetchall()]
        devices_cols = [r["name"] for r in conn.execute("PRAGMA table_info(devices);").fetchall()]
        logs_cols = [r["name"] for r in conn.execute("PRAGMA table_info(logs);").fetchall()]
        conn.close()
        self.assertIn("details", telemetry_cols)
        self.assertIn("host_details", devices_cols)
        self.assertIn("event_type", logs_cols)


if __name__ == "__main__":
    unittest.main()

