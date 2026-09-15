"""
APEXEYE — Comprehensive Tests for Presence Timeout, Application Lifecycle Events, and Dev Log Clear

Covers:
1. Client online after heartbeat / telemetry
2. Client becomes offline after heartbeat timeout
3. Read operations do not make a client look online or advance last_seen
4. Client comes back online after communication resumes
5. Application lifecycle:
   - closed -> opened = ONE OPENED event
   - remains running = NO duplicate OPENED events
   - subprocesses spawn = NO duplicate OPENED events
   - all processes stop = ONE CLOSED event
   - application opens again later = valid OPENED event
6. No spam of UNKNOWN_APPLICATION / APPLICATION_ACTIVE in activity logs
7. Log deduplication on ingestion
8. Clear Logs deletes only logs/events from database
9. Clear Logs preserves devices, pairing credentials, and telemetry
10. New logs generated after clearing work normally
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import pytest

from master.app.database import init_database, get_connection
from master.app.services.device_service import DeviceService

from master.app.services.heartbeat_service import HeartbeatService
from master.app.services.telemetry_service import TelemetryService
from master.app.services.event_service import EventService
from master.app.services.log_service import LogService
from master.app.services.presence_service import PresenceMonitorEngine
from master.app.auth import AuthService
from master.app.api import create_app
from client.app.collectors.events import EventCollector, APPLICATION_TAXONOMY


@pytest.fixture
def test_db():
    """Create a temporary clean SQLite database for tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    init_database(db_path)
    yield db_path

    try:
        os.remove(db_path)
    except OSError:
        pass


@pytest.fixture
def app(test_db):
    """Create a Flask test application bound to test_db."""
    with patch("master.app.config.config.DB_PATH", test_db):
        app = create_app()
        app.config["TESTING"] = True
        yield app


@pytest.fixture
def client(app):
    return app.test_client()


# =====================================================================
# 1. PRESENCE TIMEOUT & RECONCILIATION TESTS
# =====================================================================

def test_client_presence_flow_online_to_offline_to_reconnect(test_db):
    """
    Deterministic end-to-end presence lifecycle:
    Register -> Heartbeat -> Online -> Timeout -> Offline -> Reconnect -> Online.
    """
    with patch("master.app.config.config.DB_PATH", test_db):
        dev_svc = DeviceService()
        hb_svc = HeartbeatService()

        # 1. Register device
        dev_svc.register({
            "device_id": "TEST-WIN-01",
            "device_name": "Test Workstation",
            "device_type": "WINDOWS_PC",
            "operating_system": "Windows 11 Pro",
            "ip_address": "192.168.1.55",
        })

        # Initially status is pending
        device = dev_svc.get_device("TEST-WIN-01")
        assert device["status"] == "pending"

        # 2. Client sends heartbeat -> becomes ONLINE
        now_dt = datetime.now(timezone.utc)
        hb_svc.process_heartbeat("TEST-WIN-01", {"client_status": "running"})

        device = dev_svc.get_device("TEST-WIN-01")
        assert device["status"] == "online"
        assert device["last_seen"] is not None

        summary = dev_svc.get_summary()
        assert summary["online"] == 1
        assert summary["offline"] == 0

        # 3. Simulate passage of time beyond HEARTBEAT_TIMEOUT_SECONDS (9s)
        # Client disconnects: last_seen stops advancing and is in the past
        past_time = (now_dt - timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection(test_db)
        conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?;", (past_time, "TEST-WIN-01"))
        conn.commit()
        conn.close()

        # 4. Presence reconciliation executes with default 9s timeout
        transitioned = dev_svc.reconcile_presence()
        assert transitioned == 1

        # 5. Device is now OFFLINE
        device = dev_svc.get_device("TEST-WIN-01")
        assert device["status"] == "offline"

        summary = dev_svc.get_summary()
        assert summary["online"] == 0
        assert summary["offline"] == 1

        # 6. Device reconnects and sends new telemetry/heartbeat
        hb_svc.process_heartbeat("TEST-WIN-01", {"client_status": "running"})

        device = dev_svc.get_device("TEST-WIN-01")
        assert device["status"] == "online"

        summary = dev_svc.get_summary()
        assert summary["online"] == 1
        assert summary["offline"] == 0


def test_read_operations_do_not_refresh_presence(test_db, client):
    """
    GET requests (dashboard, device list, telemetry queries, log searches)
    MUST NOT advance last_seen or mark an offline device online.
    """
    with patch("master.app.config.config.DB_PATH", test_db):
        dev_svc = DeviceService()
        dev_svc.register({
            "device_id": "TEST-WIN-02",
            "device_name": "Accounting PC",
            "device_type": "WINDOWS_PC",
            "ip_address": "192.168.1.56",
        })

        # Set device to offline with past last_seen
        past_time = "2026-08-20 10:00:00"
        conn = get_connection(test_db)
        conn.execute(
            "UPDATE devices SET status = 'offline', last_seen = ?, updated_at = ? WHERE device_id = ?;",
            (past_time, past_time, "TEST-WIN-02")
        )
        conn.commit()
        conn.close()

        # Execute read operations
        r1 = client.get("/api/devices")
        assert r1.status_code == 200

        r2 = client.get("/api/devices/summary")
        assert r2.status_code == 200
        assert r2.json["online"] == 0
        assert r2.json["offline"] == 1

        r3 = client.get("/api/devices/TEST-WIN-02")
        assert r3.status_code == 200
        assert r3.json["status"] == "offline"
        assert r3.json["last_seen"] == past_time

        r4 = client.get("/api/logs")
        assert r4.status_code == 200

        r5 = client.get("/api/telemetry/history")
        assert r5.status_code == 200

        # Verify device remained offline and last_seen never advanced
        dev_after = dev_svc.get_device("TEST-WIN-02")
        assert dev_after["status"] == "offline"
        assert dev_after["last_seen"] == past_time


# =====================================================================
# 2. APPLICATION LIFECYCLE EVENT TESTS (OPENED / CLOSED / SUBPROCESSES)
# =====================================================================

def test_application_lifecycle_opened_closed_and_subprocess_grouping():
    """
    Tests application lifecycle state machine:
    - 0 processes -> 1: emits ONE APPLICATION_STARTED ("Microsoft Edge opened")
    - 1 -> 5 processes (subprocesses/tabs): emits NO additional opened events
    - 5 -> 2 processes: emits NO closed events
    - 2 -> 0 processes: emits ONE APPLICATION_STOPPED ("Microsoft Edge closed")
    - 0 -> 1 process (reopen): emits ONE new APPLICATION_STARTED
    """
    collector = EventCollector()
    collector._previous.processes = {}  # Start clean

    # Helper mock process
    def create_mock_proc(pid, name):
        m = MagicMock()
        m.info = {"pid": pid, "name": name}
        return m

    # STATE 1: Microsoft Edge starts (1 process)
    with patch("psutil.process_iter", return_value=[create_mock_proc(1001, "msedge.exe")]):
        events1 = collector.collect()

    assert len(events1) == 1
    assert events1[0]["event_type"] == "APPLICATION_STARTED"
    assert events1[0]["application_name"] == "Microsoft Edge"
    assert events1[0]["category"] == "BROWSER"
    assert events1[0]["message"] == "Microsoft Edge opened"

    # STATE 2: Additional helper subprocesses / tabs spawn (1 -> 4 processes)
    with patch("psutil.process_iter", return_value=[
        create_mock_proc(1001, "msedge.exe"),
        create_mock_proc(1002, "msedge.exe"),
        create_mock_proc(1003, "msedge.exe"),
        create_mock_proc(1004, "msedge.exe"),
    ]):
        events2 = collector.collect()

    # MUST NOT emit any new opened events
    assert len(events2) == 0

    # STATE 3: Two tabs close, but Edge is still running (4 -> 2 processes)
    with patch("psutil.process_iter", return_value=[
        create_mock_proc(1001, "msedge.exe"),
        create_mock_proc(1002, "msedge.exe"),
    ]):
        events3 = collector.collect()

    # MUST NOT emit closed event because Edge is still running
    assert len(events3) == 0

    # STATE 4: Edge closes completely (2 -> 0 processes)
    with patch("psutil.process_iter", return_value=[]):
        events4 = collector.collect()

    assert len(events4) == 1
    assert events4[0]["event_type"] == "APPLICATION_STOPPED"
    assert events4[0]["application_name"] == "Microsoft Edge"
    assert events4[0]["category"] == "BROWSER"
    assert events4[0]["message"] == "Microsoft Edge closed"

    # STATE 5: Edge is reopened later (0 -> 1 process)
    with patch("psutil.process_iter", return_value=[create_mock_proc(2001, "msedge.exe")]):
        events5 = collector.collect()

    assert len(events5) == 1
    assert events5[0]["event_type"] == "APPLICATION_STARTED"
    assert events5[0]["application_name"] == "Microsoft Edge"
    assert events5[0]["message"] == "Microsoft Edge opened"


def test_multiple_applications_independent_lifecycle():
    """
    Multiple applications (VS Code, Chrome, Terminal) track independently.
    """
    collector = EventCollector()
    collector._previous.processes = {}

    def create_mock_proc(pid, name):
        m = MagicMock()
        m.info = {"pid": pid, "name": name}
        return m

    # Open VS Code and Chrome simultaneously
    with patch("psutil.process_iter", return_value=[
        create_mock_proc(501, "code.exe"),
        create_mock_proc(601, "chrome.exe"),
    ]):
        events1 = collector.collect()

    assert len(events1) == 2
    app_names = {e["application_name"] for e in events1}
    assert app_names == {"Visual Studio Code", "Google Chrome"}

    # Close only Chrome; VS Code remains running
    with patch("psutil.process_iter", return_value=[create_mock_proc(501, "code.exe")]):
        events2 = collector.collect()

    assert len(events2) == 1
    assert events2[0]["event_type"] == "APPLICATION_STOPPED"
    assert events2[0]["application_name"] == "Google Chrome"
    assert events2[0]["message"] == "Google Chrome closed"


def test_no_unknown_application_spam_in_lifecycle_events():
    """
    Uncataloged background processes or OS helpers must NOT emit UNKNOWN_APPLICATION spam.
    """
    collector = EventCollector()
    collector._previous.processes = {}

    def create_mock_proc(pid, name):
        m = MagicMock()
        m.info = {"pid": pid, "name": name}
        return m

    # System processes and unrecognized background tools running
    with patch("psutil.process_iter", return_value=[
        create_mock_proc(10, "svchost.exe"),
        create_mock_proc(20, "searchindexer.exe"),
        create_mock_proc(30, "shellhost.exe"),
        create_mock_proc(40, "unknown_tool_xyz.exe"),
    ]):
        events = collector.collect()

    # MUST be completely ignored (0 events)
    assert len(events) == 0


# =====================================================================
# 3. LOG DEDUPLICATION & REOPEN PRESERVATION TESTS
# =====================================================================

def test_log_ingestion_preserves_legitimate_reopens(test_db):
    """
    Ensure deduplication allows reopening the same application at different times.
    """
    with patch("master.app.config.config.DB_PATH", test_db):
        dev_svc = DeviceService()
        log_svc = LogService()

        dev_svc.register({
            "device_id": "TEST-DEV-DEDUP",
            "device_name": "Dedup Test PC",
            "device_type": "WINDOWS_PC",
        })

        # Event 1: Edge opened at 10:00:01
        log_svc.ingest_logs("TEST-DEV-DEDUP", [{
            "timestamp": "2026-08-27 10:00:01",
            "event_type": "APPLICATION_STARTED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "message": "Microsoft Edge opened",
            "severity": "INFO",
        }])

        # Event 2: Edge closed at 10:05:12
        log_svc.ingest_logs("TEST-DEV-DEDUP", [{
            "timestamp": "2026-08-27 10:05:12",
            "event_type": "APPLICATION_STOPPED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "message": "Microsoft Edge closed",
            "severity": "INFO",
        }])

        # Event 3: Edge reopened at 10:10:43
        log_svc.ingest_logs("TEST-DEV-DEDUP", [{
            "timestamp": "2026-08-27 10:10:43",
            "event_type": "APPLICATION_STARTED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "message": "Microsoft Edge opened",
            "severity": "INFO",
        }])

        # Retry of Event 3 (same timestamp + same message) -> duplicate should be skipped
        stored = log_svc.ingest_logs("TEST-DEV-DEDUP", [{
            "timestamp": "2026-08-27 10:10:43",
            "event_type": "APPLICATION_STARTED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "message": "Microsoft Edge opened",
            "severity": "INFO",
        }])
        assert stored == 0

        # All 3 legitimate separate events MUST be present
        res = log_svc.search_logs(device_id="TEST-DEV-DEDUP")
        assert res["total"] == 3
        logs = res["logs"]
        assert logs[0]["timestamp"] == "2026-08-27 10:10:43"
        assert logs[0]["message"] == "Microsoft Edge opened"
        assert logs[1]["timestamp"] == "2026-08-27 10:05:12"
        assert logs[1]["message"] == "Microsoft Edge closed"
        assert logs[2]["timestamp"] == "2026-08-27 10:00:01"
        assert logs[2]["message"] == "Microsoft Edge opened"


# =====================================================================
# 4. CLEAR LOGS ENDPOINT & DEVELOPMENT CLEANUP TESTS
# =====================================================================

def test_clear_logs_deletes_only_logs_and_preserves_everything_else(test_db, client):
    """
    Verifies that /api/logs/clear:
    - Clears all records from the logs table
    - Preserves registered devices
    - Preserves device authentication credentials / pairings
    - Preserves telemetry data
    - Allows subsequent new logs to be ingested and queried normally
    """
    with patch("master.app.config.config.DB_PATH", test_db):
        dev_svc = DeviceService()
        auth_svc = AuthService()
        tel_svc = TelemetryService()
        log_svc = LogService()

        # 1. Register device & pair
        dev = dev_svc.register({
            "device_id": "TEST-DEV-CLEAR",
            "device_name": "Workstation Clear",
            "device_type": "WINDOWS_PC",
            "ip_address": "192.168.1.99",
        })
        pair_cred = auth_svc.generate_pairing_credential("TEST-DEV-CLEAR")
        auth_svc.authenticate_device("TEST-DEV-CLEAR", pair_cred["token"])

        # 2. Add telemetry
        tel_svc.ingest("TEST-DEV-CLEAR", {
            "timestamp": "2026-08-27 11:00:00",
            "cpu": {"cpu_usage": 45.2},
            "memory": {"memory_usage_percent": 60.5, "memory_total_gb": 16.0, "memory_used_gb": 9.68},
            "disk": {"disk_usage_percent": 30.0, "disk_total_gb": 500.0, "disk_free_gb": 350.0},
        })

        # 3. Add several logs
        for i in range(5):
            log_svc.ingest_logs("TEST-DEV-CLEAR", [{
                "timestamp": f"2026-08-27 11:0{i}:00",
                "event_type": "APPLICATION_STARTED",
                "category": "PRODUCTIVITY",
                "application_name": "Notepad",
                "message": "Notepad opened",
                "severity": "INFO",
            }])

        # Verify logs exist
        logs_before = log_svc.search_logs(device_id="TEST-DEV-CLEAR")
        assert logs_before["total"] == 5

        # 4. Call Clear Logs endpoint (POST /api/logs/clear)
        res = client.post("/api/logs/clear")
        assert res.status_code == 200
        assert res.json["status"] == "success"
        assert res.json["deleted"] == 5

        # 5. Verify logs table is now completely empty
        logs_after = log_svc.search_logs(device_id="TEST-DEV-CLEAR")
        assert logs_after["total"] == 0
        assert len(logs_after["logs"]) == 0

        # 6. Verify Device Registration is INTACT
        device = dev_svc.get_device("TEST-DEV-CLEAR")
        assert device is not None
        assert device["device_name"] == "Workstation Clear"
        assert device["authentication_status"] == "paired"

        # 7. Verify Pairing Credentials are INTACT
        auth_stat = auth_svc.get_auth_status("TEST-DEV-CLEAR")
        assert auth_stat["status"] == "paired"

        # 8. Verify Telemetry is INTACT
        tel = tel_svc.get_latest("TEST-DEV-CLEAR")
        assert tel is not None
        assert tel["cpu_usage"] == 45.2

        # 9. Ingest new logs AFTER clearing -> works normally
        log_svc.ingest_logs("TEST-DEV-CLEAR", [{
            "timestamp": "2026-08-27 11:30:00",
            "event_type": "APPLICATION_STARTED",
            "category": "DEVELOPMENT",
            "application_name": "Command Prompt",
            "message": "Command Prompt opened",
            "severity": "INFO",
        }])

        logs_new = log_svc.search_logs(device_id="TEST-DEV-CLEAR")
        assert logs_new["total"] == 1
        assert logs_new["logs"][0]["message"] == "Command Prompt opened"
