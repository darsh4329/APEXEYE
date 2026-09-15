"""
APEXEYE — Windows Client Application Activity Monitoring Test Suite

Validates:
1. Application start detection (APPLICATION_STARTED).
2. Application stop detection (APPLICATION_STOPPED).
3. Arbitrary application detection with automatic title and category formatting.
4. Multi-process application grouping (Chrome, Edge, VS Code).
5. Duplicate start/stop suppression across repeated polling scans.
6. Startup baseline snapshot (already running processes do NOT emit false started events).
7. Master API and logs table ingestion.
8. Telemetry collectors (CPU, Memory, Disk, Network) continue working properly.
"""

import hashlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import get_connection, init_database
from master.app.services.event_service import EventService
from master.app.services.log_service import LogService
from client.app.collectors.events import (
    EventCollector,
    ProcessSnapshot,
    APPLICATION_TAXONOMY,
    _resolve_application_metadata,
    _is_system_noise,
)
from client.app.collectors import (
    CPUCollector,
    MemoryCollector,
    DiskCollector,
    NetworkCollector,
)


@pytest.fixture(autouse=True)
def setup_db():
    init_database()
    yield


def seed_test_device(device_id: str = "DEV-WIN-ACTIVITY"):
    conn = get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO devices (device_id, device_name, device_type, status, authentication_status, created_at, updated_at)
               VALUES (?, 'Windows Workstation', 'WINDOWS_PC', 'online', 'paired', datetime('now'), datetime('now'));""",
            (device_id,),
        )
        token_hash = hashlib.sha256("test-token".encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT OR REPLACE INTO device_auth (device_id, credential_id, authentication_status, created_at)
               VALUES (?, ?, 'paired', datetime('now'));""",
            (device_id, token_hash),
        )
        conn.commit()
    finally:
        conn.close()


def test_01_windows_application_started_detection():
    """Verify Windows client detects a newly opened application."""
    collector = EventCollector()
    collector._previous.processes = {}  # Empty baseline

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 2048, "name": "msedge.exe"}

    with patch("psutil.process_iter", return_value=[mock_proc]):
        events = collector.collect()
        assert len(events) == 1
        evt = events[0]
        assert evt["event_type"] == "APPLICATION_STARTED"
        assert evt["application_name"] == "Microsoft Edge"
        assert evt["category"] == "BROWSER"
        assert evt["process_name"] == "msedge.exe"
        assert evt["pid"] == 2048


def test_02_windows_application_stopped_detection():
    """Verify Windows client detects application closure."""
    collector = EventCollector()
    collector._previous.processes = {}

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 2048, "name": "msedge.exe"}

    with patch("psutil.process_iter", return_value=[mock_proc]):
        collector.collect()  # App opened

    with patch("psutil.process_iter", return_value=[]):
        events = collector.collect()  # App closed
        assert len(events) == 1
        evt = events[0]
        assert evt["event_type"] == "APPLICATION_STOPPED"
        assert evt["application_name"] == "Microsoft Edge"
        assert evt["category"] == "BROWSER"


def test_03_arbitrary_application_detection():
    """Verify arbitrary unknown applications generate clean names and APPLICATION category."""
    name, category = _resolve_application_metadata("custom_accounting_suite.exe")
    assert name == "Custom Accounting Suite"
    assert category == "APPLICATION"

    name2, category2 = _resolve_application_metadata("billing-app-tool.exe")
    assert name2 == "Billing App Tool"
    assert category2 == "APPLICATION"

    collector = EventCollector()
    collector._previous.processes = {}

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 9876, "name": "custom-billing.exe"}

    with patch("psutil.process_iter", return_value=[mock_proc]):
        events = collector.collect()
        assert len(events) == 1
        assert events[0]["application_name"] == "Custom Billing"
        assert events[0]["category"] == "APPLICATION"
        assert events[0]["process_name"] == "custom-billing.exe"


def test_04_chrome_multi_process_grouping():
    """Verify multi-process Chrome creates only 1 STARTED and 1 STOPPED event."""
    collector = EventCollector()
    collector._previous.processes = {}

    p1 = MagicMock(); p1.info = {"pid": 100, "name": "chrome.exe"}
    p2 = MagicMock(); p2.info = {"pid": 101, "name": "chrome.exe"}
    p3 = MagicMock(); p3.info = {"pid": 102, "name": "chrome.exe"}

    # 1. Chrome starts with 3 processes simultaneously
    with patch("psutil.process_iter", return_value=[p1, p2, p3]):
        start_evts = collector.collect()
        assert len(start_evts) == 1
        assert start_evts[0]["event_type"] == "APPLICATION_STARTED"
        assert start_evts[0]["application_name"] == "Google Chrome"

    # 2. More subprocesses spawn (total 5)
    p4 = MagicMock(); p4.info = {"pid": 103, "name": "chrome.exe"}
    p5 = MagicMock(); p5.info = {"pid": 104, "name": "chrome.exe"}
    with patch("psutil.process_iter", return_value=[p1, p2, p3, p4, p5]):
        more_evts = collector.collect()
        assert len(more_evts) == 0, "Spawning subprocesses must emit 0 duplicate events"

    # 3. Subprocesses exit leaving only main
    with patch("psutil.process_iter", return_value=[p1]):
        sub_exit_evts = collector.collect()
        assert len(sub_exit_evts) == 0, "Subprocess termination must emit 0 events while app runs"

    # 4. Final process exits
    with patch("psutil.process_iter", return_value=[]):
        stop_evts = collector.collect()
        assert len(stop_evts) == 1
        assert stop_evts[0]["event_type"] == "APPLICATION_STOPPED"
        assert stop_evts[0]["application_name"] == "Google Chrome"


def test_05_duplicate_suppression_across_scans():
    """Verify repeating the same process state across multiple scans produces zero duplicate events."""
    collector = EventCollector()
    collector._previous.processes = {}

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 5555, "name": "code.exe"}

    with patch("psutil.process_iter", return_value=[mock_proc]):
        evts1 = collector.collect()
        assert len(evts1) == 1

        evts2 = collector.collect()
        assert len(evts2) == 0

        evts3 = collector.collect()
        assert len(evts3) == 0


def test_06_startup_baseline_snapshot():
    """Verify applications running before EventCollector initialized do NOT emit false started events."""
    mock_proc = MagicMock()
    mock_proc.info = {"pid": 1111, "name": "notepad.exe"}

    with patch("psutil.process_iter", return_value=[mock_proc]):
        # Initializing collector captures baseline
        collector = EventCollector()
        assert "Notepad" in collector._previous.app_groups

        # Subsequent scan with same process running
        events = collector.collect()
        assert len(events) == 0, "Baseline running processes must not emit APPLICATION_STARTED"


def test_07_master_log_ingestion_and_query():
    """Verify Windows client events are ingested into Master logs table with proper categories."""
    dev_id = "DEV-WIN-INGEST"
    seed_test_device(dev_id)

    evt_svc = EventService()
    res = evt_svc.ingest_events(dev_id, [
        {
            "timestamp": "2026-09-03 15:10:00",
            "event_type": "APPLICATION_STARTED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "process_name": "msedge.exe",
            "pid": 3030,
            "source": "process_monitor",
            "severity": "INFO",
            "message": "Microsoft Edge opened",
        },
        {
            "timestamp": "2026-09-03 15:15:00",
            "event_type": "APPLICATION_STOPPED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "process_name": "msedge.exe",
            "pid": 3030,
            "source": "process_monitor",
            "severity": "INFO",
            "message": "Microsoft Edge closed",
        },
    ])
    assert res["stored"] == 2

    log_svc = LogService()
    data = log_svc.search_logs(device_id=dev_id)
    logs = data.get("logs", [])
    assert len(logs) >= 2
    assert any(l["application_name"] == "Microsoft Edge" and l["event_type"] == "APPLICATION_STARTED" for l in logs)
    assert any(l["application_name"] == "Microsoft Edge" and l["event_type"] == "APPLICATION_STOPPED" for l in logs)


def test_08_windows_telemetry_remains_functional():
    """Verify CPU, RAM, Disk, and Network telemetry collectors remain fully functional."""
    cpu_coll = CPUCollector()
    cpu_data = cpu_coll.collect()
    assert "cpu_usage" in cpu_data

    mem_coll = MemoryCollector()
    mem_data = mem_coll.collect()
    assert "memory_usage_percent" in mem_data
    assert "memory_total_gb" in mem_data

    disk_coll = DiskCollector()
    disk_data = disk_coll.collect()
    assert "disk_usage_percent" in disk_data

    net_coll = NetworkCollector()
    net_data = net_coll.collect()
    assert "network_bytes_sent_mb" in net_data


def test_09_windows_noise_filtering():
    """Verify low-level OS noise and system processes are ignored."""
    assert _is_system_noise(0, "System Idle Process") is True
    assert _is_system_noise(4, "System") is True
    assert _is_system_noise(100, "svchost.exe") is True
    assert _is_system_noise(101, "dwm.exe") is True
    assert _is_system_noise(102, "services.exe") is True
    assert _is_system_noise(103, "runtimebroker.exe") is True

    # User applications must NOT be noise
    assert _is_system_noise(2000, "msedge.exe") is False
    assert _is_system_noise(2001, "chrome.exe") is False
    assert _is_system_noise(2002, "code.exe") is False
    assert _is_system_noise(2003, "arbitrary_tool.exe") is False
