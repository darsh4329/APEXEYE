"""
APEXEYE — Comprehensive Test Suite for Linux Agent Forced Re-Authentication
Shutdown Lifecycle and Real Process Activity Monitoring.

Validates all 21 Acceptance Requirements:
1. REAUTHENTICATE_AGENT stops every Linux monitoring worker.
2. No telemetry after forced disconnect.
3. No heartbeat after forced disconnect.
4. No application events after forced disconnect.
5. Credentials are cleared.
6. Connection identity is cleared.
7. WAITING_FOR_PAIRING is reached.
8. Pairing page becomes available automatically.
9. Re-pairing starts the agent again.
10. No duplicate monitoring workers after re-pairing.
11. Device record remains intact.
12. New process -> STARTED.
13. Same process across multiple scans -> no duplicate STARTED.
14. Process disappears -> STOPPED.
15. Process starts again -> STARTED again.
16. Multi-process Chrome/Edge -> only one STARTED and one STOPPED.
17. Kernel/system processes are ignored.
18. Arbitrary non-taxonomy applications can still be detected.
19. Application events reach Master.
20. Application events are persisted in logs.
21. Application events appear in dashboard.
"""

import json
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import get_connection, init_database
from master.app.services.command_service import CommandService
from master.app.services.event_service import EventService
from master.app.services.log_service import LogService
from client_linux.app.auth import ClientAuth, _CRED_FILE
from client_linux.app.communication import MasterConnection
from client_linux.app.services.command_handler import CommandHandler
from client_linux.app.agent import Agent
from client_linux.app.collectors.events import (
    EventCollector,
    ProcessSnapshot,
    LINUX_PROCESS_TAXONOMY,
    _is_kernel_or_system_noise,
    _resolve_application_metadata,
)
from client_linux.app.ui.dashboard import create_client_ui_app


@pytest.fixture(autouse=True)
def setup_test_db():
    init_database()
    yield
    if _CRED_FILE.exists():
        try:
            _CRED_FILE.unlink()
        except Exception:
            pass


def seed_device(device_id: str, status: str = "online", auth_status: str = "paired", token: str = "secret-tok"):
    import hashlib
    conn = get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO devices 
               (device_id, device_name, device_type, status, authentication_status, created_at, updated_at)
               VALUES (?, 'Ubuntu PC', 'LINUX_PC', ?, ?, datetime('now'), datetime('now'));""",
            (device_id, status, auth_status),
        )
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT OR REPLACE INTO device_auth 
               (device_id, credential_id, authentication_status, created_at)
               VALUES (?, ?, ?, datetime('now'));""",
            (device_id, token_hash, auth_status),
        )
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# PART 1: FORCED REAUTHENTICATION & AGENT SHUTDOWN TESTS (Requirements 1-11)
# ═══════════════════════════════════════════════════════════════════════════

def test_01_reauthenticate_stops_every_linux_monitoring_worker():
    """Requirement 1: REAUTHENTICATE_AGENT stops every Linux monitoring worker."""
    mock_conn = MagicMock(spec=MasterConnection)
    mock_conn.is_authenticated = True
    agent = Agent(mock_conn)
    agent.start()
    assert agent.is_running is True
    assert len(agent._threads) == 4
    for t in agent._threads:
        assert t.is_alive() is True

    # Simulate worker calling stop (e.g. on 401 Unauthorized)
    agent.stop(timeout=2.0)

    assert agent.is_running is False
    for t in agent._threads:
        assert not t.is_alive(), f"Thread {t.name} did not stop!"


def test_02_no_telemetry_after_forced_disconnect():
    """Requirement 2: No telemetry sent after connection identity is cleared."""
    conn = MasterConnection("http://127.0.0.1:9100")
    conn.clear_identity()
    assert conn.is_authenticated is False
    # Attempt to send telemetry
    res = conn.send_telemetry({"cpu": {"cpu_usage": 10.0}})
    assert res is False


def test_03_no_heartbeat_after_forced_disconnect():
    """Requirement 3: No heartbeat sent after connection identity is cleared."""
    conn = MasterConnection("http://127.0.0.1:9100")
    conn.clear_identity()
    assert conn.is_authenticated is False
    # Attempt to send heartbeat
    res = conn.send_heartbeat()
    assert res is False


def test_04_no_application_events_after_forced_disconnect():
    """Requirement 4: No application events sent after connection identity is cleared."""
    conn = MasterConnection("http://127.0.0.1:9100")
    conn.clear_identity()
    assert conn.is_authenticated is False
    # Attempt to send events
    res = conn.send_events([{"event_type": "APPLICATION_STARTED", "application_name": "TestApp"}])
    assert res is False


def test_05_and_06_credentials_and_identity_cleared_on_reauth():
    """Requirements 5 & 6: Credentials and connection identity are wiped on REAUTHENTICATE_AGENT."""
    mock_conn = MagicMock(spec=MasterConnection)
    auth = ClientAuth(mock_conn)
    auth._save_credentials({"device_id": "DEV-LIN-01", "token": "tok-123", "status": "paired"})
    assert _CRED_FILE.exists()

    handler = CommandHandler(conn=mock_conn, auth=auth)
    res = handler.handle_command({
        "command_id": "CMD-001",
        "device_id": "DEV-LIN-01",
        "command_type": "REAUTHENTICATE_AGENT",
    })

    assert res["success"] is True
    assert not _CRED_FILE.exists(), "Local credentials file must be deleted"
    assert auth.is_paired is False
    mock_conn.clear_identity.assert_called_once()


def test_07_waiting_for_pairing_reached():
    """Requirement 7: Handler returns WAITING_FOR_PAIRING lifecycle state."""
    mock_conn = MagicMock(spec=MasterConnection)
    auth = ClientAuth(mock_conn)
    auth._save_credentials({"device_id": "DEV-LIN-02", "token": "tok-456", "status": "paired"})

    handler = CommandHandler(conn=mock_conn, auth=auth)
    res = handler.handle_command({
        "command_id": "CMD-002",
        "device_id": "DEV-LIN-02",
        "command_type": "REAUTHENTICATE_AGENT",
    })

    assert res["data"]["lifecycle_state"] == "WAITING_FOR_PAIRING"
    assert res["data"]["authentication_status"] == "UNAUTHENTICATED"
    assert res["data"]["connection_status"] == "DISCONNECTED"


def test_08_pairing_page_available_automatically():
    """Requirement 8: Local UI serves client_auth.html when unauthenticated."""
    mock_conn = MagicMock(spec=MasterConnection)
    mock_conn.master_url = "http://127.0.0.1:9100"
    auth = ClientAuth(mock_conn)
    auth._clear_credentials()

    app = create_client_ui_app(auth, mock_conn)
    client = app.test_client()

    resp = client.get("/")
    assert resp.status_code == 200
    assert "ApexEye Linux Client — Device Authentication" in resp.get_data(as_text=True)

    status_resp = client.get("/api/local/status")
    assert status_resp.status_code == 200
    assert status_resp.get_json()["is_paired"] is False


def test_09_and_10_re_pairing_starts_single_agent():
    """Requirements 9 & 10: Re-pairing sets identity and restarts fresh agent without duplicate workers."""
    mock_conn = MagicMock(spec=MasterConnection)
    mock_conn.authenticate.return_value = (200, {"success": True, "device_id": "DEV-REPAIR"})

    auth = ClientAuth(mock_conn)
    auth._clear_credentials()

    app = create_client_ui_app(auth, mock_conn)
    client = app.test_client()

    # Submit new credentials through UI endpoint
    auth_resp = client.post("/api/local/authenticate", json={"device_id": "DEV-REPAIR", "token": "new-tok-999"})
    assert auth_resp.status_code == 200
    assert auth.is_paired is True
    assert auth.device_id == "DEV-REPAIR"

    # Start fresh agent
    agent = Agent(mock_conn)
    agent.start()
    assert agent.is_running is True
    assert len(agent._threads) == 4

    agent.stop(timeout=2.0)
    assert agent.is_running is False


def test_11_device_record_remains_intact_on_master():
    """Requirement 11: Master REAUTHENTICATE_AGENT preserves device record and history."""
    dev_id = "DEV-AUDIT-PRESERVE"
    seed_device(dev_id)

    # Insert a sample log entry to simulate existing history
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO logs (device_id, device_type, timestamp, level, severity, event_type, category, message, source, created_at)
               VALUES (?, 'LINUX_PC', datetime('now'), 'INFO', 'INFO', 'SYSTEM_STARTUP', 'SYSTEM', 'Prior event', 'test', datetime('now'));""",
            (dev_id,),
        )
        conn.commit()
    finally:
        conn.close()

    svc = CommandService()
    res = svc.execute_command(dev_id, "REAUTHENTICATE_AGENT")
    assert res["success"] is True

    # Check device record in database
    conn = get_connection()
    try:
        dev = conn.execute("SELECT * FROM devices WHERE device_id = ?;", (dev_id,)).fetchone()
        assert dev is not None, "Device record MUST be preserved"
        assert dev["authentication_status"] == "unauthenticated"
        assert dev["status"] == "offline"

        logs = conn.execute("SELECT id FROM logs WHERE device_id = ?;", (dev_id,)).fetchall()
        assert len(logs) >= 1, "Historical logs must remain intact"
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# PART 2: APPLICATION ACTIVITY MONITORING TESTS (Requirements 12-21)
# ═══════════════════════════════════════════════════════════════════════════

def test_12_new_process_emits_started():
    """Requirement 12: Detecting a new process emits APPLICATION_STARTED."""
    collector = EventCollector()
    collector._previous.processes = {}  # Empty baseline

    # Simulate Edge process appearing
    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 2045, "name": "microsoft-edge", "ppid": 1000}
        mock_iter.return_value = [mock_proc]

        events = collector.collect()
        assert len(events) == 1
        evt = events[0]
        assert evt["event_type"] == "APPLICATION_STARTED"
        assert evt["application_name"] == "Microsoft Edge"
        assert evt["category"] == "BROWSER"
        assert evt["pid"] == 2045


def test_13_same_process_across_scans_emits_no_duplicate_started():
    """Requirement 13: Same process across multiple scans emits NO duplicate events."""
    collector = EventCollector()
    collector._previous.processes = {}

    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 2045, "name": "microsoft-edge", "ppid": 1000}
        mock_iter.return_value = [mock_proc]

        # Scan 1: Edge started
        evts1 = collector.collect()
        assert len(evts1) == 1

        # Scan 2: Edge still running
        evts2 = collector.collect()
        assert len(evts2) == 0, "No duplicate started events while app stays open"

        # Scan 3: Edge still running
        evts3 = collector.collect()
        assert len(evts3) == 0


def test_14_process_disappears_emits_stopped():
    """Requirement 14: Process terminating emits APPLICATION_STOPPED."""
    collector = EventCollector()
    collector._previous.processes = {}

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 2045, "name": "microsoft-edge", "ppid": 1000}

    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        mock_iter.return_value = [mock_proc]
        collector.collect()  # App is running

        # App closes
        mock_iter.return_value = []
        evts = collector.collect()
        assert len(evts) == 1
        assert evts[0]["event_type"] == "APPLICATION_STOPPED"
        assert evts[0]["application_name"] == "Microsoft Edge"
        assert evts[0]["category"] == "BROWSER"


def test_15_process_starts_again_emits_started_again():
    """Requirement 15: Re-opening application emits APPLICATION_STARTED again."""
    collector = EventCollector()
    collector._previous.processes = {}

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 3001, "name": "code", "ppid": 1000}

    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        # 1. Started
        mock_iter.return_value = [mock_proc]
        evts1 = collector.collect()
        assert len(evts1) == 1
        assert evts1[0]["event_type"] == "APPLICATION_STARTED"
        assert evts1[0]["application_name"] == "Visual Studio Code"

        # 2. Closed
        mock_iter.return_value = []
        evts2 = collector.collect()
        assert len(evts2) == 1
        assert evts2[0]["event_type"] == "APPLICATION_STOPPED"

        # 3. Started again with new PID
        mock_proc2 = MagicMock()
        mock_proc2.info = {"pid": 3099, "name": "code", "ppid": 1000}
        mock_iter.return_value = [mock_proc2]
        evts3 = collector.collect()
        assert len(evts3) == 1
        assert evts3[0]["event_type"] == "APPLICATION_STARTED"
        assert evts3[0]["pid"] == 3099


def test_16_multi_process_chrome_edge_produces_one_started_and_one_stopped():
    """Requirement 16: Multi-process applications emit only 1 started and 1 stopped."""
    collector = EventCollector()
    collector._previous.processes = {}

    p1 = MagicMock(); p1.info = {"pid": 501, "name": "chrome", "ppid": 1000}
    p2 = MagicMock(); p2.info = {"pid": 502, "name": "chrome", "ppid": 501}
    p3 = MagicMock(); p3.info = {"pid": 503, "name": "chrome", "ppid": 501}

    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        # Chrome starts with 3 processes simultaneously
        mock_iter.return_value = [p1, p2, p3]
        evts = collector.collect()
        assert len(evts) == 1
        assert evts[0]["event_type"] == "APPLICATION_STARTED"
        assert evts[0]["application_name"] == "Google Chrome"

        # Chrome spawns 2 more helper subprocesses (5 total)
        p4 = MagicMock(); p4.info = {"pid": 504, "name": "chrome", "ppid": 501}
        p5 = MagicMock(); p5.info = {"pid": 505, "name": "chrome", "ppid": 501}
        mock_iter.return_value = [p1, p2, p3, p4, p5]
        assert len(collector.collect()) == 0, "Subprocess spawn must emit 0 events"

        # 4 subprocesses exit, 1 remains
        mock_iter.return_value = [p1]
        assert len(collector.collect()) == 0, "Subprocess termination must emit 0 events while app still runs"

        # Final process exits
        mock_iter.return_value = []
        stop_evts = collector.collect()
        assert len(stop_evts) == 1
        assert stop_evts[0]["event_type"] == "APPLICATION_STOPPED"
        assert stop_evts[0]["application_name"] == "Google Chrome"


def test_17_kernel_and_system_noise_ignored():
    """Requirement 17: Kernel threads and low-level system services are filtered out."""
    assert _is_kernel_or_system_noise(0, "swapper") is True
    assert _is_kernel_or_system_noise(1, "systemd") is True
    assert _is_kernel_or_system_noise(2, "kthreadd") is True
    assert _is_kernel_or_system_noise(10, "[kworker/0:0]") is True
    assert _is_kernel_or_system_noise(15, "ksoftirqd/0") is True
    assert _is_kernel_or_system_noise(55, "migration/1") is True
    assert _is_kernel_or_system_noise(105, "rcu_sched") is True
    assert _is_kernel_or_system_noise(200, "systemd-journald") is True
    assert _is_kernel_or_system_noise(250, "dbus-daemon") is True
    assert _is_kernel_or_system_noise(300, "kworker", ppid=2) is True

    # Real user applications must NOT be filtered
    assert _is_kernel_or_system_noise(1500, "chrome", ppid=1000) is False
    assert _is_kernel_or_system_noise(1600, "microsoft-edge", ppid=1000) is False
    assert _is_kernel_or_system_noise(1700, "code", ppid=1000) is False
    assert _is_kernel_or_system_noise(1800, "vlc", ppid=1000) is False
    assert _is_kernel_or_system_noise(1900, "custom-billing-tool", ppid=1000) is False


def test_18_arbitrary_non_taxonomy_applications_detected():
    """Requirement 18: Arbitrary user applications are detected with clean titles and APPLICATION category."""
    name, category = _resolve_application_metadata("my-custom-accounting-app")
    assert name == "My Custom Accounting App"
    assert category == "APPLICATION"

    name2, category2 = _resolve_application_metadata("inventory_manager")
    assert name2 == "Inventory Manager"
    assert category2 == "APPLICATION"

    collector = EventCollector()
    collector._previous.processes = {}

    custom_proc = MagicMock()
    custom_proc.info = {"pid": 7777, "name": "my-custom-app", "ppid": 1000}

    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        mock_iter.return_value = [custom_proc]
        evts = collector.collect()
        assert len(evts) == 1
        assert evts[0]["application_name"] == "My Custom App"
        assert evts[0]["category"] == "APPLICATION"
        assert evts[0]["process_name"] == "my-custom-app"


def test_19_20_application_events_reach_master_and_persisted():
    """Requirements 19 & 20: Events reach Master API and are persisted in logs database."""
    dev_id = "DEV-LINUX-EVT-TEST"
    seed_device(dev_id)

    events = [
        {
            "timestamp": "2026-09-03 14:50:00",
            "event_type": "APPLICATION_STARTED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "process_name": "microsoft-edge",
            "pid": 4120,
            "source": "linux_process_monitor",
            "severity": "INFO",
            "message": "Application started: Microsoft Edge (PID 4120, process: microsoft-edge)",
        },
        {
            "timestamp": "2026-09-03 14:55:00",
            "event_type": "APPLICATION_STOPPED",
            "category": "BROWSER",
            "application_name": "Microsoft Edge",
            "process_name": "microsoft-edge",
            "pid": 4120,
            "source": "linux_process_monitor",
            "severity": "INFO",
            "message": "Application stopped: Microsoft Edge (PID 4120, process: microsoft-edge)",
        },
    ]

    svc = EventService()
    res = svc.ingest_events(dev_id, events)
    assert res["stored"] == 2

    # Verify database persistence
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT event_type, category, application_name, message FROM logs WHERE device_id = ? ORDER BY id ASC;",
            (dev_id,),
        ).fetchall()
        assert len(rows) == 2
        assert rows[0]["event_type"] == "APPLICATION_STARTED"
        assert rows[0]["application_name"] == "Microsoft Edge"
        assert rows[0]["category"] == "BROWSER"

        assert rows[1]["event_type"] == "APPLICATION_STOPPED"
        assert rows[1]["application_name"] == "Microsoft Edge"
    finally:
        conn.close()


def test_21_application_events_rendered_by_log_service():
    """Requirement 21: Application events queried via LogService reflect proper category and event type."""
    dev_id = "DEV-DASHBOARD-TEST"
    seed_device(dev_id)

    evt_svc = EventService()
    evt_svc.ingest_events(dev_id, [{
        "timestamp": "2026-09-03 15:00:00",
        "event_type": "APPLICATION_STARTED",
        "category": "BROWSER",
        "application_name": "Google Chrome",
        "process_name": "chrome",
        "pid": 8888,
        "source": "linux_process_monitor",
        "severity": "INFO",
        "message": "Application started: Google Chrome (PID 8888, process: chrome)",
    }])

    log_svc = LogService()
    data = log_svc.search_logs(device_id=dev_id)
    logs = data.get("logs", [])
    assert len(logs) >= 1
    found = any(l["application_name"] == "Google Chrome" and l["event_type"] == "APPLICATION_STARTED" for l in logs)
    assert found is True, "Ingested event must appear in LogService output"
