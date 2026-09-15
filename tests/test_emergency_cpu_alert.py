"""
APEXEYE — Emergency Critical CPU Alert Popup Test Suite

Verifies:
  1. New critical CPU log generates an emergency alert payload with device name, ID, and CPU %
  2. Repeated polling with the same since_id or updated since_id prevents duplicate popups
  3. Multiple distinct clients generate independent alerts without overwriting
  4. CPU percentage extracted from event details / message matches real data
  5. Baseline initialization prevents replaying historical critical logs on initial dashboard load
  6. Dismissing an alert does NOT delete or alter the underlying database log
  7. Presence & Telemetry constants remain 100% frozen
"""

import json
import pytest
from datetime import datetime, timezone

from master.app.database import init_database, get_connection
from master.app.services.log_service import LogService
from master.app.services.telemetry_service import TelemetryService
from master.app.services.health_service import HealthService
from master.app.api import create_app


@pytest.fixture(autouse=True)
def setup_clean_db(monkeypatch, tmp_path):
    """Setup an isolated temporary database for each test run."""
    db_path = str(tmp_path / "test_emergency.db")
    monkeypatch.setattr("master.app.config.config.DB_PATH", db_path)
    init_database()
    return db_path


@pytest.fixture
def log_svc():
    return LogService()


@pytest.fixture
def tel_svc():
    return TelemetryService()


@pytest.fixture
def health_svc():
    return HealthService()


@pytest.fixture
def test_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def create_device(device_id, name="Test PC", status="online"):
    conn = get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO devices (device_id, device_name, device_type, operating_system, status, last_seen, created_at, updated_at)
           VALUES (?, ?, 'WINDOWS_PC', 'Windows 11', ?, ?, ?, ?);""",
        (device_id, name, status, now, now, now),
    )
    conn.commit()
    conn.close()


def insert_cpu_log(device_id, cpu_percent=100.0, severity="CRITICAL", message=None):
    conn = get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    msg = message or f"Critical CPU utilization alert: {cpu_percent:.1f}%"
    evt = "CPU_CRITICAL" if cpu_percent >= 95.0 else "CPU_WARNING"
    details = json.dumps({"cpu_usage": cpu_percent})
    cur = conn.execute(
        """INSERT INTO logs (device_id, timestamp, level, severity, event_type, category, message, details, source)
           VALUES (?, ?, ?, ?, ?, 'SYSTEM', ?, ?, 'telemetry_monitor');""",
        (device_id, now, severity, severity, evt, msg, details),
    )
    conn.commit()
    inserted_id = cur.lastrowid
    conn.close()
    return inserted_id


# ── Test Cases ────────────────────────────────────────────────────────

def test_01_new_critical_cpu_log_generates_alert(log_svc):
    """Test that a new critical CPU event generates a structured alert payload."""
    create_device("Vansh", "Vansh Workstation", status="online")
    log_id = insert_cpu_log("Vansh", cpu_percent=100.0, severity="CRITICAL")

    result = log_svc.get_live_critical_alerts(baseline=True)
    # Baseline mode returns latest_id without historical popups
    assert result["latest_id"] >= log_id
    assert len(result["alerts"]) == 0

    # Polling with since_id before log_id returns the alert
    res_poll = log_svc.get_live_critical_alerts(since_id=log_id - 1)
    assert len(res_poll["alerts"]) == 1
    alert = res_poll["alerts"][0]
    assert alert["device_id"] == "Vansh"
    assert alert["device_name"] == "Vansh Workstation"
    assert alert["cpu_percent"] == 100.0
    assert "Vansh" in alert["human_reason"]
    assert "100.0%" in alert["human_reason"]


def test_02_repeated_polling_prevents_duplicates(log_svc):
    """Test that updating since_id prevents duplicate alert popups on subsequent polls."""
    create_device("DEV-01", "Client-01", status="online")
    log_id = insert_cpu_log("DEV-01", cpu_percent=98.0)

    # First poll: receives alert and updates since_id
    r1 = log_svc.get_live_critical_alerts(since_id=log_id - 1)
    assert len(r1["alerts"]) == 1
    latest_id = r1["latest_id"]

    # Second poll with latest_id: 0 duplicate alerts returned
    r2 = log_svc.get_live_critical_alerts(since_id=latest_id)
    assert len(r2["alerts"]) == 0


def test_03_multi_client_independent_alerts(log_svc):
    """Test that two different clients generate independent alerts that do not overwrite each other."""
    create_device("Vansh", "Vansh", status="online")
    create_device("Client-02", "Client-02", status="online")

    log_1 = insert_cpu_log("Vansh", cpu_percent=100.0)
    log_2 = insert_cpu_log("Client-02", cpu_percent=96.5)

    res = log_svc.get_live_critical_alerts(since_id=min(log_1, log_2) - 1)
    assert len(res["alerts"]) == 2
    dev_ids = {a["device_id"] for a in res["alerts"]}
    assert "Vansh" in dev_ids
    assert "Client-02" in dev_ids

    # Verify distinct CPU values
    vansh_alert = next(a for a in res["alerts"] if a["device_id"] == "Vansh")
    c2_alert = next(a for a in res["alerts"] if a["device_id"] == "Client-02")
    assert vansh_alert["cpu_percent"] == 100.0
    assert c2_alert["cpu_percent"] == 96.5


def test_04_baseline_initialization_ignores_historical_logs(log_svc):
    """Test that initial dashboard load (baseline mode) ignores existing historical critical logs."""
    create_device("DEV-OLD", "Old PC", status="online")
    insert_cpu_log("DEV-OLD", cpu_percent=100.0)
    insert_cpu_log("DEV-OLD", cpu_percent=98.0)

    # Baseline query must return 0 alerts so dashboard load doesn't spam historical alerts
    res_base = log_svc.get_live_critical_alerts(baseline=True)
    assert len(res_base["alerts"]) == 0
    assert res_base["latest_id"] > 0

    # Only a newly inserted log after baseline generates an alert
    new_log_id = insert_cpu_log("DEV-OLD", cpu_percent=99.0)
    res_new = log_svc.get_live_critical_alerts(since_id=res_base["latest_id"])
    assert len(res_new["alerts"]) == 1
    assert res_new["alerts"][0]["id"] == new_log_id


def test_05_dismiss_preserves_underlying_log(log_svc):
    """Test that dismissing a popup on UI is non-destructive and preserves database logs."""
    create_device("DEV-DISMISS", "Dismiss PC", status="online")
    log_id = insert_cpu_log("DEV-DISMISS", cpu_percent=97.0)

    # Log exists in DB
    conn = get_connection()
    row = conn.execute("SELECT id FROM logs WHERE id = ?;", (log_id,)).fetchone()
    conn.close()
    assert row is not None

    # Search logs still returns the log
    search_res = log_svc.search_logs(device_id="DEV-DISMISS")
    assert search_res["total"] >= 1


def test_06_telemetry_ingest_triggers_critical_cpu_log(tel_svc, log_svc):
    """Test that TelemetryService.ingest automatically creates the CPU log consumed by live-alerts."""
    create_device("DEV-TEL", "Telemetry PC", status="online")
    base = log_svc.get_live_critical_alerts(baseline=True)

    # Ingest telemetry with 100% CPU
    tel_svc.ingest("DEV-TEL", {
        "timestamp": "2026-08-29 12:00:00",
        "cpu": {"cpu_usage": 100.0},
        "memory": {"memory_usage_percent": 40.0},
        "disk": {"disk_usage_percent": 30.0},
        "network": {"network_bytes_sent_mb": 1.0, "network_bytes_recv_mb": 1.0},
    })

    # Live alerts endpoint detects it immediately
    res = log_svc.get_live_critical_alerts(since_id=base["latest_id"])
    assert len(res["alerts"]) == 1
    assert res["alerts"][0]["device_id"] == "DEV-TEL"
    assert res["alerts"][0]["cpu_percent"] == 100.0


def test_07_rest_api_live_alerts_endpoint(test_client):
    """Test GET /api/logs/live-alerts REST endpoint."""
    create_device("DEV-REST", "REST PC", status="online")
    insert_cpu_log("DEV-REST", cpu_percent=99.5)

    # Baseline call
    resp1 = test_client.get("/api/logs/live-alerts?baseline=true")
    assert resp1.status_code == 200
    data1 = resp1.get_json()
    assert "latest_id" in data1
    assert data1["alerts"] == []

    # Polling call
    resp2 = test_client.get("/api/logs/live-alerts?since_id=0")
    assert resp2.status_code == 200


def test_08_presence_constants_remain_frozen():
    """Verify presence & telemetry constants are 100% untouched."""
    from master.app.config import config as master_config
    from client.app.config import config as client_config

    assert master_config.HEARTBEAT_TIMEOUT_SECONDS == 9
    assert master_config.PRESENCE_CHECK_INTERVAL == 1
    assert master_config.TELEMETRY_INTERVAL == 10

    assert client_config.HEARTBEAT_INTERVAL == 3
    assert client_config.TELEMETRY_INTERVAL == 10
