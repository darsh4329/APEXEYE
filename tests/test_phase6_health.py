"""
APEXEYE — Phase 6 Health Score & Alert Assessment Test Suite

Tests:
  1. Score boundary calculations (100, 80, 79, 50, 49, 0)
  2. Resource evaluation brackets (CPU, RAM, Disk at <70%, 70-85%, 85-95%, >95%)
  3. Log health evaluation, recency decay, and single-event cliff prevention
  4. Mandatory Offline Device Override (capped at <=49, CRITICAL status, explicit offline explanation)
  5. Strict Per-Client Data Isolation (Client A logs/telemetry do NOT affect Client B)
  6. Missing telemetry handling (clean N/A, zero fabricated values)
  7. Thermal sensor reporting (real data if available, explicit 'Not available' otherwise)
  8. Alert generation, deduplication, and lifecycle resolution
  9. Health REST API Endpoints (GET /health, POST /health/check, GET /trend, GET /summary)
 10. Presence & Telemetry Frozen Safety Verification
"""

import json
import pytest
from datetime import datetime, timezone, timedelta

from master.app.database import init_database, get_connection
from master.app.services.health_service import HealthService
from master.app.services.alert_service import AlertService
from master.app.services.telemetry_service import TelemetryService
from master.app.services.device_service import DeviceService
from master.app.api import create_app
from master.app.auth import AuthService


@pytest.fixture(autouse=True)
def setup_clean_db(monkeypatch, tmp_path):
    """Setup an isolated temporary database for each test run."""
    db_path = str(tmp_path / "test_health.db")
    monkeypatch.setattr("master.app.config.config.DB_PATH", db_path)
    init_database()
    return db_path


@pytest.fixture
def health_svc():
    return HealthService()


@pytest.fixture
def alert_svc():
    return AlertService()


@pytest.fixture
def test_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def admin_headers():
    auth = AuthService()
    token = auth.generate_jwt("admin_test", role="admin")
    return {"Authorization": f"Bearer {token}"}


# ── Helper Functions ──────────────────────────────────────────────────

def create_test_device(device_id="DEV-001", name="Workstation 1", status="online"):
    conn = get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO devices (device_id, device_name, device_type, operating_system, status, last_seen, created_at, updated_at)
           VALUES (?, ?, 'WINDOWS_PC', 'Windows 11', ?, ?, ?, ?);""",
        (device_id, name, status, now, now, now),
    )
    conn.commit()
    conn.close()


def insert_telemetry(device_id, cpu=25.0, ram=45.0, disk=50.0, net_sent=10.0, net_recv=20.0, details=None):
    conn = get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    details_json = json.dumps(details) if details else "{}"
    conn.execute(
        """INSERT INTO telemetry (device_id, timestamp, cpu_usage, memory_usage, disk_usage,
                                  network_bytes_sent_mb, network_bytes_recv_mb, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
        (device_id, now, cpu, ram, disk, net_sent, net_recv, details_json),
    )
    conn.commit()
    conn.close()


def insert_log(device_id, severity="INFO", message="Event", hours_ago=0):
    conn = get_connection()
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO logs (device_id, timestamp, level, severity, event_type, category, message, source)
           VALUES (?, ?, ?, ?, 'EVENT', 'SYSTEM', ?, 'agent');""",
        (device_id, ts, severity, severity, message),
    )
    conn.commit()
    conn.close()


# ── Test Suite ────────────────────────────────────────────────────────

def test_perfect_healthy_device_score_is_good(health_svc):
    """Test a fully healthy online device achieves a GOOD score (>=80, close to 100)."""
    create_test_device("DEV-GOOD", "Healthy PC", status="online")
    insert_telemetry("DEV-GOOD", cpu=15.0, ram=35.0, disk=40.0)

    result = health_svc.evaluate_device_health("DEV-GOOD")
    assert result is not None
    assert result["status"] == "GOOD"
    assert result["score"] >= 80
    assert result["score"] <= 100
    assert result["is_online"] is True
    assert "🟢" in result["status_badge"]
    assert any("operating normally" in exp["text"].lower() or "healthy" in exp["text"].lower() for exp in result["explanations"])


def test_resource_warning_bracket_produces_warning(health_svc):
    """Test elevated CPU and RAM (70-85%) lowers health score into WARNING band (50-79)."""
    create_test_device("DEV-WARN", "Busy PC", status="online")
    insert_telemetry("DEV-WARN", cpu=78.0, ram=82.0, disk=76.0)

    result = health_svc.evaluate_device_health("DEV-WARN")
    assert result is not None
    assert result["status"] == "WARNING"
    assert 50 <= result["score"] <= 79
    assert result["components"]["resources"]["cpu"]["status"] == "WARNING"
    assert result["components"]["resources"]["ram"]["status"] == "WARNING"


def test_critical_resource_saturation_produces_critical(health_svc):
    """Test critical resource saturation (>95% CPU, RAM, Disk) drops score to CRITICAL (0-49)."""
    create_test_device("DEV-CRIT", "Saturated PC", status="online")
    insert_telemetry("DEV-CRIT", cpu=98.0, ram=97.0, disk=96.0)

    result = health_svc.evaluate_device_health("DEV-CRIT")
    assert result is not None
    assert result["status"] == "CRITICAL"
    assert result["score"] < 50
    assert result["components"]["resources"]["cpu"]["status"] == "CRITICAL"
    assert result["components"]["resources"]["ram"]["status"] == "CRITICAL"


def test_mandatory_offline_device_override(health_svc):
    """
    MANDATORY CORRECTION TEST:
    If a device is OFFLINE, regardless of healthy historical resources:
      - Score must be capped at <= 49.
      - Final status must be CRITICAL.
      - Explanation must explicitly say '🔴 Device is currently offline.'
    """
    create_test_device("DEV-OFFLINE", "Offline Laptop", status="offline")
    # Perfectly healthy historical metrics
    insert_telemetry("DEV-OFFLINE", cpu=10.0, ram=20.0, disk=30.0)

    result = health_svc.evaluate_device_health("DEV-OFFLINE")
    assert result is not None
    assert result["is_online"] is False
    assert result["status"] == "CRITICAL"
    assert result["score"] <= 49
    # Check explicit offline explanation
    offline_explanations = [e["text"] for e in result["explanations"] if "offline" in e["text"].lower()]
    assert len(offline_explanations) > 0
    assert "🔴 Device is currently offline." in offline_explanations[0]


def test_log_health_recency_and_cliff_prevention(health_svc):
    """
    Test log health degradation with recency weighting and protection against single-event score cliff.
    """
    create_test_device("DEV-LOGS", "Log Test PC", status="online")
    insert_telemetry("DEV-LOGS", cpu=20.0, ram=30.0, disk=30.0)

    # 1 single isolated warning should NOT drop the system to CRITICAL or 0
    insert_log("DEV-LOGS", severity="WARNING", message="Minor network retry", hours_ago=0.5)
    r1 = health_svc.evaluate_device_health("DEV-LOGS")
    assert r1["status"] == "GOOD"  # Still healthy overall
    assert r1["components"]["logs"]["score"] >= 90

    # Multiple critical logs reduce log score proportionally
    insert_log("DEV-LOGS", severity="CRITICAL", message="Database socket failure", hours_ago=0.2)
    insert_log("DEV-LOGS", severity="CRITICAL", message="Process kernel panic", hours_ago=0.3)
    r2 = health_svc.evaluate_device_health("DEV-LOGS")
    assert r2["components"]["logs"]["critical_24h"] == 2
    assert r2["components"]["logs"]["score"] < 70


def test_strict_per_client_data_isolation(health_svc):
    """
    Test that Client A's logs and telemetry never bleed into or contaminate Client B's health assessment.
    """
    create_test_device("CLIENT-A", "Client Alpha", status="online")
    create_test_device("CLIENT-B", "Client Beta", status="online")

    # Client A: Healthy telemetry and clean logs
    insert_telemetry("CLIENT-A", cpu=15.0, ram=25.0, disk=30.0)
    insert_log("CLIENT-A", severity="INFO", message="Application started")

    # Client B: Severely degraded telemetry and critical error logs
    insert_telemetry("CLIENT-B", cpu=96.0, ram=95.0, disk=94.0)
    for i in range(5):
        insert_log("CLIENT-B", severity="CRITICAL", message=f"Fatal fault {i}")

    eval_a = health_svc.evaluate_device_health("CLIENT-A")
    eval_b = health_svc.evaluate_device_health("CLIENT-B")

    # Client A must remain GOOD with 0 critical logs
    assert eval_a["status"] == "GOOD"
    assert eval_a["score"] >= 80
    assert eval_a["components"]["logs"]["critical_24h"] == 0

    # Client B must be CRITICAL with 5 critical logs
    assert eval_b["status"] == "CRITICAL"
    assert eval_b["score"] < 50
    assert eval_b["components"]["logs"]["critical_24h"] == 5


def test_missing_telemetry_handling_no_fake_values(health_svc):
    """Test brand new device without telemetry reports data unavailable without fake numbers."""
    create_test_device("DEV-EMPTY", "Brand New PC", status="online")

    result = health_svc.evaluate_device_health("DEV-EMPTY")
    assert result is not None
    res = result["components"]["resources"]
    assert res["available"] is False
    assert res["cpu"]["usage"] is None
    assert res["cpu"]["display"] == "Data unavailable"
    assert res["ram"]["usage"] is None
    assert res["storage"]["usage"] is None


def test_thermal_telemetry_reporting(health_svc):
    """Test thermal data: real temperature if provided, 'Not available' otherwise."""
    create_test_device("DEV-THERM", "Sensor PC", status="online")

    # Case 1: No thermal data in telemetry details
    insert_telemetry("DEV-THERM", cpu=30.0, details={})
    r1 = health_svc.evaluate_device_health("DEV-THERM")
    assert r1["components"]["thermal"]["available"] is False
    assert "Not available" in r1["components"]["thermal"]["display"]

    # Case 2: Real thermal data present in details
    insert_telemetry("DEV-THERM", cpu=30.0, details={"temperature": 48.5})
    r2 = health_svc.evaluate_device_health("DEV-THERM")
    assert r2["components"]["thermal"]["available"] is True
    assert r2["components"]["thermal"]["temperature_c"] == 48.5
    assert "48.5°C" in r2["components"]["thermal"]["display"]


def test_alert_deduplication_and_resolution(alert_svc, health_svc):
    """Test persistent condition generates 1 open alert in DB without duplicate spam."""
    create_test_device("DEV-ALERT", "Alert Test PC", status="online")
    insert_telemetry("DEV-ALERT", cpu=98.0, ram=40.0, disk=40.0)

    # Initial evaluation creates 1 open alert
    h1 = health_svc.evaluate_device_health("DEV-ALERT", persist_alerts=True)
    assert h1["alerts_count"] >= 1
    open_alerts1 = alert_svc.get_open_alerts("DEV-ALERT")
    assert len(open_alerts1) == 1
    alert_id = open_alerts1[0]["id"]

    # Subsequent evaluation with the SAME persistent condition must NOT create a duplicate alert row
    h2 = health_svc.evaluate_device_health("DEV-ALERT", persist_alerts=True)
    open_alerts2 = alert_svc.get_open_alerts("DEV-ALERT")
    assert len(open_alerts2) == 1
    assert open_alerts2[0]["id"] == alert_id

    # Condition clears (CPU drops to 20%) -> Alert auto-resolves to 'resolved'
    insert_telemetry("DEV-ALERT", cpu=20.0, ram=40.0, disk=40.0)
    h3 = health_svc.evaluate_device_health("DEV-ALERT", persist_alerts=True)
    open_alerts3 = alert_svc.get_open_alerts("DEV-ALERT")
    assert len(open_alerts3) == 0  # Resolved


def test_health_rest_api_endpoints(test_client):
    """Test GET /api/devices/<id>/health and POST /api/devices/<id>/health/check."""
    create_test_device("DEV-API", "API Test PC", status="online")
    insert_telemetry("DEV-API", cpu=22.0, ram=44.0, disk=50.0)

    # 1. GET /api/devices/<id>/health
    res1 = test_client.get("/api/devices/DEV-API/health")
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1["device_id"] == "DEV-API"
    assert data1["status"] == "GOOD"
    assert "components" in data1
    assert "explanations" in data1

    # 2. POST /api/devices/<id>/health/check
    res2 = test_client.post("/api/devices/DEV-API/health/check")
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2["device_id"] == "DEV-API"

    # 3. GET /api/devices/<id>/health/trend
    res3 = test_client.get("/api/devices/DEV-API/health/trend")
    assert res3.status_code == 200
    data3 = res3.get_json()
    assert data3["device_id"] == "DEV-API"
    assert "trend" in data3

    # 4. GET /api/devices/health/summary
    res4 = test_client.get("/api/devices/health/summary")
    assert res4.status_code == 200
    data4 = res4.get_json()
    assert data4["total_devices"] >= 1
    assert data4["good_count"] >= 1


def test_presence_and_telemetry_constants_are_frozen():
    """Safety test to verify presence & telemetry intervals remain frozen."""
    from master.app.config import config as master_config
    from client.app.config import config as client_config

    # Presence constants MUST remain:
    assert master_config.HEARTBEAT_TIMEOUT_SECONDS == 9
    assert master_config.PRESENCE_CHECK_INTERVAL == 1
    assert master_config.TELEMETRY_INTERVAL == 10

    # Client constants MUST remain:
    assert client_config.HEARTBEAT_INTERVAL == 3
    assert client_config.TELEMETRY_INTERVAL == 10
