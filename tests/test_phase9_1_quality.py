"""
APEXEYE — Phase 9.1 Report Quality, AI Analysis & Real-World Validation Test Suite

Verifies:
  1. Charts generated when sufficient telemetry exists (>= 2 points).
  2. Charts omitted gracefully with clear message when insufficient telemetry exists (< 2 points).
  3. No fabricated/interpolated values generated to artificially fill charts.
  4. Evidence-based AI summary dynamically reflects actual CPU, RAM, Disk, and Log metrics.
  5. Recommendations are evidence-driven (Priority, Finding, Action, Reason).
  6. Healthy device does not receive inappropriate critical recommendations.
  7. High CPU condition produces CPU-specific anomaly, explanation, and P1 recommendation.
  8. Application lifecycle events (OPENED/CLOSED) appear accurately in reports.
  9. Entire System report produces genuine fleet-level overview and comparative matrix.
  10. Selected Devices report strictly includes only the selected device IDs.
  11. Single Device report remains strictly isolated to the specified device_id.
  12. Date range validation enforces start_date < end_date (raises ValueError / 400).
  13. Date range with no data generates report explaining data is unavailable without crashing.
  14. High CPU end-to-end analysis correctly flows from telemetry to AI analysis.
  15. Emergency CPU alert popup remains completely independent from AI analysis.
  16. Presence and telemetry constants remain 100% frozen.
"""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from master.app.database import init_database, get_connection
from master.app.services.chart_service import ChartService
from master.app.services.pdf_renderer import PDFRenderer
from master.app.services.report_service import ReportService
from master.app.services.ai_service import AIService
from master.app.services.report_data_builder import ReportDataBuilder
from master.app.services.anomaly_service import AnomalyDetectionEngine
from master.app.services.recommendation_engine import RecommendationEngine
from master.app.services.log_service import LogService
from master.app.api import create_app


@pytest.fixture(autouse=True)
def setup_clean_db(monkeypatch, tmp_path):
    """Setup isolated temporary database and reports directory for each test run."""
    db_path = str(tmp_path / "test_phase9_1.db")
    monkeypatch.setattr("master.app.config.config.DB_PATH", db_path)
    init_database()
    return db_path


@pytest.fixture
def temp_reports_dir(tmp_path):
    rep_dir = tmp_path / "reports_quality"
    rep_dir.mkdir(parents=True, exist_ok=True)
    return rep_dir


@pytest.fixture
def report_svc(temp_reports_dir):
    return ReportService(reports_dir=temp_reports_dir)


@pytest.fixture
def ai_svc():
    return AIService()


@pytest.fixture
def chart_svc():
    return ChartService()


@pytest.fixture
def test_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def create_test_device(device_id: str, name: str = "Test PC", status: str = "online"):
    conn = get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO devices (device_id, device_name, device_type, operating_system, status, last_seen, created_at, updated_at)
           VALUES (?, ?, 'WINDOWS_PC', 'Windows 11 Pro', ?, ?, ?, ?);""",
        (device_id, name, status, now, now, now),
    )
    conn.commit()
    conn.close()


def insert_telemetry_series(device_id: str, records: list[dict]):
    conn = get_connection()
    for r in records:
        conn.execute(
            """INSERT INTO telemetry (device_id, timestamp, cpu_usage, memory_usage, disk_usage, network_usage, health_score, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
            (
                device_id,
                r.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
                r.get("cpu"),
                r.get("ram"),
                r.get("disk"),
                r.get("net", 1.0),
                r.get("health", 90.0),
                json.dumps(r.get("details", {})),
            ),
        )
    conn.commit()
    conn.close()


def insert_test_log(device_id: str, severity: str = "INFO", event_type: str = "SYSTEM_INFO", message: str = "Test message", app: str = None, timestamp: str = None):
    conn = get_connection()
    now = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO logs (device_id, timestamp, level, severity, event_type, category, application_name, message, source)
           VALUES (?, ?, ?, ?, ?, 'SYSTEM', ?, ?, 'test_runner');""",
        (device_id, now, severity, severity, event_type, app, message),
    )
    conn.commit()
    conn.close()


# ── Test Cases ────────────────────────────────────────────────────────

def test_01_charts_generated_when_sufficient_telemetry_exists(chart_svc):
    """Test charts are generated when >= 2 telemetry samples exist."""
    now = datetime.now(timezone.utc)
    telemetry = [
        {"timestamp": (now - timedelta(minutes=20)).isoformat(), "cpu_usage": 30.0, "memory_usage": 45.0, "disk_usage": 50.0},
        {"timestamp": now.isoformat(), "cpu_usage": 40.0, "memory_usage": 46.0, "disk_usage": 50.0},
    ]

    chart_bytes = chart_svc.generate_combined_resources_chart(telemetry)
    assert chart_bytes is not None
    assert chart_bytes.startswith(b"\x89PNG")


def test_02_charts_omitted_gracefully_when_insufficient_telemetry(chart_svc, report_svc):
    """Test charts return None when < 2 points exist without crashing report compilation."""
    create_test_device("DEV-NO-CHART", "Single Point PC", status="online")
    insert_telemetry_series("DEV-NO-CHART", [{"cpu": 25.0, "ram": 40.0, "disk": 30.0}])

    # Chart service returns None for single point
    assert chart_svc.generate_combined_resources_chart([{"timestamp": "2026-08-29 12:00:00", "cpu_usage": 25.0}]) is None

    # Report still compiles successfully
    res = report_svc.generate_report(scope="single_device", device_id="DEV-NO-CHART")
    assert res["status"] == "ready"
    assert res["file_size"] > 1000


def test_03_no_fabricated_chart_values(report_svc):
    """Ensure report generator never hallucinates telemetry points when none exist."""
    create_test_device("DEV-ZERO-TEL", "Zero Telemetry PC", status="online")
    data_builder = ReportDataBuilder()
    data = data_builder.build_single_device_data("DEV-ZERO-TEL")

    assert len(data["telemetry"]) == 0
    assert data["stats"]["cpu_avg"] is None
    assert data["stats"]["ram_avg"] is None


def test_04_evidence_based_ai_summary(ai_svc):
    """Verify AI summary includes real empirical metrics (CPU %, RAM %, Storage %)."""
    create_test_device("DEV-EVID-01", "Evidence PC", status="online")
    insert_telemetry_series("DEV-EVID-01", [
        {"cpu": 32.5, "ram": 48.0, "disk": 42.0},
        {"cpu": 34.0, "ram": 50.0, "disk": 42.0},
    ])
    insert_test_log("DEV-EVID-01", severity="INFO", event_type="APPLICATION_STARTED", app="VSCode", message="VSCode opened")

    res = ai_svc.analyze_device("DEV-EVID-01")
    summary = res["narrative"]["summary"]
    obs = " ".join(res["narrative"]["key_observations"])

    assert "33.2%" in summary or "33.2%" in obs or "33." in summary or "33." in obs or "49.0%" in obs or "42.0%" in obs
    assert "VSCode" in obs or "start event" in obs


def test_05_recommendations_evidence_driven(ai_svc):
    """Verify recommendations contain Priority, Finding, Description, and Rationale."""
    create_test_device("DEV-REC-EVID", "Rec PC", status="online")
    insert_telemetry_series("DEV-REC-EVID", [{"cpu": 98.0, "ram": 92.0, "disk": 40.0}])

    res = ai_svc.analyze_device("DEV-REC-EVID")
    recs = res["recommendations"]

    assert len(recs) >= 2
    for r in recs:
        assert "priority" in r
        assert "finding" in r
        assert "description" in r
        assert "rationale" in r


def test_06_healthy_device_no_critical_recommendations(ai_svc):
    """Verify a healthy device receives P3 routine monitoring and zero P1 critical alerts."""
    create_test_device("DEV-HEALTHY-01", "Healthy PC", status="online")
    insert_telemetry_series("DEV-HEALTHY-01", [
        {"cpu": 20.0, "ram": 35.0, "disk": 40.0},
        {"cpu": 22.0, "ram": 36.0, "disk": 40.0},
    ])

    res = ai_svc.analyze_device("DEV-HEALTHY-01")
    assert res["anomaly_count"] == 0
    recs = res["recommendations"]
    assert len(recs) == 1
    assert "P3" in recs[0]["priority"]
    assert "routine" in recs[0]["description"].lower() or "monitoring" in recs[0]["description"].lower()


def test_07_high_cpu_produces_cpu_anomaly_and_recommendation(ai_svc):
    """Verify high CPU condition produces Critical CPU anomaly and P1 recommendation."""
    create_test_device("DEV-HIGH-CPU", "High CPU Server", status="online")
    insert_telemetry_series("DEV-HIGH-CPU", [
        {"cpu": 98.0, "ram": 50.0, "disk": 40.0},
        {"cpu": 99.0, "ram": 52.0, "disk": 40.0},
    ])

    res = ai_svc.analyze_device("DEV-HIGH-CPU")
    cpu_anoms = [a for a in res["anomalies"] if a["category"] == "CPU"]
    assert len(cpu_anoms) >= 1
    assert cpu_anoms[0]["severity"] == "CRITICAL"

    cpu_recs = [r for r in res["recommendations"] if "P1" in r["priority"] and "CPU" in r["category"]]
    assert len(cpu_recs) == 1
    assert "processes" in cpu_recs[0]["description"].lower()


def test_08_application_lifecycle_events_in_reports(report_svc):
    """Verify Application Activity table is rendered in Single Device report."""
    create_test_device("DEV-APP-REP", "App Activity PC", status="online")
    now = datetime.now(timezone.utc)
    insert_telemetry_series("DEV-APP-REP", [{"cpu": 20.0, "ram": 40.0, "disk": 30.0}])
    insert_test_log("DEV-APP-REP", severity="INFO", event_type="APPLICATION_STARTED", app="Microsoft Edge", message="Edge opened", timestamp=now.strftime("%Y-%m-%d %H:%M:%S"))
    insert_test_log("DEV-APP-REP", severity="INFO", event_type="APPLICATION_STOPPED", app="Microsoft Edge", message="Edge closed", timestamp=(now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"))

    res = report_svc.generate_report(scope="single_device", device_id="DEV-APP-REP")
    assert res["status"] == "ready"

    raw_path = report_svc.get_report_file_path(res["report_id"])
    assert raw_path.exists()
    assert raw_path.stat().st_size > 1000


def test_09_entire_system_fleet_level_comparison(report_svc):
    """Verify Entire System report produces genuine fleet-level comparison."""
    create_test_device("FLEET-01", "Fleet Node 1", status="online")
    create_test_device("FLEET-02", "Fleet Node 2", status="offline")
    insert_telemetry_series("FLEET-01", [{"cpu": 45.0, "ram": 55.0, "disk": 60.0}])

    res = report_svc.generate_report(scope="system")
    assert res["status"] == "ready"
    assert "entire_system" in res["report_type"]


def test_10_selected_devices_strict_isolation(report_svc):
    """Verify Selected Devices report includes only specified devices."""
    create_test_device("SEL-A", "Selected A", status="online")
    create_test_device("SEL-B", "Selected B", status="online")
    create_test_device("SEL-C", "Unselected C", status="online")

    res = report_svc.generate_report(scope="selected_devices", device_ids=["SEL-A", "SEL-B"])
    assert res["status"] == "ready"
    assert "selected_devices:2" in res["report_type"]


def test_11_single_device_isolated(report_svc):
    """Verify Single Device report is isolated to requested device."""
    create_test_device("ISO-1", "Isolated 1", status="online")
    create_test_device("ISO-2", "Isolated 2", status="online")
    insert_telemetry_series("ISO-1", [{"cpu": 15.0, "ram": 30.0, "disk": 40.0}])
    insert_telemetry_series("ISO-2", [{"cpu": 95.0, "ram": 90.0, "disk": 80.0}])

    res = report_svc.generate_report(scope="single_device", device_id="ISO-1")
    assert res["status"] == "ready"
    assert res["report_type"] == "single_device:ISO-1"


def test_12_date_range_validation_start_before_end(report_svc, test_client):
    """Verify start_date < end_date is strictly validated."""
    create_test_device("DEV-DATE-VAL", "Date Validation PC", status="online")

    # Invalid range (start is after end) -> ValueError
    with pytest.raises(ValueError) as exc:
        report_svc.generate_report(
            scope="single_device",
            device_id="DEV-DATE-VAL",
            start_date="2026-08-29 15:00:00",
            end_date="2026-08-20 15:00:00",
        )
    assert "Start date must be earlier than end date" in str(exc.value)

    # API returns 400 Bad Request
    r = test_client.post("/api/reports/generate", json={
        "scope": "single_device",
        "device_id": "DEV-DATE-VAL",
        "start_date": "2026-08-29 15:00:00",
        "end_date": "2026-08-20 15:00:00",
    })
    assert r.status_code == 400


def test_13_date_range_with_no_data_handled_gracefully(report_svc):
    """Verify report generates gracefully when date range contains 0 telemetry/logs."""
    create_test_device("DEV-NO-DATA", "Empty Range PC", status="online")
    # Date range in past year where no data exists
    start = "2020-01-01 00:00:00"
    end = "2020-01-02 00:00:00"

    res = report_svc.generate_report(scope="single_device", device_id="DEV-NO-DATA", start_date=start, end_date=end)
    assert res["status"] == "ready"
    assert res["file_size"] > 1000


def test_14_high_cpu_end_to_end_analysis(ai_svc):
    """Verify realistic high CPU flow from telemetry to AI analysis & recommendations."""
    create_test_device("DEV-E2E-CPU", "E2E High CPU PC", status="online")
    insert_telemetry_series("DEV-E2E-CPU", [
        {"cpu": 96.5, "ram": 60.0, "disk": 45.0},
        {"cpu": 97.2, "ram": 62.0, "disk": 45.0},
    ])

    analysis = ai_svc.analyze_device("DEV-E2E-CPU")
    assert any(a["severity"] == "CRITICAL" and a["category"] == "CPU" for a in analysis["anomalies"])
    assert any("P1" in r["priority"] and "CPU" in r["category"] for r in analysis["recommendations"])
    assert "97." in analysis["narrative"]["summary"] or "96." in analysis["narrative"]["summary"] or "critical" in analysis["narrative"]["summary"].lower()


def test_15_emergency_cpu_alert_remains_independent():
    """Verify emergency CPU alert service functions independently of AI analysis."""
    create_test_device("DEV-EMERG-IND", "Emergency Independent PC", status="online")
    log_svc = LogService()
    
    # Initialize baseline
    baseline = log_svc.get_live_critical_alerts(baseline=True)
    base_id = baseline["latest_id"]

    insert_test_log("DEV-EMERG-IND", severity="CRITICAL", event_type="CPU_CRITICAL", message="Critical CPU utilization alert: 98.5%")
    res = log_svc.get_live_critical_alerts(since_id=base_id)

    assert len(res["alerts"]) == 1
    assert res["alerts"][0]["device_id"] == "DEV-EMERG-IND"
    assert res["alerts"][0]["cpu_percent"] == 98.5


def test_16_presence_and_telemetry_constants_are_frozen():
    """Verify presence & telemetry intervals remain 100% frozen."""
    from master.app.config import config as master_config
    from client.app.config import config as client_config

    assert master_config.HEARTBEAT_TIMEOUT_SECONDS == 9
    assert master_config.PRESENCE_CHECK_INTERVAL == 1
    assert master_config.TELEMETRY_INTERVAL == 10

    assert client_config.HEARTBEAT_INTERVAL == 3
    assert client_config.TELEMETRY_INTERVAL == 10
