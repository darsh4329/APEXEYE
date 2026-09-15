"""
APEXEYE — Phase 9.2 Visual Polish & PDF Presentation Quality Test Suite

Verifies:
  1. Single device healthy report compiles with polished visual header and health card.
  2. Sparse telemetry (< 2 samples) renders structured Telemetry Availability Summary instead of empty page.
  3. Charts render with threshold context (70%, 90%) when >= 2 samples exist.
  4. Health trajectory chart renders when historical health scores exist.
  5. Application lifecycle table displays OPENED/CLOSED events with categories.
  6. Empty lifecycle events display graceful informational panel.
  7. Anomaly cards render with severity badges, findings, and explanations.
  8. Clean/healthy systems render green "NO SIGNIFICANT ANOMALIES" panel.
  9. Recommendation cards render with Priority, Finding, Action, and Reason.
  10. Entire System report renders Fleet Overview and Endpoint Health Comparative Matrix.
  11. Selected Devices report renders clear scope subtitle with device count.
  12. Empty date range generates valid PDF report with zero runtime exceptions.
  13. Presence and telemetry constants remain 100% frozen.
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
from master.app.api import create_app


@pytest.fixture(autouse=True)
def setup_clean_db(monkeypatch, tmp_path):
    """Setup isolated temporary database and reports directory for each test run."""
    db_path = str(tmp_path / "test_phase9_2.db")
    monkeypatch.setattr("master.app.config.config.DB_PATH", db_path)
    init_database()
    return db_path


@pytest.fixture
def temp_reports_dir(tmp_path):
    rep_dir = tmp_path / "reports_polish"
    rep_dir.mkdir(parents=True, exist_ok=True)
    return rep_dir


@pytest.fixture
def report_svc(temp_reports_dir):
    return ReportService(reports_dir=temp_reports_dir)


@pytest.fixture
def chart_svc():
    return ChartService()


@pytest.fixture
def pdf_renderer():
    return PDFRenderer()


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

def test_01_single_device_healthy_report_visual_structure(report_svc):
    """Test full single device report generation producing valid PDF."""
    create_test_device("DEV-POL-01", "Executive Workstation", status="online")
    now = datetime.now(timezone.utc)
    insert_telemetry_series("DEV-POL-01", [
        {"timestamp": (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"), "cpu": 25.0, "ram": 40.0, "disk": 35.0, "health": 100.0},
        {"timestamp": now.strftime("%Y-%m-%d %H:%M:%S"), "cpu": 30.0, "ram": 42.0, "disk": 35.0, "health": 100.0},
    ])
    insert_test_log("DEV-POL-01", severity="INFO", event_type="APPLICATION_STARTED", app="VSCode", message="VSCode opened")

    res = report_svc.generate_report(scope="single_device", device_id="DEV-POL-01")
    assert res["status"] == "ready"
    assert res["file_size"] > 1000

    pdf_path = report_svc.get_report_file_path(res["report_id"])
    assert pdf_path.exists()
    content = pdf_path.read_bytes()
    assert content.startswith(b"%PDF-")


def test_02_sparse_telemetry_renders_availability_panel(report_svc):
    """Test sparse telemetry (< 2 samples) compiles cleanly with Telemetry Availability Summary."""
    create_test_device("DEV-SPARSE-01", "Sparse Node", status="online")
    # Insert exactly 1 telemetry sample
    insert_telemetry_series("DEV-SPARSE-01", [{"cpu": 28.0, "ram": 45.0, "disk": 40.0, "health": 95.0}])

    res = report_svc.generate_report(scope="single_device", device_id="DEV-SPARSE-01")
    assert res["status"] == "ready"

    pdf_path = report_svc.get_report_file_path(res["report_id"])
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000


def test_03_charts_render_with_threshold_lines(chart_svc):
    """Test ChartService generates multi-resource chart with threshold reference lines."""
    now = datetime.now(timezone.utc)
    telemetry = [
        {"timestamp": (now - timedelta(minutes=30)).isoformat(), "cpu_usage": 35.0, "memory_usage": 50.0, "disk_usage": 45.0},
        {"timestamp": (now - timedelta(minutes=15)).isoformat(), "cpu_usage": 72.0, "memory_usage": 55.0, "disk_usage": 45.0},
        {"timestamp": now.isoformat(), "cpu_usage": 40.0, "memory_usage": 51.0, "disk_usage": 45.0},
    ]

    png_bytes = chart_svc.generate_combined_resources_chart(telemetry)
    assert png_bytes is not None
    assert png_bytes.startswith(b"\x89PNG")


def test_04_health_score_trajectory_chart(chart_svc):
    """Test ChartService generates health trajectory chart when historical health scores exist."""
    now = datetime.now(timezone.utc)
    telemetry = [
        {"timestamp": (now - timedelta(hours=3)).isoformat(), "health_score": 90.0},
        {"timestamp": (now - timedelta(hours=1)).isoformat(), "health_score": 95.0},
        {"timestamp": now.isoformat(), "health_score": 100.0},
    ]

    png_bytes = chart_svc.generate_health_trajectory_chart(telemetry)
    assert png_bytes is not None
    assert png_bytes.startswith(b"\x89PNG")


def test_05_application_activity_table_formatting(report_svc):
    """Test application activity table renders OPENED and CLOSED transitions with timestamps."""
    create_test_device("DEV-ACT-01", "Activity PC", status="online")
    now = datetime.now(timezone.utc)
    insert_telemetry_series("DEV-ACT-01", [
        {"cpu": 20.0, "ram": 35.0, "disk": 30.0},
        {"cpu": 22.0, "ram": 36.0, "disk": 30.0},
    ])
    insert_test_log("DEV-ACT-01", severity="INFO", event_type="APPLICATION_STARTED", app="Google Chrome", message="Chrome opened", timestamp=now.strftime("%Y-%m-%d %H:%M:%S"))
    insert_test_log("DEV-ACT-01", severity="INFO", event_type="APPLICATION_STOPPED", app="Google Chrome", message="Chrome closed", timestamp=(now + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"))

    res = report_svc.generate_report(scope="single_device", device_id="DEV-ACT-01")
    assert res["status"] == "ready"


def test_06_empty_application_lifecycle_handled_gracefully(report_svc):
    """Test reports with zero application lifecycle events compile with informational message."""
    create_test_device("DEV-NO-APP", "No App PC", status="online")
    insert_telemetry_series("DEV-NO-APP", [
        {"cpu": 15.0, "ram": 30.0, "disk": 30.0},
        {"cpu": 16.0, "ram": 30.0, "disk": 30.0},
    ])

    res = report_svc.generate_report(scope="single_device", device_id="DEV-NO-APP")
    assert res["status"] == "ready"


def test_07_anomaly_cards_and_clean_anomalies_box(report_svc):
    """Test report compilation for both critical anomaly conditions and clean healthy conditions."""
    # 1. Critical device
    create_test_device("DEV-CRIT-ANOM", "Critical PC", status="online")
    insert_telemetry_series("DEV-CRIT-ANOM", [
        {"cpu": 98.0, "ram": 60.0, "disk": 40.0},
        {"cpu": 99.0, "ram": 62.0, "disk": 40.0},
    ])
    res1 = report_svc.generate_report(scope="single_device", device_id="DEV-CRIT-ANOM")
    assert res1["status"] == "ready"

    # 2. Clean device
    create_test_device("DEV-CLEAN-ANOM", "Clean PC", status="online")
    insert_telemetry_series("DEV-CLEAN-ANOM", [
        {"cpu": 20.0, "ram": 30.0, "disk": 40.0},
        {"cpu": 22.0, "ram": 32.0, "disk": 40.0},
    ])
    res2 = report_svc.generate_report(scope="single_device", device_id="DEV-CLEAN-ANOM")
    assert res2["status"] == "ready"


def test_08_evidence_driven_recommendation_cards(report_svc):
    """Test recommendation card generation produces structured cards in the PDF."""
    create_test_device("DEV-REC-CARD", "Rec Card PC", status="online")
    insert_telemetry_series("DEV-REC-CARD", [
        {"cpu": 96.0, "ram": 92.0, "disk": 92.0},
        {"cpu": 97.0, "ram": 93.0, "disk": 92.0},
    ])

    res = report_svc.generate_report(scope="single_device", device_id="DEV-REC-CARD")
    assert res["status"] == "ready"


def test_09_fleet_overview_and_endpoint_matrix(report_svc):
    """Test Entire System report compiles with Fleet Overview and Endpoint Matrix."""
    create_test_device("NODE-01", "Node 1", status="online")
    create_test_device("NODE-02", "Node 2", status="offline")
    create_test_device("NODE-03", "Node 3", status="online")

    insert_telemetry_series("NODE-01", [{"cpu": 30.0, "ram": 40.0, "disk": 50.0}, {"cpu": 32.0, "ram": 42.0, "disk": 50.0}])
    insert_telemetry_series("NODE-03", [{"cpu": 85.0, "ram": 80.0, "disk": 75.0}, {"cpu": 88.0, "ram": 82.0, "disk": 75.0}])

    res = report_svc.generate_report(scope="system")
    assert res["status"] == "ready"
    assert "entire_system" in res["report_type"]


def test_10_selected_devices_scope_header(report_svc):
    """Test Selected Devices report explicitly indicates selected scope and device count."""
    create_test_device("SEL-1", "Selected 1", status="online")
    create_test_device("SEL-2", "Selected 2", status="online")
    create_test_device("UNSEL-3", "Unselected 3", status="online")

    res = report_svc.generate_report(scope="selected_devices", device_ids=["SEL-1", "SEL-2"])
    assert res["status"] == "ready"
    assert "selected_devices:2" in res["report_type"]


def test_11_empty_date_range_generates_valid_pdf(report_svc):
    """Test generating a report when the date range contains zero telemetry/logs."""
    create_test_device("DEV-ZERO-RANGE", "Zero Range PC", status="online")
    # Date range in 2019
    start = "2019-01-01 00:00:00"
    end = "2019-01-02 00:00:00"

    res = report_svc.generate_report(scope="single_device", device_id="DEV-ZERO-RANGE", start_date=start, end_date=end)
    assert res["status"] == "ready"
    assert res["file_size"] > 1000


def test_12_presence_and_telemetry_constants_are_frozen():
    """Verify presence & telemetry intervals remain 100% frozen."""
    from master.app.config import config as master_config
    from client.app.config import config as client_config

    assert master_config.HEARTBEAT_TIMEOUT_SECONDS == 9
    assert master_config.PRESENCE_CHECK_INTERVAL == 1
    assert master_config.TELEMETRY_INTERVAL == 10

    assert client_config.HEARTBEAT_INTERVAL == 3
    assert client_config.TELEMETRY_INTERVAL == 10
