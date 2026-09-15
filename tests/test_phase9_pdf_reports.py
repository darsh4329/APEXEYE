"""
APEXEYE — Phase 9 PDF Reports Generation Test Suite

Verifies:
  1. ChartService generation (headless Agg backend, valid PNG headers)
  2. Single device PDF compilation (multi-page ReportLab, %PDF-1.4 header)
  3. Selected devices PDF compilation
  4. Entire system fleet PDF compilation
  5. Date range validation and custom window filtering
  6. Path traversal safety on report download endpoint
  7. Report persistence in 'reports' SQLite table
  8. Missing telemetry / empty periods graceful handling
  9. PDF Reports REST API endpoints
  10. Presence & Telemetry constants remain 100% frozen
"""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from master.app.database import init_database, get_connection
from master.app.services.chart_service import ChartService
from master.app.services.pdf_renderer import PDFRenderer
from master.app.services.report_service import ReportService
from master.app.api import create_app


@pytest.fixture(autouse=True)
def setup_clean_db(monkeypatch, tmp_path):
    """Setup isolated database and reports directory for each test run."""
    db_path = str(tmp_path / "test_phase9.db")
    monkeypatch.setattr("master.app.config.config.DB_PATH", db_path)
    init_database()
    return db_path


@pytest.fixture
def temp_reports_dir(tmp_path):
    rep_dir = tmp_path / "reports"
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


def insert_test_log(device_id: str, severity: str = "INFO", message: str = "Test message"):
    conn = get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT INTO logs (device_id, timestamp, level, severity, event_type, category, message, source)
           VALUES (?, ?, ?, ?, 'SYSTEM_EVENT', 'SYSTEM', ?, 'test_runner');""",
        (device_id, now, severity, severity, message),
    )
    conn.commit()
    conn.close()


# ── Test Cases ────────────────────────────────────────────────────────

def test_01_chart_service_timeline_generation(chart_svc):
    """Test ChartService generates valid PNG bytes for telemetry timeline."""
    now = datetime.now(timezone.utc)
    telemetry = [
        {"timestamp": (now - timedelta(minutes=30)).isoformat(), "cpu_usage": 35.0, "memory_usage": 50.0, "disk_usage": 45.0},
        {"timestamp": (now - timedelta(minutes=15)).isoformat(), "cpu_usage": 75.0, "memory_usage": 52.0, "disk_usage": 45.0},
        {"timestamp": now.isoformat(), "cpu_usage": 42.0, "memory_usage": 51.0, "disk_usage": 45.0},
    ]

    png_bytes = chart_svc.generate_combined_resources_chart(telemetry)
    assert png_bytes is not None
    assert len(png_bytes) > 500
    # Verify PNG header magic bytes
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")


def test_02_chart_service_severity_pie_chart(chart_svc):
    """Test ChartService generates valid pie chart for log severity distribution."""
    logs = [
        {"severity": "INFO"},
        {"severity": "WARNING"},
        {"severity": "CRITICAL"},
    ]
    pie_bytes = chart_svc.generate_severity_distribution_chart(logs)
    assert pie_bytes is not None
    assert pie_bytes.startswith(b"\x89PNG\r\n\x1a\n")


def test_03_single_device_pdf_generation(report_svc):
    """Test generating a single device PDF report."""
    create_test_device("DEV-PDF-01", "Executive Laptop", status="online")
    now = datetime.now(timezone.utc)
    insert_telemetry_series("DEV-PDF-01", [
        {"timestamp": (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"), "cpu": 25.0, "ram": 45.0, "disk": 40.0},
        {"timestamp": now.strftime("%Y-%m-%d %H:%M:%S"), "cpu": 30.0, "ram": 48.0, "disk": 40.0},
    ])
    insert_test_log("DEV-PDF-01", severity="INFO", message="Boot successful")

    res = report_svc.generate_report(scope="single_device", device_id="DEV-PDF-01")
    assert res["status"] == "ready"
    assert res["file_name"].endswith(".pdf")
    assert res["file_size"] > 1000

    # Verify physical file existence and PDF header
    file_path = report_svc.get_report_file_path(res["report_id"])
    assert file_path is not None
    assert file_path.exists()
    content = file_path.read_bytes()
    assert content.startswith(b"%PDF-")


def test_04_system_fleet_pdf_generation(report_svc):
    """Test generating an entire system fleet PDF report."""
    create_test_device("DEV-SYS-01", "Workstation 1", status="online")
    create_test_device("DEV-SYS-02", "Workstation 2", status="offline")

    insert_telemetry_series("DEV-SYS-01", [{"cpu": 20.0, "ram": 40.0, "disk": 35.0}])

    res = report_svc.generate_report(scope="system")
    assert res["status"] == "ready"
    assert "system" in res["report_type"]
    assert res["file_size"] > 1000

    file_path = report_svc.get_report_file_path(res["report_id"])
    assert file_path is not None
    assert file_path.read_bytes().startswith(b"%PDF-")


def test_05_selected_devices_pdf_generation(report_svc):
    """Test generating a report for a specific subset of selected devices."""
    create_test_device("DEV-SEL-01", "Select 1", status="online")
    create_test_device("DEV-SEL-02", "Select 2", status="online")
    create_test_device("DEV-IGN-03", "Ignored 3", status="online")

    res = report_svc.generate_report(scope="selected_devices", device_ids=["DEV-SEL-01", "DEV-SEL-02"])
    assert res["status"] == "ready"
    assert "selected_devices:2" in res["report_type"]


def test_06_date_range_validation(report_svc):
    """Test date range normalization and report generation."""
    create_test_device("DEV-TIME-01", "Timeline PC", status="online")
    start = "2026-08-01 00:00:00"
    end = "2026-08-02 00:00:00"

    res = report_svc.generate_report(scope="single_device", device_id="DEV-TIME-01", start_date=start, end_date=end)
    assert res["start_date"] == start
    assert res["end_date"] == end


def test_07_path_traversal_protection(report_svc, monkeypatch):
    """Test that unauthorized paths or path traversal attempts are blocked."""
    create_test_device("DEV-TRAV", "Traversal PC", status="online")
    res = report_svc.generate_report(scope="single_device", device_id="DEV-TRAV")
    report_id = res["report_id"]

    # Valid path must resolve
    safe_path = report_svc.get_report_file_path(report_id)
    assert safe_path is not None

    # Manually tamper with database to point outside reports directory
    conn = get_connection()
    conn.execute("UPDATE reports SET file_path = ? WHERE id = ?;", ("../../etc/passwd", report_id))
    conn.commit()
    conn.close()

    # Traversal path must return None
    blocked_path = report_svc.get_report_file_path(report_id)
    assert blocked_path is None


def test_08_empty_telemetry_graceful_handling(report_svc):
    """Test generating a PDF report for a device with zero telemetry."""
    create_test_device("DEV-EMPTY-PDF", "Zero Telemetry PC", status="online")
    res = report_svc.generate_report(scope="single_device", device_id="DEV-EMPTY-PDF")
    assert res["status"] == "ready"
    assert res["file_size"] > 1000


def test_09_pdf_reports_rest_api(test_client):
    """Test Phase 9 PDF Reports REST API endpoints."""
    create_test_device("DEV-API-REP", "API Report PC", status="online")
    insert_telemetry_series("DEV-API-REP", [{"cpu": 30.0, "ram": 45.0, "disk": 40.0}])

    # 1. POST /api/reports/generate
    gen_payload = {
        "scope": "single_device",
        "device_id": "DEV-API-REP",
    }
    r1 = test_client.post("/api/reports/generate", json=gen_payload)
    assert r1.status_code == 201
    d1 = r1.get_json()
    assert "report_id" in d1
    report_id = d1["report_id"]

    # 2. GET /api/reports/<int:report_id>
    r2 = test_client.get(f"/api/reports/{report_id}")
    assert r2.status_code == 200
    d2 = r2.get_json()
    assert d2["status"] == "ready"

    # 3. GET /api/reports/<int:report_id>/download
    r3 = test_client.get(f"/api/reports/{report_id}/download")
    assert r3.status_code == 200
    assert r3.mimetype == "application/pdf"
    assert r3.data.startswith(b"%PDF-")

    # 4. GET /api/reports
    r4 = test_client.get("/api/reports?limit=10")
    assert r4.status_code == 200
    d4 = r4.get_json()
    assert len(d4["reports"]) >= 1


def test_10_presence_and_telemetry_constants_are_frozen():
    """Verify presence & telemetry intervals remain 100% frozen."""
    from master.app.config import config as master_config
    from client.app.config import config as client_config

    assert master_config.HEARTBEAT_TIMEOUT_SECONDS == 9
    assert master_config.PRESENCE_CHECK_INTERVAL == 1
    assert master_config.TELEMETRY_INTERVAL == 10

    assert client_config.HEARTBEAT_INTERVAL == 3
    assert client_config.TELEMETRY_INTERVAL == 10
