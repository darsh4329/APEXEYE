"""
APEXEYE — Phase 9.2.1 Sample PDF Verification Script
Generates real PDF samples for manual/visual verification across all key report scopes and data states.
"""

from pathlib import Path
from datetime import datetime, timezone, timedelta
from master.app.database import init_database, get_connection
from master.app.services.report_service import ReportService
import json

def run_verification():
    db_file = Path("scratch/verify_phase9_2_1.db")
    if db_file.exists():
        db_file.unlink()
    db_path = str(db_file)
    import master.app.config
    master.app.config.config.DB_PATH = db_path
    init_database()

    out_dir = Path("scratch/sample_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_svc = ReportService(reports_dir=out_dir)

    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Setup Test Devices
    conn = get_connection()
    conn.execute(
        "INSERT INTO devices (device_id, device_name, device_type, operating_system, status, last_seen, created_at, updated_at) "
        "VALUES ('DEV-HEALTHY', 'Workstation-Alpha', 'WINDOWS_PC', 'Windows 11 Pro', 'online', ?, ?, ?);",
        (now_str, now_str, now_str)
    )
    conn.execute(
        "INSERT INTO devices (device_id, device_name, device_type, operating_system, status, last_seen, created_at, updated_at) "
        "VALUES ('DEV-SPARSE', 'Lab-Node-Beta', 'WINDOWS_PC', 'Windows 10 Enterprise', 'online', ?, ?, ?);",
        (now_str, now_str, now_str)
    )
    conn.execute(
        "INSERT INTO devices (device_id, device_name, device_type, operating_system, status, last_seen, created_at, updated_at) "
        "VALUES ('DEV-HIGH-CPU', 'Build-Server-Gamma', 'WINDOWS_PC', 'Windows Server 2022', 'online', ?, ?, ?);",
        (now_str, now_str, now_str)
    )
    conn.commit()

    # 2. Insert Telemetry
    # Healthy series (>= 2 samples)
    for i in range(10):
        t_time = (now - timedelta(minutes=10 - i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO telemetry (device_id, timestamp, cpu_usage, memory_usage, disk_usage, network_usage, health_score, details) "
            "VALUES ('DEV-HEALTHY', ?, ?, ?, ?, 1.2, 98.0, ?);",
            (t_time, 25.0 + (i % 5), 42.0 + (i % 3), 35.0, json.dumps({}))
        )
    # Sparse series (1 sample)
    conn.execute(
        "INSERT INTO telemetry (device_id, timestamp, cpu_usage, memory_usage, disk_usage, network_usage, health_score, details) "
        "VALUES ('DEV-SPARSE', ?, 32.0, 48.0, 40.0, 0.8, 92.0, ?);",
        (now_str, json.dumps({}))
    )
    # High CPU series
    for i in range(8):
        t_time = (now - timedelta(minutes=8 - i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO telemetry (device_id, timestamp, cpu_usage, memory_usage, disk_usage, network_usage, health_score, details) "
            "VALUES ('DEV-HIGH-CPU', ?, ?, ?, ?, 5.5, 45.0, ?);",
            (t_time, 96.5 + (i % 3), 78.0, 60.0, json.dumps({}))
        )

    # 3. Insert Logs & Lifecycle events
    conn.execute(
        "INSERT INTO logs (device_id, timestamp, level, severity, event_type, category, application_name, message, source) "
        "VALUES ('DEV-HEALTHY', ?, 'INFO', 'INFO', 'APPLICATION_STARTED', 'SYSTEM', 'Visual Studio Code', 'VSCode opened', 'test_runner');",
        (now_str,)
    )
    conn.execute(
        "INSERT INTO logs (device_id, timestamp, level, severity, event_type, category, application_name, message, source) "
        "VALUES ('DEV-HEALTHY', ?, 'INFO', 'INFO', 'APPLICATION_STOPPED', 'SYSTEM', 'Visual Studio Code', 'VSCode closed', 'test_runner');",
        (now_str,)
    )
    conn.execute(
        "INSERT INTO logs (device_id, timestamp, level, severity, event_type, category, message, details, source) "
        "VALUES ('DEV-HIGH-CPU', ?, 'CRITICAL', 'CRITICAL', 'CPU_CRITICAL', 'SYSTEM', 'Critical CPU utilization alert: 98.5%', ?, 'test_runner');",
        (now_str, json.dumps({"cpu_usage": 98.5}))
    )
    conn.commit()
    conn.close()

    print("Generating Test A: Single Healthy Device Report...")
    rep_a = report_svc.generate_report(scope="single_device", device_id="DEV-HEALTHY")
    print(f"Test A generated: {rep_a['file_name']} ({rep_a['file_size']} bytes)")

    print("Generating Test B: Sparse Telemetry Device Report...")
    rep_b = report_svc.generate_report(scope="single_device", device_id="DEV-SPARSE")
    print(f"Test B generated: {rep_b['file_name']} ({rep_b['file_size']} bytes)")

    print("Generating Test C: Empty Date-Range Report...")
    rep_c = report_svc.generate_report(scope="single_device", device_id="DEV-HEALTHY", start_date="2018-01-01 00:00:00", end_date="2018-01-02 00:00:00")
    print(f"Test C generated: {rep_c['file_name']} ({rep_c['file_size']} bytes)")

    print("Generating Test D: Entire System Fleet Report...")
    rep_d = report_svc.generate_report(scope="system")
    print(f"Test D generated: {rep_d['file_name']} ({rep_d['file_size']} bytes)")

    print("Generating Test E: Selected Devices Report...")
    rep_e = report_svc.generate_report(scope="selected_devices", device_ids=["DEV-HEALTHY", "DEV-SPARSE"])
    print(f"Test E generated: {rep_e['file_name']} ({rep_e['file_size']} bytes)")

    print("Generating Test F: High-CPU Anomaly Report...")
    rep_f = report_svc.generate_report(scope="single_device", device_id="DEV-HIGH-CPU")
    print(f"Test F generated: {rep_f['file_name']} ({rep_f['file_size']} bytes)")

    print("\nALL SAMPLE PDFS GENERATED SUCCESSFULLY WITH ZERO ERRORS!")

if __name__ == "__main__":
    run_verification()
