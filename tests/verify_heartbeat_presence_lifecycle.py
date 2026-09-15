"""
APEXEYE — Targeted Runtime Verification Script
Validates 3-second heartbeat, 9-second timeout, presence reconciliation,
process-group application lifecycle, deduplication, and log clear safety.
"""

import os
import sys
import time
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.config import config as master_config
from client.app.config import config as client_config
from master.app.services.device_service import DeviceService
from master.app.services.heartbeat_service import HeartbeatService
from master.app.services.telemetry_service import TelemetryService
from master.app.services.log_service import LogService
from master.app.services.presence_service import PresenceMonitorEngine
from master.app.auth import AuthService
from client.app.collectors.events import EventCollector


def run_runtime_verification():
    print("=" * 70)
    print("APEXEYE RUNTIME VERIFICATION — HEARTBEAT, PRESENCE & LIFECYCLE")
    print("=" * 70)

    # 1. Verify Config Defaults
    print("\n[STEP 1] Verifying Configuration Constants …")
    print(f"  Master HEARTBEAT_TIMEOUT_SECONDS: {master_config.HEARTBEAT_TIMEOUT_SECONDS}s (Expected: 9s)")
    print(f"  Master PRESENCE_CHECK_INTERVAL  : {master_config.PRESENCE_CHECK_INTERVAL}s (Expected: 1s)")
    print(f"  Client HEARTBEAT_INTERVAL       : {client_config.HEARTBEAT_INTERVAL}s (Expected: 3s)")
    assert master_config.HEARTBEAT_TIMEOUT_SECONDS == 9, "Master heartbeat timeout must be 9s"
    assert master_config.PRESENCE_CHECK_INTERVAL == 1, "Master presence check interval must be 1s"
    assert client_config.HEARTBEAT_INTERVAL == 3, "Client heartbeat interval must be 3s"
    print("  --> PASS: Configuration values verified.")

    # 2. Setup Isolated Database & Services
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        test_db = f.name

    try:
        init_database(test_db)
        with patch("master.app.config.config.DB_PATH", test_db):
            dev_svc = DeviceService()
            hb_svc = HeartbeatService()
            tel_svc = TelemetryService()
            log_svc = LogService()
            auth_svc = AuthService()

            # 3. Scenario A: Device Registration & Heartbeat -> ONLINE
            print("\n[STEP 2] Scenario A — Device Heartbeat & Online Presence …")
            dev_svc.register({
                "device_id": "TEST-PC-RUNTIME",
                "device_name": "Runtime Verification PC",
                "device_type": "WINDOWS_PC",
                "operating_system": "Windows 11 Pro",
                "ip_address": "192.168.1.100",
            })
            pair_info = auth_svc.generate_pairing_credential("TEST-PC-RUNTIME")
            auth_svc.authenticate_device("TEST-PC-RUNTIME", pair_info["token"])

            dev = dev_svc.get_device("TEST-PC-RUNTIME")
            assert dev["status"] == "pending", "Initial status must be pending"

            # Heartbeat arrives
            hb_res = hb_svc.process_heartbeat("TEST-PC-RUNTIME", {"client_status": "running"})
            assert hb_res["status"] == "acknowledged"

            dev = dev_svc.get_device("TEST-PC-RUNTIME")
            assert dev["status"] == "online", "Device must be online after heartbeat"
            last_seen_1 = dev["last_seen"]
            assert last_seen_1 is not None

            sum_1 = dev_svc.get_summary()
            assert sum_1["online"] == 1
            assert sum_1["offline"] == 0
            print("  --> PASS: Device is ONLINE after receiving heartbeat.")

            # 4. Read operations must never advance last_seen or alter presence
            print("\n[STEP 3] Verifying Read Operations Semantics …")
            dev_svc.list_devices()
            dev_svc.list_devices_with_telemetry()
            dev_svc.get_summary()
            dev_svc.get_device("TEST-PC-RUNTIME")
            log_svc.search_logs(device_id="TEST-PC-RUNTIME")
            tel_svc.get_latest("TEST-PC-RUNTIME")

            dev_after_reads = dev_svc.get_device("TEST-PC-RUNTIME")
            assert dev_after_reads["last_seen"] == last_seen_1, "last_seen MUST NOT advance on read operations"
            print("  --> PASS: Read operations do not modify last_seen.")

            # 5. Scenario B: Client Hard Disappearance & Automatic OFFLINE transition
            print("\n[STEP 4] Scenario B — Client Disappearance (Timeout => OFFLINE) …")
            # Simulate 10 seconds of no heartbeats (past 9s timeout)
            old_time = (datetime.now(timezone.utc) - timedelta(seconds=11)).strftime("%Y-%m-%d %H:%M:%S")
            conn = get_connection(test_db)
            conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = 'TEST-PC-RUNTIME';", (old_time,))
            conn.commit()
            conn.close()

            # Presence reconciliation runs
            transitioned = dev_svc.reconcile_presence()
            assert transitioned == 1, "Must transition 1 device to offline"

            dev_offline = dev_svc.get_device("TEST-PC-RUNTIME")
            assert dev_offline["status"] == "offline", "Device must be marked OFFLINE after 9s timeout"
            assert dev_offline["last_seen"] == old_time, "Historical last_seen must be preserved"

            sum_2 = dev_svc.get_summary()
            assert sum_2["online"] == 0
            assert sum_2["offline"] == 1
            print("  --> PASS: Device automatically transitioned to OFFLINE after timeout.")

            # 6. Scenario C: Reconnection -> Back ONLINE with all history preserved
            print("\n[STEP 5] Scenario C — Reconnection (Heartbeat => Back ONLINE) …")
            hb_svc.process_heartbeat("TEST-PC-RUNTIME", {"client_status": "running"})

            dev_reconnected = dev_svc.get_device("TEST-PC-RUNTIME")
            assert dev_reconnected["status"] == "online", "Device must be back ONLINE"
            assert dev_reconnected["device_name"] == "Runtime Verification PC"

            # Check pairing is intact
            auth_stat = auth_svc.get_auth_status("TEST-PC-RUNTIME")
            assert auth_stat["status"] == "paired", "Pairing must remain intact"

            sum_3 = dev_svc.get_summary()
            assert sum_3["online"] == 1
            assert sum_3["offline"] == 0
            print("  --> PASS: Reconnection successfully restored ONLINE without resetting pairing/device.")

            # 7. Scenario D: Application Lifecycle Process-Group State Machine
            print("\n[STEP 6] Scenario D — Application Lifecycle Process Group Transitions …")
            collector = EventCollector()
            collector._previous.processes = {}

            def mock_p(pid, name):
                m = MagicMock()
                m.info = {"pid": pid, "name": name}
                return m

            # Edge Launch: 0 -> 1 process -> 1 OPENED
            with patch("psutil.process_iter", return_value=[mock_p(101, "msedge.exe")]):
                evt_1 = collector.collect()
            assert len(evt_1) == 1
            assert evt_1[0]["event_type"] == "APPLICATION_STARTED"
            assert evt_1[0]["application_name"] == "Microsoft Edge"
            assert evt_1[0]["message"] == "Microsoft Edge opened"

            # Edge Subprocesses spawn: 1 -> 5 processes -> 0 extra events
            with patch("psutil.process_iter", return_value=[
                mock_p(101, "msedge.exe"),
                mock_p(102, "msedge.exe"),
                mock_p(103, "msedge.exe"),
                mock_p(104, "msedge.exe"),
                mock_p(105, "msedge.exe"),
            ]):
                evt_2 = collector.collect()
            assert len(evt_2) == 0, "Spawning tabs/subprocesses must emit 0 events"

            # Edge Tabs reduce: 5 -> 2 processes -> 0 events
            with patch("psutil.process_iter", return_value=[
                mock_p(101, "msedge.exe"),
                mock_p(102, "msedge.exe"),
            ]):
                evt_3 = collector.collect()
            assert len(evt_3) == 0, "Closing individual tabs must emit 0 events while app is running"

            # Edge Closes completely: 2 -> 0 processes -> 1 CLOSED
            with patch("psutil.process_iter", return_value=[]):
                evt_4 = collector.collect()
            assert len(evt_4) == 1
            assert evt_4[0]["event_type"] == "APPLICATION_STOPPED"
            assert evt_4[0]["application_name"] == "Microsoft Edge"
            assert evt_4[0]["message"] == "Microsoft Edge closed"

            # Edge Re-opens: 0 -> 1 process -> 1 OPENED
            with patch("psutil.process_iter", return_value=[mock_p(201, "msedge.exe")]):
                evt_5 = collector.collect()
            assert len(evt_5) == 1
            assert evt_5[0]["event_type"] == "APPLICATION_STARTED"
            assert evt_5[0]["application_name"] == "Microsoft Edge"
            print("  --> PASS: Process group lifecycle matches 0->1 OPENED, 1->N zero, N->0 CLOSED, Reopen OPENED.")

            # 8. Scenario E: Clear Logs Safety
            print("\n[STEP 7] Scenario E — Clear Logs Safety & Subsequent Ingestion …")
            # Ingest events into master database with realistic sequential timestamps
            evt_1[0]["timestamp"] = "2026-08-27 10:00:00"
            evt_4[0]["timestamp"] = "2026-08-27 10:05:00"
            evt_5[0]["timestamp"] = "2026-08-27 10:10:00"
            log_svc.ingest_logs("TEST-PC-RUNTIME", [evt_1[0], evt_4[0], evt_5[0]])
            logs_before = log_svc.search_logs(device_id="TEST-PC-RUNTIME")
            assert logs_before["total"] == 3

            # Clear logs
            deleted = log_svc.clear_logs()
            assert deleted == 3

            logs_after = log_svc.search_logs(device_id="TEST-PC-RUNTIME")
            assert logs_after["total"] == 0

            # Verify device, auth, telemetry still exist
            dev_surv = dev_svc.get_device("TEST-PC-RUNTIME")
            assert dev_surv is not None
            assert dev_surv["status"] == "online"

            auth_surv = auth_svc.get_auth_status("TEST-PC-RUNTIME")
            assert auth_surv["status"] == "paired"

            # Ingest new event after clear
            log_svc.ingest_logs("TEST-PC-RUNTIME", [{
                "timestamp": "2026-08-27 12:00:00",
                "event_type": "APPLICATION_STARTED",
                "category": "DEVELOPMENT",
                "application_name": "Visual Studio Code",
                "message": "Visual Studio Code opened",
                "severity": "INFO",
            }])
            logs_new = log_svc.search_logs(device_id="TEST-PC-RUNTIME")
            assert logs_new["total"] == 1
            assert logs_new["logs"][0]["message"] == "Visual Studio Code opened"
            print("  --> PASS: Clear Logs deletes only logs and allows subsequent ingestion.")

        print("\n" + "=" * 70)
        print("ALL RUNTIME VERIFICATION SCENARIOS PASSED WITH 100% SUCCESS!")
        print("=" * 70)

    finally:
        try:
            os.remove(test_db)
        except OSError:
            pass


if __name__ == "__main__":
    run_runtime_verification()
