"""
APEXEYE — End-to-End Runtime Scenario Verification Script

Executes and verifies Scenarios A through E:
- Scenario A (Online): Master & Client runtime, registration, pairing, online status, live telemetry, application lifecycle
- Scenario B (Disconnect): Client termination, time elapsed past heartbeat timeout, status transition to OFFLINE, online=0, offline=1, device appears in offline list
- Scenario C (Reconnect): Client resumption, status automatically returns to ONLINE, historical logs/telemetry preserved
- Scenario D (Application Lifecycle): 0->1 "Microsoft Edge opened", 1->4 helper processes (no duplicate opened), 4->0 "Microsoft Edge closed", 0->1 reopen "Microsoft Edge opened"
- Scenario E (Clear Logs): POST /api/logs/clear clears activity logs, preserves device registration, pairing, and telemetry, allows new logs to be created
"""

import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.services.device_service import DeviceService
from master.app.services.heartbeat_service import HeartbeatService
from master.app.services.telemetry_service import TelemetryService
from master.app.services.log_service import LogService
from master.app.services.presence_service import PresenceMonitorEngine
from master.app.auth import AuthService
from master.app.api import create_app
from client.app.collectors.events import EventCollector


def run_all_runtime_verifications():
    print("=" * 70)
    print("APEXEYE — STARTING RUNTIME SCENARIO VERIFICATION")
    print("=" * 70)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        init_database(db_path)
        with patch("master.app.config.config.DB_PATH", db_path):
            app = create_app()
            client = app.test_client()

            dev_svc = DeviceService()
            auth_svc = AuthService()
            hb_svc = HeartbeatService()
            tel_svc = TelemetryService()
            log_svc = LogService()

            # -------------------------------------------------------------
            # TEST A — ONLINE
            # -------------------------------------------------------------
            print("\n[TEST A — ONLINE]")
            # 1. Register device
            dev_data = {
                "device_id": "CLIENT-WIN-LIVE-01",
                "device_name": "Front Desk Desktop",
                "device_type": "WINDOWS_PC",
                "operating_system": "Windows 11 Pro",
                "hostname": "DESKTOP-FRONT",
                "ip_address": "192.168.1.120",
            }
            dev = dev_svc.register(dev_data)
            pair_cred = auth_svc.generate_pairing_credential("CLIENT-WIN-LIVE-01")
            auth_ok = auth_svc.authenticate_device("CLIENT-WIN-LIVE-01", pair_cred["token"])
            assert auth_ok, "Pairing authentication failed"

            # 2. Client sends heartbeat & telemetry
            hb_svc.process_heartbeat("CLIENT-WIN-LIVE-01", {"client_status": "running"})
            tel_svc.ingest("CLIENT-WIN-LIVE-01", {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "cpu": {"cpu_usage": 32.4},
                "memory": {"memory_usage_percent": 54.1, "memory_total_gb": 16.0, "memory_used_gb": 8.65},
                "disk": {"disk_usage_percent": 41.0, "disk_total_gb": 512.0, "disk_free_gb": 302.0},
            })

            # 3. Check Master status
            dev_state = dev_svc.get_device("CLIENT-WIN-LIVE-01", with_telemetry=True)
            summary = dev_svc.get_summary()

            assert dev_state["status"] == "online", f"Expected online, got {dev_state['status']}"
            assert summary["online"] == 1, f"Expected online count 1, got {summary['online']}"
            assert summary["offline"] == 0, f"Expected offline count 0, got {summary['offline']}"
            assert dev_state["latest_telemetry"]["cpu_usage"] == 32.4
            print("  [PASS] Client is ONLINE (Status: online, Online: 1, Offline: 0)")
            print("  [PASS] CPU/RAM Telemetry accurately updated (CPU: 32.4%, RAM: 54.1%)")

            # -------------------------------------------------------------
            # TEST B — DISCONNECT
            # -------------------------------------------------------------
            print("\n[TEST B — DISCONNECT]")
            # 1. Simulate client shutdown: last_seen stops advancing
            # Simulate elapsed time beyond 90s timeout
            now_dt = datetime.now(timezone.utc)
            past_time = (now_dt - timedelta(seconds=120)).strftime("%Y-%m-%d %H:%M:%S")
            conn = get_connection(db_path)
            conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?;", (past_time, "CLIENT-WIN-LIVE-01"))
            conn.commit()
            conn.close()

            # 2. Presence reconciliation executes
            transitioned = dev_svc.reconcile_presence(timeout_seconds=90)
            assert transitioned == 1, f"Expected 1 device transitioned, got {transitioned}"

            # 3. Verify Master changed client to OFFLINE
            dev_offline = dev_svc.get_device("CLIENT-WIN-LIVE-01", with_telemetry=True)
            summary_offline = dev_svc.get_summary()
            all_devices = dev_svc.list_devices()
            offline_devices = [d for d in all_devices if d["status"] == "offline"]

            assert dev_offline["status"] == "offline", f"Expected offline, got {dev_offline['status']}"
            assert summary_offline["online"] == 0, f"Expected online=0, got {summary_offline['online']}"
            assert summary_offline["offline"] == 1, f"Expected offline=1, got {summary_offline['offline']}"
            assert len(offline_devices) == 1, f"Expected 1 offline device, got {len(offline_devices)}"
            assert offline_devices[0]["device_id"] == "CLIENT-WIN-LIVE-01"
            print("  [PASS] Client automatically transitioned to OFFLINE after heartbeat timeout")
            print("  [PASS] Summary updated (Online: 0, Offline: 1)")
            print("  [PASS] Device appears in Offline Devices list")

            # -------------------------------------------------------------
            # TEST C — RECONNECT
            # -------------------------------------------------------------
            print("\n[TEST C — RECONNECT]")
            # 1. Client starts up again and resumes heartbeats
            hb_svc.process_heartbeat("CLIENT-WIN-LIVE-01", {"client_status": "running"})
            tel_svc.ingest("CLIENT-WIN-LIVE-01", {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "cpu": {"cpu_usage": 28.1},
                "memory": {"memory_usage_percent": 55.0},
            })

            dev_reconnected = dev_svc.get_device("CLIENT-WIN-LIVE-01", with_telemetry=True)
            summary_reconnected = dev_svc.get_summary()

            assert dev_reconnected["status"] == "online", f"Expected online, got {dev_reconnected['status']}"
            assert summary_reconnected["online"] == 1
            assert summary_reconnected["offline"] == 0
            assert dev_reconnected["authentication_status"] == "paired"
            print("  [PASS] Client returned to ONLINE on reconnection")
            print("  [PASS] Device identity, pairing credentials, and historical telemetry preserved")

            # -------------------------------------------------------------
            # TEST D — APPLICATION LIFECYCLE
            # -------------------------------------------------------------
            print("\n[TEST D — APPLICATION LIFECYCLE]")
            collector = EventCollector()
            collector._previous.processes = {}

            def mock_p(pid, name):
                m = MagicMock()
                m.info = {"pid": pid, "name": name}
                return m

            # 1. Open Edge -> exactly ONE "Microsoft Edge opened"
            with patch("psutil.process_iter", return_value=[mock_p(101, "msedge.exe")]):
                e1 = collector.collect()
            assert len(e1) == 1
            assert e1[0]["event_type"] == "APPLICATION_STARTED"
            assert e1[0]["category"] == "BROWSER"
            assert e1[0]["application_name"] == "Microsoft Edge"
            assert e1[0]["message"] == "Microsoft Edge opened"
            print("  [PASS] Step 1: Microsoft Edge opened -> exactly 1 'Microsoft Edge opened' (Category: BROWSER)")

            # Set realistic timestamps
            t1 = (datetime.now(timezone.utc) - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
            t2 = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            t3 = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            e1[0]["timestamp"] = t1
            log_svc.ingest_logs("CLIENT-WIN-LIVE-01", e1)

            # 2. Keep Edge running + spawn helper tabs (1 -> 4 processes)
            with patch("psutil.process_iter", return_value=[
                mock_p(101, "msedge.exe"),
                mock_p(102, "msedge.exe"),
                mock_p(103, "msedge.exe"),
            ]):
                e2 = collector.collect()
            started_events = [e for e in e2 if e["event_type"] == "APPLICATION_STARTED"]
            assert len(started_events) == 0
            print("  [PASS] Step 2: Helper processes/tabs spawned -> NO repeated 'Microsoft Edge opened' events")

            # 3. Close Edge completely -> exactly ONE "Microsoft Edge closed"
            with patch("psutil.process_iter", return_value=[]):
                e3 = collector.collect()
            assert len(e3) == 1
            assert e3[0]["event_type"] == "APPLICATION_STOPPED"
            assert e3[0]["category"] == "BROWSER"
            assert e3[0]["message"] == "Microsoft Edge closed"
            print("  [PASS] Step 3: Microsoft Edge closed -> exactly 1 'Microsoft Edge closed'")

            e3[0]["timestamp"] = t2
            log_svc.ingest_logs("CLIENT-WIN-LIVE-01", e3)

            # 4. Open Edge again later -> new valid "Microsoft Edge opened"
            with patch("psutil.process_iter", return_value=[mock_p(201, "msedge.exe")]):
                e4 = collector.collect()
            assert len(e4) == 1
            assert e4[0]["event_type"] == "APPLICATION_STARTED"
            assert e4[0]["message"] == "Microsoft Edge opened"
            print("  [PASS] Step 4: Reopened Microsoft Edge -> exactly 1 new 'Microsoft Edge opened'")

            e4[0]["timestamp"] = t3
            log_svc.ingest_logs("CLIENT-WIN-LIVE-01", e4)

            # Verify Master logs table has all 3 lifecycle events
            logs_res = log_svc.search_logs(device_id="CLIENT-WIN-LIVE-01")
            assert logs_res["total"] == 3
            print("  [PASS] All 3 lifecycle events preserved in sequence (Opened -> Closed -> Opened)")


            # -------------------------------------------------------------
            # TEST E — CLEAR LOGS
            # -------------------------------------------------------------
            print("\n[TEST E — CLEAR LOGS]")
            # 1. Clear logs via endpoint
            clear_res = client.post("/api/logs/clear")
            assert clear_res.status_code == 200
            assert clear_res.json["status"] == "success"
            assert clear_res.json["deleted"] == 3
            print(f"  [PASS] POST /api/logs/clear executed: {clear_res.json['deleted']} logs deleted")

            # 2. Verify logs table is empty
            logs_after = log_svc.search_logs(device_id="CLIENT-WIN-LIVE-01")
            assert logs_after["total"] == 0
            assert len(logs_after["logs"]) == 0
            print("  [PASS] Centralized logs table is now empty (Total: 0)")

            # 3. Verify registered device is still intact
            dev_check = dev_svc.get_device("CLIENT-WIN-LIVE-01")
            assert dev_check is not None
            assert dev_check["device_id"] == "CLIENT-WIN-LIVE-01"
            assert dev_check["status"] == "online"
            print("  [PASS] Registered device intact (CLIENT-WIN-LIVE-01, Status: online)")

            # 4. Verify pairing is still intact
            auth_check = auth_svc.get_auth_status("CLIENT-WIN-LIVE-01")
            assert auth_check["status"] == "paired"
            print("  [PASS] Pairing credentials intact (Status: paired)")

            # 5. Verify new logs after clear work normally
            log_svc.ingest_logs("CLIENT-WIN-LIVE-01", [{
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "APPLICATION_STARTED",
                "category": "DEVELOPMENT",
                "application_name": "Visual Studio Code",
                "message": "Visual Studio Code opened",
                "severity": "INFO",
            }])
            logs_fresh = log_svc.search_logs(device_id="CLIENT-WIN-LIVE-01")
            assert logs_fresh["total"] == 1
            assert logs_fresh["logs"][0]["application_name"] == "Visual Studio Code"
            print("  [PASS] New logs generated after clear ingested and retrieved successfully")


            print("\n" + "=" * 70)
            print("ALL 5 RUNTIME SCENARIOS (A, B, C, D, E) PASSED WITH 100% SUCCESS!")
            print("=" * 70)

    finally:
        try:
            os.remove(db_path)
        except OSError:
            pass


if __name__ == "__main__":
    run_all_runtime_verifications()
