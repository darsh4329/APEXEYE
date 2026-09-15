"""
APEXEYE — Real Windows Runtime Application Lifecycle Verification

Performs live execution against the actual operating system:
1. Initializes EventCollector with live process baseline.
2. Spawns an actual Windows application process (Notepad).
3. Verifies APPLICATION_STARTED event with message '<App> opened'.
4. Keeps it running across multiple collect cycles and verifies zero duplicate events.
5. Spawns a helper/second subprocess and verifies zero duplicate events.
6. Terminates all processes and verifies APPLICATION_STOPPED event with message '<App> closed'.
7. Reopens the application and verifies a new APPLICATION_STARTED event.
8. Cleans up.
9. Ingests events into Master /api/events and verifies DB storage and /api/logs query.
"""

import os
import sys
import time
import subprocess
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.collectors.events import EventCollector, APPLICATION_TAXONOMY, IGNORED_SYSTEM_PROCESSES
from master.app.database import init_database, get_connection
from master.app.api import create_app
from master.app.services.device_service import DeviceService
from master.app.auth import AuthService


def run_live_windows_lifecycle_verification():
    print("=" * 60)
    print("APEXEYE LIVE WINDOWS RUNTIME APPLICATION LIFECYCLE TEST")
    print("=" * 60)

    # 1. Baseline Initialization
    collector = EventCollector()
    baseline_groups = collector._previous.app_groups
    print(f"[1] Baseline initialized. Recognized taxonomy size: {len(APPLICATION_TAXONOMY)}")
    print(f"    Currently running recognized apps: {list(baseline_groups.keys())}")

    # Ensure notepad is closed before starting test
    subprocess.run(["taskkill", "/F", "/IM", "notepad.exe"], capture_output=True)
    time.sleep(0.5)
    collector.collect()  # Flush any closed events from killing prior instances

    # 2. Open Application (Notepad)
    print("\n[2] Spawning live Windows process: notepad.exe ...")
    proc1 = subprocess.Popen(["notepad.exe"])
    time.sleep(1.0)  # Wait for Windows process to spawn

    events1 = collector.collect()
    print(f"    Collector cycle 1 returned {len(events1)} event(s):")
    for e in events1:
        print(f"      -> {e['event_type']} | {e['category']} | {e['application_name']} | {e['message']}")

    assert len(events1) == 1, f"Expected 1 event, got {len(events1)}"
    assert events1[0]["event_type"] == "APPLICATION_STARTED"
    assert events1[0]["application_name"] == "Notepad"
    assert events1[0]["category"] == "PRODUCTIVITY"
    assert events1[0]["message"] == "Notepad opened"
    print("    [PASS] Step 2: Exactly one 'APPLICATION_STARTED' ('Notepad opened') emitted.")

    # 3. Wait across multiple collector cycles while running
    print("\n[3] Waiting across 3 subsequent collector cycles while application is running ...")
    for i in range(3):
        time.sleep(0.5)
        evts = collector.collect()
        assert len(evts) == 0, f"Expected 0 duplicate events on cycle {i+1}, got {len(evts)}"
    print("    [PASS] Step 3: Zero duplicate events while application remains running.")

    # 4. Spawn a second instance / helper subprocess (1 -> 2 processes)
    print("\n[4] Spawning second instance of notepad.exe (helper / multi-process) ...")
    proc2 = subprocess.Popen(["notepad.exe"])
    time.sleep(1.0)

    events_multi = collector.collect()
    assert len(events_multi) == 0, f"Expected 0 events for helper/child process, got {len(events_multi)}"
    print("    [PASS] Step 4: Zero duplicate events when additional subprocesses appear.")

    # 5. Terminate only one process (2 -> 1 process)
    print("\n[5] Terminating one subprocess (application still has 1 running process) ...")
    proc2.terminate()
    try:
        proc2.wait(timeout=2)
    except Exception:
        pass
    time.sleep(0.5)

    events_partial = collector.collect()
    assert len(events_partial) == 0, f"Expected 0 events when partial subprocesses close, got {len(events_partial)}"
    print("    [PASS] Step 5: Zero CLOSED events while at least 1 process remains.")

    # 6. Completely close the application (1 -> 0 processes)
    print("\n[6] Terminating final process (application fully closes) ...")
    proc1.terminate()
    try:
        proc1.wait(timeout=2)
    except Exception:
        pass
    subprocess.run(["taskkill", "/F", "/IM", "notepad.exe"], capture_output=True)
    time.sleep(1.0)

    events_close = collector.collect()
    print(f"    Collector cycle returned {len(events_close)} event(s):")
    for e in events_close:
        print(f"      -> {e['event_type']} | {e['category']} | {e['application_name']} | {e['message']}")

    assert len(events_close) == 1, f"Expected 1 event, got {len(events_close)}"
    assert events_close[0]["event_type"] == "APPLICATION_STOPPED"
    assert events_close[0]["application_name"] == "Notepad"
    assert events_close[0]["category"] == "PRODUCTIVITY"
    assert events_close[0]["message"] == "Notepad closed"
    print("    [PASS] Step 6: Exactly one 'APPLICATION_STOPPED' ('Notepad closed') emitted.")

    # 7. Reopen the application (0 -> 1 process)
    print("\n[7] Reopening application (notepad.exe) ...")
    proc3 = subprocess.Popen(["notepad.exe"])
    time.sleep(1.0)

    events_reopen = collector.collect()
    print(f"    Collector cycle returned {len(events_reopen)} event(s):")
    for e in events_reopen:
        print(f"      -> {e['event_type']} | {e['category']} | {e['application_name']} | {e['message']}")

    assert len(events_reopen) == 1, f"Expected 1 event on reopen, got {len(events_reopen)}"
    assert events_reopen[0]["event_type"] == "APPLICATION_STARTED"
    assert events_reopen[0]["message"] == "Notepad opened"
    print("    [PASS] Step 7: Exactly one new 'APPLICATION_STARTED' ('Notepad opened') emitted on reopen.")

    # Cleanup
    proc3.terminate()
    try:
        proc3.wait(timeout=2)
    except Exception:
        pass
    subprocess.run(["taskkill", "/F", "/IM", "notepad.exe"], capture_output=True)
    time.sleep(0.5)

    # 8. End-to-End Master Pipeline Verification
    print("\n[8] Testing End-to-End Pipeline: Ingestion -> DB Logs Table -> Dashboard API ...")
    init_database()
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    dev_svc = DeviceService()
    auth_svc = AuthService()
    dev_id = "LIVE-TEST-PC"
    dev_svc.register({"device_id": dev_id, "device_name": "Test PC", "device_type": "WINDOWS_PC"})
    pair = auth_svc.generate_pairing_credential(dev_id)
    token = pair["token"]
    auth_svc.authenticate_device(dev_id, token)

    headers = {"X-Device-ID": dev_id, "X-Auth-Token": token, "Content-Type": "application/json"}

    all_test_events = events1 + events_close + events_reopen
    resp = client.post("/api/events", json={"events": all_test_events}, headers=headers)
    assert resp.status_code == 201, f"Expected 201 from /api/events, got {resp.status_code}"
    print("    [PASS] Stored events in Master successfully.")

    # Query /api/logs
    resp_logs = client.get(f"/api/logs?device_id={dev_id}")
    assert resp_logs.status_code == 200
    log_data = resp_logs.get_json()
    logs = log_data.get("logs", [])
    print(f"    Queried {len(logs)} logs from /api/logs:")
    for l in logs:
        print(f"      [{l['timestamp']}] {l['category']} | {l['event_type']} | {l['application_name']} | {l['message']}")

    assert len(logs) == 3
    assert logs[0]["message"] in ["Notepad opened", "Notepad closed"]

    print("\n" + "=" * 60)
    print("ALL REAL RUNTIME APPLICATION LIFECYCLE TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    run_live_windows_lifecycle_verification()
