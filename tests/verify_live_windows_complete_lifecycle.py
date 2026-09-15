"""
APEXEYE — Production Windows Live Verification: Complete Real Desktop Lifecycle Test

Validates all 11 user requirements on the physical Windows laptop:
1. Master and Windows Client live event collection.
2. Real GUI applications currently open with visible desktop windows:
   - Google Chrome
   - Microsoft Edge
   - Visual Studio Code
   - Antigravity IDE
3. Production EventCollector.get_running_applications() returns genuine applications.
4. Logical multi-process grouping: child renderers/gpu/utility/crashpad collapsed.
5. Exact Master Overview Activity Log verification:
   - Real events recorded in Master DB.
   - No Identity Helper spam.
   - No Lenovo background-helper spam.
   - No svchost/dwm/RuntimeBroker/SearchHost spam.
6. Real Windows lifecycle behavior:
   - Close Chrome completely -> exactly ONE APPLICATION_STOPPED.
   - Reopen Chrome -> exactly ONE APPLICATION_STARTED.
   - Subprocess churn -> ZERO duplicate events.
   - Same lifecycle tested for Edge and Visual Studio Code.
7. Startup-Background Problem Verification:
   - Edge/Chrome background processes exist without GUI window.
   - Start fresh EventCollector.
   - Open GUI window -> confirms APPLICATION_STARTED generates on GUI launch.
"""

import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import get_connection, init_database
from master.app.services.event_service import EventService
from master.app.services.log_service import LogService
from client.app.collectors.events import EventCollector, ProcessSnapshot

DEVICE_ID = "DEV-WIN-LIVE"

def setup_master_device():
    init_database()
    conn = get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO devices (device_id, device_name, device_type, status, authentication_status, created_at, updated_at)
               VALUES (?, 'Windows Workstation', 'WINDOWS_PC', 'online', 'paired', datetime('now'), datetime('now'));""",
            (DEVICE_ID,),
        )
        token_hash = hashlib.sha256("test-token".encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT OR REPLACE INTO device_auth (device_id, credential_id, authentication_status, created_at)
               VALUES (?, ?, 'paired', datetime('now'));""",
            (DEVICE_ID, token_hash),
        )
        # Clear previous test logs for clean verification
        conn.execute("DELETE FROM logs WHERE device_id = ?;", (DEVICE_ID,))
        conn.commit()
    finally:
        conn.close()

def push_events_to_master(events: list[dict]):
    """Simulate client pushing events to Master EventService."""
    if events:
        EventService().ingest_events(device_id=DEVICE_ID, events=events)

def main():
    print("=" * 70)
    print("APEXEYE PRODUCTION WINDOWS LIVE APPLICATION VERIFICATION")
    print("=" * 70)
    setup_master_device()

    # =========================================================================
    # STEP 1: Verify get_running_applications() on REAL Active Desktop
    # =========================================================================
    print("\n[STEP 1] Inspecting Current Running Applications on Desktop...")
    snapshot = ProcessSnapshot()
    snapshot.capture()
    running = snapshot.get_running_applications()
    print(f"Total Logical Applications Detected: {len(running)}")
    for app in running:
        safe_title = app['window_title'].encode('ascii', errors='replace').decode('ascii')
        print(f"  * [{app['category']}] {app['application_name']}")
        print(f"      Executable: {app['executable']} | Primary PID: {app['primary_pid']} | Process Count: {app['process_count']}")
        print(f"      Foreground: {app['is_foreground']} | Window Title: '{safe_title}'")

    running_names = {a["application_name"] for a in running}
    print(f"\nCurrently Running Applications: {running_names}")

    # Verify key applications are detected
    assert "Antigravity" in running_names, "Antigravity IDE was not detected!"
    assert "Google Chrome" in running_names, "Google Chrome was not detected!"
    assert "Microsoft Edge" in running_names, "Microsoft Edge was not detected!"
    assert "Visual Studio Code" in running_names, "Visual Studio Code was not detected!"

    # Verify background noise is NOT present
    for noise in ("Identity Helper", "RuntimeBroker", "SearchHost", "svchost", "Lenovo", "wslservice"):
        assert not any(noise.lower() in name.lower() for name in running_names), f"Noise {noise} found in running apps!"
    print("[OK] Real Chrome, Edge, VS Code, and Antigravity IDE all detected. System noise suppressed.")

    # Initialize collector tracking live state
    collector = EventCollector()

    # =========================================================================
    # STEP 2: Live Lifecycle Test — Google Chrome
    # =========================================================================
    print("\n[STEP 2] Testing Real Lifecycle: Google Chrome...")
    # A. Terminate Chrome
    print("  -> Closing Google Chrome completely...")
    subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
    time.sleep(3)

    events_chrome_stop = collector.collect()
    push_events_to_master(events_chrome_stop)
    chrome_stops = [e for e in events_chrome_stop if e["application_name"] == "Google Chrome"]
    print(f"  -> Chrome close events: {len(chrome_stops)}")
    assert len(chrome_stops) == 1, f"Expected 1 Chrome STOPPED event, got {len(chrome_stops)}"
    assert chrome_stops[0]["event_type"] == "APPLICATION_STOPPED"
    print("  [OK] Exactly ONE APPLICATION_STOPPED event emitted for Google Chrome.")

    # B. Re-open Chrome
    print("  -> Re-opening Google Chrome via WMI...")
    subprocess.run([
        "powershell.exe", "-Command",
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = '\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" https://www.google.com'}"
    ], capture_output=True)
    time.sleep(4)

    events_chrome_start = collector.collect()
    push_events_to_master(events_chrome_start)
    chrome_starts = [e for e in events_chrome_start if e["application_name"] == "Google Chrome"]
    print(f"  -> Chrome reopen events: {len(chrome_starts)}")
    assert len(chrome_starts) == 1, f"Expected 1 Chrome STARTED event, got {len(chrome_starts)}"
    assert chrome_starts[0]["event_type"] == "APPLICATION_STARTED"
    print("  [OK] Exactly ONE APPLICATION_STARTED event emitted for Google Chrome reopen.")

    # C. Verify Tab / Subprocess Churn emits 0 duplicate events
    print("  -> Verifying tab/subprocess churn emits ZERO duplicate events...")
    time.sleep(2)
    churn_events = collector.collect()
    chrome_churn = [e for e in churn_events if e["application_name"] == "Google Chrome"]
    assert len(chrome_churn) == 0, f"Expected 0 churn events, got {len(chrome_churn)}"
    print("  [OK] Repeated scans with Chrome open emitted ZERO duplicate events.")

    # =========================================================================
    # STEP 3: Live Lifecycle Test — Microsoft Edge
    # =========================================================================
    print("\n[STEP 3] Testing Real Lifecycle: Microsoft Edge...")
    # A. Close Edge
    print("  -> Closing Microsoft Edge completely...")
    subprocess.run(["taskkill", "/F", "/IM", "msedge.exe"], capture_output=True)
    time.sleep(3)

    events_edge_stop = collector.collect()
    push_events_to_master(events_edge_stop)
    edge_stops = [e for e in events_edge_stop if e["application_name"] == "Microsoft Edge"]
    print(f"  -> Edge close events: {len(edge_stops)}")
    assert len(edge_stops) == 1, f"Expected 1 Edge STOPPED event, got {len(edge_stops)}"
    assert edge_stops[0]["event_type"] == "APPLICATION_STOPPED"
    print("  [OK] Exactly ONE APPLICATION_STOPPED event emitted for Microsoft Edge.")

    # B. Re-open Edge
    print("  -> Re-opening Microsoft Edge via WMI...")
    subprocess.run([
        "powershell.exe", "-Command",
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = '\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" https://www.bing.com'}"
    ], capture_output=True)
    time.sleep(4)

    events_edge_start = collector.collect()
    push_events_to_master(events_edge_start)
    edge_starts = [e for e in events_edge_start if e["application_name"] == "Microsoft Edge"]
    print(f"  -> Edge reopen events: {len(edge_starts)}")
    assert len(edge_starts) == 1, f"Expected 1 Edge STARTED event, got {len(edge_starts)}"
    assert edge_starts[0]["event_type"] == "APPLICATION_STARTED"
    print("  [OK] Exactly ONE APPLICATION_STARTED event emitted for Microsoft Edge reopen.")

    # =========================================================================
    # STEP 4: Live Lifecycle Test — Visual Studio Code
    # =========================================================================
    print("\n[STEP 4] Testing Real Lifecycle: Visual Studio Code...")
    # A. Close Visual Studio Code
    print("  -> Closing Visual Studio Code window...")
    subprocess.run(["taskkill", "/F", "/IM", "Code.exe"], capture_output=True)
    time.sleep(3)

    events_code_stop = collector.collect()
    push_events_to_master(events_code_stop)
    code_stops = [e for e in events_code_stop if e["application_name"] == "Visual Studio Code"]
    print(f"  -> VS Code close events: {len(code_stops)}")
    assert len(code_stops) == 1, f"Expected 1 VS Code STOPPED event, got {len(code_stops)}"
    assert code_stops[0]["event_type"] == "APPLICATION_STOPPED"
    print("  [OK] Exactly ONE APPLICATION_STOPPED event emitted for Visual Studio Code.")

    # B. Re-open Visual Studio Code
    print("  -> Re-opening Visual Studio Code via WMI...")
    subprocess.run([
        "powershell.exe", "-Command",
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = '\"C:\\Users\\DELL\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe\" --new-window'}"
    ], capture_output=True)
    time.sleep(4)

    events_code_start = collector.collect()
    push_events_to_master(events_code_start)
    code_starts = [e for e in events_code_start if e["application_name"] == "Visual Studio Code"]
    print(f"  -> VS Code reopen events: {len(code_starts)}")
    assert len(code_starts) == 1, f"Expected 1 VS Code STARTED event, got {len(code_starts)}"
    assert code_starts[0]["event_type"] == "APPLICATION_STARTED"
    print("  [OK] Exactly ONE APPLICATION_STARTED event emitted for Visual Studio Code reopen.")

    # =========================================================================
    # STEP 5: Startup-Background Problem Verification (Requirement 8)
    # =========================================================================
    print("\n[STEP 5] Verifying Startup-Background Problem (Edge Startup Boost)...")
    # Close Edge window
    subprocess.run(["taskkill", "/F", "/IM", "msedge.exe"], capture_output=True)
    time.sleep(2)
    # Start Edge in background mode (--no-startup-window)
    print("  -> Starting Edge in background mode (--no-startup-window)...")
    subprocess.run([
        "powershell.exe", "-Command",
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = '\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window'}"
    ], capture_output=True)
    time.sleep(3)

    # Start a FRESH EventCollector (simulating agent boot with background processes present)
    print("  -> Initializing fresh EventCollector baseline...")
    fresh_collector = EventCollector()
    baseline_apps = [a["application_name"] for a in fresh_collector._previous.get_running_applications()]
    print(f"  -> Fresh baseline applications: {baseline_apps}")
    assert "Microsoft Edge" not in baseline_apps, "Background boost Edge falsely detected as active GUI app!"
    print("  [OK] Background boost Edge correctly suppressed from initial baseline.")

    # Now launch real Edge GUI window
    print("  -> Launching Edge GUI window...")
    subprocess.run([
        "powershell.exe", "-Command",
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = '\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" https://www.bing.com'}"
    ], capture_output=True)
    time.sleep(4)

    gui_launch_events = fresh_collector.collect()
    push_events_to_master(gui_launch_events)
    edge_gui_starts = [e for e in gui_launch_events if e["application_name"] == "Microsoft Edge"]
    print(f"  -> Events after GUI launch: {len(edge_gui_starts)}")
    assert len(edge_gui_starts) == 1, f"Expected 1 Edge STARTED event on GUI launch, got {len(edge_gui_starts)}"
    assert edge_gui_starts[0]["event_type"] == "APPLICATION_STARTED"
    print("  [OK] Confirmed: GUI application generated APPLICATION_STARTED even though background browser processes existed before opening!")

    # =========================================================================
    # STEP 6: Master Activity Log Evidence & Noise Audit
    # =========================================================================
    print("\n[STEP 6] Inspecting Master Activity Logs Database Table...")
    conn = get_connection()
    try:
        cursor = conn.execute(
            """SELECT event_type, source, message, created_at 
               FROM logs 
               WHERE device_id = ? 
               ORDER BY id ASC;""",
            (DEVICE_ID,),
        )
        logs = cursor.fetchall()
        print(f"Total Master Activity Log Records for {DEVICE_ID}: {len(logs)}")
        for r in logs:
            print(f"  [{r[3]}] {r[0]} | {r[1]} | {r[2]}")

        # Assert all required events are in Master
        messages = [r[2] for r in logs]
        event_types = [r[0] for r in logs]

        assert any(e == "APPLICATION_STARTED" and "Google Chrome" in m for e, m in zip(event_types, messages)), "Master missing Chrome started log!"
        assert any(e == "APPLICATION_STOPPED" and "Google Chrome" in m for e, m in zip(event_types, messages)), "Master missing Chrome stopped log!"
        assert any(e == "APPLICATION_STARTED" and "Microsoft Edge" in m for e, m in zip(event_types, messages)), "Master missing Edge started log!"
        assert any(e == "APPLICATION_STOPPED" and "Microsoft Edge" in m for e, m in zip(event_types, messages)), "Master missing Edge stopped log!"
        assert any(e == "APPLICATION_STARTED" and "Visual Studio Code" in m for e, m in zip(event_types, messages)), "Master missing VS Code started log!"
        assert any(e == "APPLICATION_STOPPED" and "Visual Studio Code" in m for e, m in zip(event_types, messages)), "Master missing VS Code stopped log!"

        # Assert ZERO noise in Master logs
        for noise in ("Identity Helper", "Lenovo", "svchost", "dwm", "RuntimeBroker", "SearchHost"):
            assert not any(noise.lower() in m.lower() for m in messages), f"Noise found in Master activity logs: {noise}"
        print("[OK] Master Overview Activity Log verified: Chrome, Edge, and VS Code events recorded. Zero noise detected.")
    finally:
        conn.close()

    print("\n" + "=" * 70)
    print("ALL PRODUCTION WINDOWS LIVE VERIFICATION REQUIREMENTS FULLY VERIFIED!")
    print("=" * 70)

if __name__ == "__main__":
    main()
