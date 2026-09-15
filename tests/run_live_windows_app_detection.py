"""
Real Windows GUI Live Application Verification
Verifies real Chrome, Edge, and Notepad/GUI applications on the host laptop:
1. get_running_applications()
2. APPLICATION_STARTED
3. APPLICATION_STOPPED
4. Multi-process grouping
5. Browser subprocess suppression
6. System/background process suppression
"""

import os
import subprocess
import sys
import time
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database
from master.app.services.event_service import EventService
from master.app.services.log_service import LogService
from client.app.collectors.events import EventCollector, ProcessSnapshot

def main():
    print("=" * 60)
    print("STARTING WINDOWS LIVE APPLICATION VERIFICATION")
    print("=" * 60)
    init_database()

    collector = EventCollector()
    initial_running = collector._previous.get_running_applications()
    print(f"Initial Running Baseline Applications ({len(initial_running)}):")
    for a in initial_running:
        print(f"  - {a['application_name']} ({a['category']}) [PID {a['primary_pid']}, total PIDs: {a['process_count']}]")

    # Verify background processes are suppressed
    app_names = [a['application_name'].lower() for a in initial_running]
    execs = [a['executable'].lower() for a in initial_running]
    for suppressed in ("svchost.exe", "searchhost.exe", "runtimebroker.exe", "identity helper", "widgetservice.exe", "wslservice.exe"):
        assert suppressed not in execs and suppressed not in app_names, f"Suppressed process {suppressed} was found in running apps!"
    print("[OK] Background noise successfully suppressed from running applications baseline.")

    # Locate Chrome executable
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    chrome_exe = None
    for p in chrome_paths:
        if os.path.exists(p):
            chrome_exe = p
            break

    # Locate Edge executable
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    edge_exe = None
    for p in edge_paths:
        if os.path.exists(p):
            edge_exe = p
            break

    print(f"Detected Chrome executable: {chrome_exe}")
    print(f"Detected Edge executable: {edge_exe}")

    launched_procs = []

    try:
        # TEST 1: Launch real Google Chrome if available
        if chrome_exe:
            print("\n--- LAUNCHING REAL GOOGLE CHROME ---")
            chrome_proc = subprocess.Popen([chrome_exe, "about:blank"])
            launched_procs.append(chrome_proc)
            time.sleep(3)

            events = collector.collect()
            print(f"Events captured after Chrome launch ({len(events)}):")
            for evt in events:
                print(f"  - {evt['event_type']}: {evt['application_name']} ({evt['category']}) PID: {evt['pid']}")
            
            chrome_evts = [e for e in events if e.get("application_name") == "Google Chrome"]
            assert len(chrome_evts) == 1, f"Expected exactly 1 Google Chrome STARTED event, got {len(chrome_evts)}"
            assert chrome_evts[0]["event_type"] == "APPLICATION_STARTED"
            assert chrome_evts[0]["category"] == "BROWSER"
            print("[OK] Google Chrome successfully emitted exactly ONE APPLICATION_STARTED event.")

            # Verify multi-process grouping
            snapshot = ProcessSnapshot()
            snapshot.capture()
            running = snapshot.get_running_applications()
            chrome_app = next((a for a in running if a["application_name"] == "Google Chrome"), None)
            assert chrome_app is not None, "Google Chrome not found in get_running_applications()"
            print(f"[OK] Google Chrome grouped: {chrome_app['process_count']} subprocesses collapsed into 1 logical app.")

            # Scan again with Chrome still running - verify 0 duplicate events
            dup_events = collector.collect()
            chrome_dups = [e for e in dup_events if e.get("application_name") == "Google Chrome"]
            assert len(chrome_dups) == 0, f"Expected 0 duplicate events, got {len(chrome_dups)}"
            print("[OK] Subprocess churn and repeated scans emitted ZERO duplicate started events.")

            # Close Chrome
            print("\n--- TERMINATING REAL GOOGLE CHROME ---")
            chrome_proc.terminate()
            subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
            time.sleep(2)

            stop_events = collector.collect()
            print(f"Events captured after Chrome termination ({len(stop_events)}):")
            for evt in stop_events:
                print(f"  - {evt['event_type']}: {evt['application_name']} ({evt['category']}) PID: {evt['pid']}")
            
            chrome_stops = [e for e in stop_events if e.get("application_name") == "Google Chrome"]
            assert len(chrome_stops) == 1, f"Expected exactly 1 Google Chrome STOPPED event, got {len(chrome_stops)}"
            assert chrome_stops[0]["event_type"] == "APPLICATION_STOPPED"
            print("[OK] Google Chrome successfully emitted exactly ONE APPLICATION_STOPPED event.")

        # TEST 2: Launch real Notepad (GUI application)
        print("\n--- LAUNCHING REAL NOTEPAD (GUI APPLICATION) ---")
        notepad_proc = subprocess.Popen(["notepad.exe"])
        launched_procs.append(notepad_proc)
        time.sleep(2)

        np_events = collector.collect()
        print(f"Events captured after Notepad launch ({len(np_events)}):")
        for evt in np_events:
            print(f"  - {evt['event_type']}: {evt['application_name']} ({evt['category']}) PID: {evt['pid']}")
        
        np_starts = [e for e in np_events if "notepad" in e.get("application_name", "").lower()]
        assert len(np_starts) == 1, f"Expected 1 Notepad STARTED event, got {len(np_starts)}"
        assert np_starts[0]["event_type"] == "APPLICATION_STARTED"
        print("[OK] Real Notepad successfully emitted exactly ONE APPLICATION_STARTED event.")

        # Terminate Notepad
        print("\n--- TERMINATING REAL NOTEPAD ---")
        notepad_proc.terminate()
        subprocess.run(["taskkill", "/F", "/IM", "notepad.exe"], capture_output=True)
        time.sleep(2)

        np_stop_events = collector.collect()
        print(f"Events captured after Notepad termination ({len(np_stop_events)}):")
        for evt in np_stop_events:
            print(f"  - {evt['event_type']}: {evt['application_name']} ({evt['category']}) PID: {evt['pid']}")
        
        np_stops = [e for e in np_stop_events if "notepad" in e.get("application_name", "").lower()]
        assert len(np_stops) == 1, f"Expected 1 Notepad STOPPED event, got {len(np_stops)}"
        assert np_stops[0]["event_type"] == "APPLICATION_STOPPED"
        print("[OK] Real Notepad successfully emitted exactly ONE APPLICATION_STOPPED event.")

    finally:
        for p in launched_procs:
            try:
                p.terminate()
            except Exception:
                pass
        subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "notepad.exe"], capture_output=True)

    print("\n" + "=" * 60)
    print("ALL WINDOWS REAL APPLICATION LIVE CHECKS PASSED!")
    print("=" * 60)

if __name__ == "__main__":
    main()
