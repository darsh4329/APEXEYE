"""
Real Windows Host Verification — Chrome Lifecycle, Tab Churn, and Grouping
Validates against actual running Chrome on the developer's laptop:
1. get_running_applications() detects real running apps (Antigravity, ChatGPT, WhatsApp, etc.).
2. No Windows OS infrastructure or background services appear.
3. Open Chrome -> exactly ONE APPLICATION_STARTED.
4. Open multiple Chrome tabs -> ZERO duplicate started events (subprocess churn suppressed).
5. Terminate Chrome -> exactly ONE APPLICATION_STOPPED.
6. Reopen Chrome -> exactly ONE APPLICATION_STARTED.
7. Close Chrome again -> exactly ONE APPLICATION_STOPPED.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.collectors.events import EventCollector, ProcessSnapshot

def test_live_chrome_tab_churn_and_lifecycle():
    print("=" * 65)
    print("RUNNING LIVE CHROME TAB CHURN & LIFECYCLE TEST ON WINDOWS HOST")
    print("=" * 65)

    collector = EventCollector()
    running_baseline = collector.get_running_applications()
    print(f"\n1. Baseline Running Applications ({len(running_baseline)}):")
    app_names = [a["application_name"] for a in running_baseline]
    for a in running_baseline:
        print(f"   * {a['application_name']} ({a['category']}) - PIDs: {a['process_count']}")

    # Confirm key user apps appear if present
    for must_detect in ["Antigravity", "ChatGPT", "WhatsApp"]:
        if must_detect in app_names:
            print(f"[CONFIRMED] Real running app detected: {must_detect}")

    # Confirm OS infrastructure does NOT appear
    for noise in ["svchost.exe", "dwm.exe", "RuntimeBroker.exe", "SearchHost.exe", "explorer.exe"]:
        assert noise.lower() not in [a["executable"].lower() for a in running_baseline]
        assert noise.lower() not in [a["application_name"].lower() for a in running_baseline]
    print("[CONFIRMED] Zero OS system infrastructure/services in running applications.")

    # Locate Chrome executable
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    chrome_exe = next((p for p in chrome_paths if os.path.exists(p)), None)
    if not chrome_exe:
        print("[SKIP] Chrome executable not installed at standard paths.")
        return

    # Ensure no lingering Chrome processes before test starts
    subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
    time.sleep(1)
    # Flush collector baseline
    collector.collect()

    try:
        # STEP 1: Launch Chrome
        print("\n2. Launching Chrome (main window)...")
        p1 = subprocess.Popen([chrome_exe, "about:blank"])
        time.sleep(3)

        evts_start = collector.collect()
        chrome_starts = [e for e in evts_start if e.get("application_name") == "Google Chrome"]
        print(f"   Events emitted: {[e['event_type'] + ':' + e['application_name'] for e in evts_start]}")
        assert len(chrome_starts) == 1, f"Expected 1 APPLICATION_STARTED for Chrome, got {len(chrome_starts)}"
        assert chrome_starts[0]["event_type"] == "APPLICATION_STARTED"
        assert chrome_starts[0]["category"] == "BROWSER"
        print("   [PASS] Exactly 1 APPLICATION_STARTED emitted on initial launch.")

        # Check multi-process grouping
        snap = ProcessSnapshot()
        snap.capture()
        chrome_app = next((a for a in snap.get_running_applications() if a["application_name"] == "Google Chrome"), None)
        assert chrome_app is not None, "Chrome not found in running applications snapshot"
        initial_pids = chrome_app["process_count"]
        print(f"   [PASS] Chrome collapsed into 1 logical application ({initial_pids} processes).")

        # STEP 2: Open multiple new tabs (subprocess churn)
        print("\n3. Opening 3 additional Chrome tabs (simulating tab churn)...")
        subprocess.Popen([chrome_exe, "about:blank"])
        subprocess.Popen([chrome_exe, "about:blank"])
        subprocess.Popen([chrome_exe, "about:blank"])
        time.sleep(3)

        evts_churn = collector.collect()
        chrome_churn_starts = [e for e in evts_churn if e.get("application_name") == "Google Chrome"]
        print(f"   Events emitted during tab churn: {len(chrome_churn_starts)}")
        assert len(chrome_churn_starts) == 0, f"Expected 0 Chrome started events on tab opening, got {len(chrome_churn_starts)}"
        print("   [PASS] Opening tabs emitted ZERO duplicate started events.")

        # STEP 3: Close Chrome
        print("\n4. Terminating Chrome...")
        subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
        time.sleep(2)

        evts_stop = collector.collect()
        chrome_stops = [e for e in evts_stop if e.get("application_name") == "Google Chrome"]
        print(f"   Events emitted: {[e['event_type'] + ':' + e['application_name'] for e in evts_stop]}")
        assert len(chrome_stops) == 1, f"Expected 1 APPLICATION_STOPPED for Chrome, got {len(chrome_stops)}"
        assert chrome_stops[0]["event_type"] == "APPLICATION_STOPPED"
        print("   [PASS] Exactly 1 APPLICATION_STOPPED emitted on Chrome close.")

        # STEP 4: Reopen Chrome
        print("\n5. Reopening Chrome...")
        p2 = subprocess.Popen([chrome_exe, "about:blank"])
        time.sleep(3)

        evts_reopen = collector.collect()
        chrome_reopens = [e for e in evts_reopen if e.get("application_name") == "Google Chrome"]
        print(f"   Events emitted: {[e['event_type'] + ':' + e['application_name'] for e in evts_reopen]}")
        assert len(chrome_reopens) == 1, f"Expected 1 APPLICATION_STARTED for Chrome on reopen, got {len(chrome_reopens)}"
        assert chrome_reopens[0]["event_type"] == "APPLICATION_STARTED"
        print("   [PASS] Exactly 1 APPLICATION_STARTED emitted on Chrome reopen.")

        # STEP 5: Close Chrome again
        print("\n6. Terminating Chrome final time...")
        subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
        time.sleep(2)

        evts_stop2 = collector.collect()
        chrome_stops2 = [e for e in evts_stop2 if e.get("application_name") == "Google Chrome"]
        print(f"   Events emitted: {[e['event_type'] + ':' + e['application_name'] for e in evts_stop2]}")
        assert len(chrome_stops2) == 1, f"Expected 1 APPLICATION_STOPPED for Chrome on final close, got {len(chrome_stops2)}"
        assert chrome_stops2[0]["event_type"] == "APPLICATION_STOPPED"
        print("   [PASS] Exactly 1 APPLICATION_STOPPED emitted on final close.")

    finally:
        subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)

    print("\n" + "=" * 65)
    print("ALL REAL CHROME LIFECYCLE & TAB CHURN CHECKS SUCCEEDED!")
    print("=" * 65)

if __name__ == "__main__":
    test_live_chrome_tab_churn_and_lifecycle()
