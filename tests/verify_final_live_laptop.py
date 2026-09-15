"""
APEXEYE — Comprehensive Final Live Laptop Verification
Windows Real Host Environment

Requirements to verify:
1. Run get_running_applications() while all of the following are actively running:
   - Chrome
   - Microsoft Edge
   - Visual Studio Code
   - Antigravity
   - ChatGPT
   - WhatsApp
   - PowerShell
   - Command Prompt
2. Confirm zero Windows OS system infrastructure appears in the application snapshot.
3. Close Chrome -> exactly ONE APPLICATION_STOPPED.
4. Reopen Chrome -> exactly ONE APPLICATION_STARTED.
5. Close VS Code -> exactly ONE APPLICATION_STOPPED.
6. Reopen VS Code -> exactly ONE APPLICATION_STARTED.
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

def main():
    print("=" * 70)
    print("APEXEYE — FINAL LIVE LAPTOP VERIFICATION ON REAL WINDOWS HOST")
    print("=" * 70)

    # Executable paths
    chrome_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    edge_exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    code_exe = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe")

    procs_to_cleanup = []

    # Ensure Edge, Chrome, and VS Code are running
    print("\n[SETUP] Launching Chrome, Edge, and VS Code to ensure all 8 applications run concurrently...")
    if os.path.exists(chrome_exe):
        procs_to_cleanup.append(subprocess.Popen([chrome_exe, "about:blank"]))
    if os.path.exists(edge_exe):
        procs_to_cleanup.append(subprocess.Popen([edge_exe, "about:blank"]))
    if os.path.exists(code_exe):
        procs_to_cleanup.append(subprocess.Popen([code_exe, "--no-sandbox"]))

    time.sleep(4)

    try:
        collector = EventCollector()
        running_apps = collector.get_running_applications()
        print(f"\n[LIVE SNAPSHOT] get_running_applications() returned {len(running_apps)} applications:\n")
        
        app_map = {}
        for app in running_apps:
            name = app["application_name"]
            app_map[name] = app
            print(f"  * {name:<25} | Cat: {app['category']:<15} | Primary PID: {app['primary_pid']:<6} | Procs: {app['process_count']:<3} | Exe: {app['executable']}")

        print("\n" + "-" * 70)
        print("CHECKING ALL 8 REQUIRED APPLICATIONS ARE DETECTED:")
        print("-" * 70)

        required_apps = {
            "Google Chrome": "Chrome",
            "Microsoft Edge": "Edge",
            "Visual Studio Code": "VS Code",
            "Antigravity": "Antigravity",
            "ChatGPT": "ChatGPT",
            "WhatsApp": "WhatsApp",
            "PowerShell": "PowerShell",
            "Command Prompt": "Command Prompt",
        }

        all_detected = True
        for app_name, label in required_apps.items():
            if app_name in app_map:
                info = app_map[app_name]
                print(f"  [OK] {label:<16} -> DETECTED as '{app_name}' (PIDs: {info['process_count']})")
            else:
                print(f"  [FAIL] {label:<16} -> NOT FOUND in running applications snapshot!")
                all_detected = False

        assert all_detected, "Not all 8 required applications were detected in the running application snapshot!"

        print("\n" + "-" * 70)
        print("CONFIRMING ZERO WINDOWS OS INFRASTRUCTURE / SYSTEM SERVICES APPEAR:")
        print("-" * 70)
        
        system_noise_procs = [
            "svchost.exe", "dwm.exe", "runtimebroker.exe", "searchhost.exe",
            "explorer.exe", "services.exe", "smss.exe", "csrss.exe", "wininit.exe",
            "taskhostw.exe", "sihost.exe", "ctfmon.exe", "audiodg.exe",
            "msmpeng.exe", "securityhealthservice.exe", "defendersessionhelper.exe"
        ]

        found_noise = []
        for app in running_apps:
            exe_lower = app["executable"].lower()
            name_lower = app["application_name"].lower()
            for noise in system_noise_procs:
                if noise in exe_lower or noise in name_lower:
                    found_noise.append((app["application_name"], app["executable"]))

        if found_noise:
            print(f"  [FAIL] Found prohibited system noise in applications: {found_noise}")
            assert False, f"Prohibited OS system infrastructure detected: {found_noise}"
        else:
            print("  [OK] Zero Windows system services/infrastructure present in running applications.")

        # ======================================================================
        # LIFECYCLE TEST 1: CHROME CLOSE & REOPEN
        # ======================================================================
        print("\n" + "-" * 70)
        print("TESTING CHROME LIFECYCLE (CLOSE -> REOPEN):")
        print("-" * 70)

        print("1. Terminating Google Chrome...")
        subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
        time.sleep(2)

        stop_events_chrome = collector.collect()
        chrome_stops = [e for e in stop_events_chrome if e.get("application_name") == "Google Chrome"]
        print(f"   Collected events after Chrome close ({len(stop_events_chrome)} total):")
        for e in stop_events_chrome:
            print(f"     -> {e['event_type']}: {e['application_name']} (PID: {e['pid']})")
        assert len(chrome_stops) == 1, f"Expected 1 APPLICATION_STOPPED for Chrome, got {len(chrome_stops)}"
        assert chrome_stops[0]["event_type"] == "APPLICATION_STOPPED"
        print("   [OK] Google Chrome emitted exactly ONE APPLICATION_STOPPED event.")

        print("2. Reopening Google Chrome...")
        p_chrome_reopen = subprocess.Popen([chrome_exe, "about:blank"])
        procs_to_cleanup.append(p_chrome_reopen)
        time.sleep(3)

        start_events_chrome = collector.collect()
        chrome_starts = [e for e in start_events_chrome if e.get("application_name") == "Google Chrome"]
        print(f"   Collected events after Chrome reopen ({len(start_events_chrome)} total):")
        for e in start_events_chrome:
            print(f"     -> {e['event_type']}: {e['application_name']} (PID: {e['pid']})")
        assert len(chrome_starts) == 1, f"Expected 1 APPLICATION_STARTED for Chrome, got {len(chrome_starts)}"
        assert chrome_starts[0]["event_type"] == "APPLICATION_STARTED"
        print("   [OK] Google Chrome emitted exactly ONE APPLICATION_STARTED event.")

        # ======================================================================
        # LIFECYCLE TEST 2: VS CODE CLOSE & REOPEN
        # ======================================================================
        print("\n" + "-" * 70)
        print("TESTING VISUAL STUDIO CODE LIFECYCLE (CLOSE -> REOPEN):")
        print("-" * 70)

        print("1. Terminating Visual Studio Code...")
        subprocess.run(["taskkill", "/F", "/IM", "Code.exe"], capture_output=True)
        time.sleep(2)

        stop_events_code = collector.collect()
        code_stops = [e for e in stop_events_code if e.get("application_name") == "Visual Studio Code"]
        print(f"   Collected events after VS Code close ({len(stop_events_code)} total):")
        for e in stop_events_code:
            print(f"     -> {e['event_type']}: {e['application_name']} (PID: {e['pid']})")
        assert len(code_stops) == 1, f"Expected 1 APPLICATION_STOPPED for Visual Studio Code, got {len(code_stops)}"
        assert code_stops[0]["event_type"] == "APPLICATION_STOPPED"
        print("   [OK] Visual Studio Code emitted exactly ONE APPLICATION_STOPPED event.")

        print("2. Reopening Visual Studio Code...")
        p_code_reopen = subprocess.Popen([code_exe, "--no-sandbox"])
        procs_to_cleanup.append(p_code_reopen)
        time.sleep(3)

        start_events_code = collector.collect()
        code_starts = [e for e in start_events_code if e.get("application_name") == "Visual Studio Code"]
        print(f"   Collected events after VS Code reopen ({len(start_events_code)} total):")
        for e in start_events_code:
            print(f"     -> {e['event_type']}: {e['application_name']} (PID: {e['pid']})")
        assert len(code_starts) == 1, f"Expected 1 APPLICATION_STARTED for Visual Studio Code, got {len(code_starts)}"
        assert code_starts[0]["event_type"] == "APPLICATION_STARTED"
        print("   [OK] Visual Studio Code emitted exactly ONE APPLICATION_STARTED event.")

        print("\n" + "=" * 70)
        print("ALL VERIFICATIONS COMPLETED SUCCESSFULLY WITH ZERO ERRORS!")
        print("=" * 70)

    finally:
        for p in procs_to_cleanup:
            try:
                p.terminate()
            except Exception:
                pass
        subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "msedge.exe"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "Code.exe"], capture_output=True)

if __name__ == "__main__":
    main()
