"""
APEXEYE LINUX CLIENT — Live Application Activity Detection Verification Runner

Verifies production Linux application activity detection implementation:
1. get_running_applications()
2. APPLICATION_STARTED
3. APPLICATION_STOPPED
4. multi-process grouping (Chrome/Chromium, VS Code, Firefox/Gedit)
5. browser/Electron subprocess suppression (zygote, renderer, gpu, utility, crashpad)
6. system/background process suppression (systemd, dbus, nginx, dockerd, kernel threads)
"""

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database
from client_linux.app.collectors.events import (
    EventCollector,
    ProcessSnapshot,
    _is_kernel_or_system_noise,
    _is_browser_or_electron_subworker,
    _resolve_application_metadata,
    _get_desktop_entry_metadata,
)

def run_live_linux_app_verification():
    print("=" * 70)
    print("APEXEYE LINUX CLIENT — LIVE APPLICATION DETECTION VERIFICATION")
    print("=" * 70)
    init_database()

    # Environment check: Determine if graphical desktop is available
    display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    has_graphical_desktop = bool(display)
    print(f"[*] Linux Graphical Desktop Environment: {'AVAILABLE (' + str(display) + ')' if has_graphical_desktop else 'HEADLESS / NON-DISPLAY SESSION'}")

    # =========================================================================
    # 1. System and Daemon Process Suppression Verification
    # =========================================================================
    print("\n--- 1. SYSTEM / BACKGROUND PROCESS SUPPRESSION ---")
    system_test_cases = [
        (1, "systemd", 0),
        (2, "kthreadd", 0),
        (10, "[kworker/0:0]", 2),
        (15, "ksoftirqd/0", 2),
        (200, "systemd-journald", 1),
        (250, "dbus-daemon", 1),
        (350, "polkitd", 1),
        (400, "nginx", 1),
        (420, "apache2", 1),
        (450, "dockerd", 1),
    ]
    for pid, name, ppid in system_test_cases:
        is_noise = _is_kernel_or_system_noise(pid, name, ppid=ppid)
        assert is_noise is True, f"Failed to suppress system daemon: {name} (PID {pid})"
    print("[OK] Successfully verified suppression of systemd, dbus, nginx, dockerd, and kernel threads.")

    # =========================================================================
    # 2. Browser / Electron Subprocess Role Suppression Verification
    # =========================================================================
    print("\n--- 2. BROWSER & ELECTRON SUBPROCESS SUPPRESSION ---")
    subworker_cmdlines = [
        ["/opt/google/chrome/chrome", "--type=renderer", "--field-trial-handle=..."],
        ["/opt/google/chrome/chrome", "--type=gpu-process"],
        ["/opt/google/chrome/chrome", "--type=utility", "--utility-sub-type=network.mojom.NetworkService"],
        ["/opt/google/chrome/chrome", "--type=zygote"],
        ["/opt/google/chrome/chrome", "--type=crashpad-handler"],
        ["/usr/share/code/code", "--type=renderer"],
        ["/usr/share/code/code", "--type=utility"],
        ["/usr/share/code/code", "--type=gpu-process"],
    ]
    for cmd in subworker_cmdlines:
        mock_p = MagicMock()
        mock_p.cmdline.return_value = cmd
        assert _is_browser_or_electron_subworker(mock_p) is True, f"Subworker not recognized: {cmd}"
    
    # Verify main application processes are NOT marked as subworkers
    main_cmdlines = [
        ["/opt/google/chrome/chrome"],
        ["/usr/share/code/code", "--unity-launch"],
        ["/usr/bin/gedit", "/home/user/document.txt"],
        ["/usr/bin/firefox"],
    ]
    for cmd in main_cmdlines:
        mock_p = MagicMock()
        mock_p.cmdline.return_value = cmd
        assert _is_browser_or_electron_subworker(mock_p) is False, f"Main app falsely marked as subworker: {cmd}"
    print("[OK] Successfully verified browser/Electron subprocess suppression (--type=renderer/gpu/utility/zygote/crashpad).")

    # =========================================================================
    # 3. Dynamic Application Metadata & Desktop Entry Resolution
    # =========================================================================
    print("\n--- 3. DYNAMIC METADATA & DESKTOP RESOLUTION ---")
    assert _resolve_application_metadata("google-chrome")[0] == "Google Chrome"
    assert _resolve_application_metadata("google-chrome")[1] == "BROWSER"
    assert _resolve_application_metadata("chromium")[0] == "Chromium"
    assert _resolve_application_metadata("code")[0] == "Visual Studio Code"
    assert _resolve_application_metadata("code")[1] == "DEVELOPMENT"
    assert _resolve_application_metadata("gedit")[0] == "gedit Text Editor"
    assert _resolve_application_metadata("gedit")[1] == "PRODUCTIVITY"
    assert _resolve_application_metadata("firefox")[0] == "Mozilla Firefox"
    print("[OK] Dynamic naming and taxonomy categorization verified for Chrome, VS Code, and desktop GUI applications.")

    # =========================================================================
    # 4. Multi-Process Grouping & get_running_applications()
    # =========================================================================
    print("\n--- 4. MULTI-PROCESS GROUPING & SNAPSHOT API ---")
    snap = ProcessSnapshot()
    mock_procs = []
    
    # 1 Main Chrome + 6 Chrome worker processes
    p_chrome_main = MagicMock(); p_chrome_main.info = {"pid": 2101, "name": "chrome", "ppid": 1000}
    p_chrome_main.cmdline.return_value = ["/opt/google/chrome/chrome"]
    mock_procs.append(p_chrome_main)
    for i in range(1, 7):
        p_sub = MagicMock(); p_sub.info = {"pid": 2101 + i, "name": "chrome", "ppid": 2101}
        p_sub.cmdline.return_value = ["/opt/google/chrome/chrome", "--type=renderer"]
        mock_procs.append(p_sub)

    # 1 Main VS Code + 4 VS Code worker processes
    p_code_main = MagicMock(); p_code_main.info = {"pid": 3201, "name": "code", "ppid": 1000}
    p_code_main.cmdline.return_value = ["/usr/share/code/code"]
    mock_procs.append(p_code_main)
    for i in range(1, 5):
        p_sub = MagicMock(); p_sub.info = {"pid": 3201 + i, "name": "code", "ppid": 3201}
        p_sub.cmdline.return_value = ["/usr/share/code/code", "--type=utility"]
        mock_procs.append(p_sub)

    # 1 Main Gedit process
    p_gedit = MagicMock(); p_gedit.info = {"pid": 4101, "name": "gedit", "ppid": 1000}
    p_gedit.cmdline.return_value = ["gedit"]
    mock_procs.append(p_gedit)

    # 2 System daemons that MUST NOT appear
    p_daemon1 = MagicMock(); p_daemon1.info = {"pid": 105, "name": "systemd-resolved", "ppid": 1}
    p_daemon2 = MagicMock(); p_daemon2.info = {"pid": 110, "name": "nginx", "ppid": 1}
    mock_procs.extend([p_daemon1, p_daemon2])

    with patch("client_linux.app.collectors.events.psutil.process_iter", return_value=mock_procs):
        snap.capture()

    running_apps = snap.get_running_applications()
    print(f"Running applications detected in snapshot ({len(running_apps)}):")
    for app in running_apps:
        print(f"  - [{app['category']}] {app['application_name']} (Executable: {app['executable']}, PIDs: {app['process_count']})")

    assert len(running_apps) == 3, f"Expected exactly 3 logical applications, got {len(running_apps)}"
    app_map = {a["application_name"]: a for a in running_apps}
    assert "Google Chrome" in app_map
    assert app_map["Google Chrome"]["process_count"] == 7
    assert app_map["Google Chrome"]["primary_pid"] == 2101

    assert "Visual Studio Code" in app_map
    assert app_map["Visual Studio Code"]["process_count"] == 5
    assert app_map["Visual Studio Code"]["primary_pid"] == 3201

    assert "gedit Text Editor" in app_map
    assert app_map["gedit Text Editor"]["process_count"] == 1
    assert app_map["gedit Text Editor"]["primary_pid"] == 4101

    assert "NGINX Web Server" not in app_map
    assert "systemd-resolved" not in app_map
    print("[OK] Multi-process grouping verified: 7 Chrome processes -> 1 app, 5 VS Code processes -> 1 app, 1 Gedit -> 1 app. Daemons suppressed.")

    # =========================================================================
    # 5. Application Lifecycle State Machine (STARTED -> CHURN -> STOPPED)
    # =========================================================================
    print("\n--- 5. APPLICATION LIFECYCLE STATE MACHINE (0 -> 1+ -> 0) ---")
    collector = EventCollector()
    collector._previous.processes = {}

    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        # Step A: Launch Chrome (1 main + 3 workers)
        mock_iter.return_value = [p_chrome_main, mock_procs[1], mock_procs[2], mock_procs[3]]
        events_start = collector.collect()
        assert len(events_start) == 1
        assert events_start[0]["event_type"] == "APPLICATION_STARTED"
        assert events_start[0]["application_name"] == "Google Chrome"
        assert events_start[0]["category"] == "BROWSER"
        print(f"[OK] 0 -> 1+ transition: Emitted exactly ONE APPLICATION_STARTED for Google Chrome.")

        # Step B: Worker process churn (3 more workers spawn)
        mock_iter.return_value = [p_chrome_main] + mock_procs[1:7]
        events_churn = collector.collect()
        assert len(events_churn) == 0, f"Expected 0 events during worker churn, got {len(events_churn)}"
        print(f"[OK] Worker process churn: Emitted ZERO extra events when subprocesses spawn.")

        # Step C: Subprocess exits while main process still lives
        mock_iter.return_value = [p_chrome_main, mock_procs[1]]
        events_partial = collector.collect()
        assert len(events_partial) == 0, f"Expected 0 events while app still open, got {len(events_partial)}"
        print(f"[OK] Partial worker exit: Emitted ZERO events while main application still lives.")

        # Step D: All Chrome processes exit
        mock_iter.return_value = []
        events_stop = collector.collect()
        assert len(events_stop) == 1
        assert events_stop[0]["event_type"] == "APPLICATION_STOPPED"
        assert events_stop[0]["application_name"] == "Google Chrome"
        print(f"[OK] 1+ -> 0 transition: Emitted exactly ONE APPLICATION_STOPPED for Google Chrome.")

        # Step E: Launch VS Code and Gedit simultaneously
        mock_iter.return_value = [p_code_main, mock_procs[8], p_gedit]
        events_multi_start = collector.collect()
        assert len(events_multi_start) == 2
        names = {e["application_name"] for e in events_multi_start}
        assert "Visual Studio Code" in names
        assert "gedit Text Editor" in names
        print(f"[OK] Simultaneous launch: Emitted exactly ONE event per distinct logical application.")

        # Step F: Close VS Code only, keep Gedit open
        mock_iter.return_value = [p_gedit]
        events_code_close = collector.collect()
        assert len(events_code_close) == 1
        assert events_code_close[0]["event_type"] == "APPLICATION_STOPPED"
        assert events_code_close[0]["application_name"] == "Visual Studio Code"
        print(f"[OK] Selective termination: Emitted APPLICATION_STOPPED for closed app without affecting running app.")

        # Step G: Close Gedit
        mock_iter.return_value = []
        events_gedit_close = collector.collect()
        assert len(events_gedit_close) == 1
        assert events_gedit_close[0]["event_type"] == "APPLICATION_STOPPED"
        assert events_gedit_close[0]["application_name"] == "gedit Text Editor"
        print(f"[OK] Final app termination: Emitted APPLICATION_STOPPED for gedit.")

    print("\n" + "=" * 70)
    print("ALL LINUX APPLICATION ACTIVITY DETECTION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_live_linux_app_verification()
