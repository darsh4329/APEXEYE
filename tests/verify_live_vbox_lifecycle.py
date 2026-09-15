"""
APEXEYE — VirtualBox Live Dynamic Lifecycle Verification
Verifies lifecycle behavior on VirtualBox (which is dynamically detected without taxonomy):
1. Record baseline with VirtualBox running.
2. Terminate VirtualBox -> exactly ONE APPLICATION_STOPPED.
3. Relaunch VirtualBox -> exactly ONE APPLICATION_STARTED.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.collectors.events import EventCollector

def main():
    print("=" * 70)
    print("VIRTUALBOX LIVE LIFECYCLE VERIFICATION (DYNAMIC NON-TAXONOMY APP)")
    print("=" * 70)

    vbox_exe = r"C:\Program Files\Oracle\VirtualBox\VirtualBox.exe"
    if not os.path.exists(vbox_exe):
        print("[SKIP] VirtualBox.exe not found at path.")
        return

    collector = EventCollector()
    initial_apps = collector.get_running_applications()
    vbox_app = next((a for a in initial_apps if "virtualbox" in a["application_name"].lower() or "virtualbox" in a["executable"].lower()), None)
    
    print("\n1. Initial Baseline Check:")
    if vbox_app:
        print(f"   [OK] VirtualBox is currently running and detected:")
        print(f"        Name: {vbox_app['application_name']}")
        print(f"        Executable: {vbox_app['executable']}")
        print(f"        Category: {vbox_app['category']}")
        print(f"        PIDs: {vbox_app['pids']}")
    else:
        print("   [INFO] VirtualBox not detected in baseline. Launching it first...")
        subprocess.Popen([vbox_exe])
        time.sleep(3)
        collector.collect()

    # Step 2: Terminate VirtualBox
    print("\n2. Terminating VirtualBox...")
    subprocess.run(["taskkill", "/IM", "VirtualBox.exe"], capture_output=True)
    time.sleep(3)

    stop_events = collector.collect()
    print(f"   Events emitted on VirtualBox termination ({len(stop_events)} total):")
    for e in stop_events:
        print(f"     -> {e['event_type']}: {e['application_name']} (PID: {e['pid']})")

    vbox_stops = [e for e in stop_events if "virtualbox" in e.get("application_name", "").lower() or "virtualbox" in e.get("process_name", "").lower()]
    assert len(vbox_stops) == 1, f"Expected exactly 1 APPLICATION_STOPPED for VirtualBox, got {len(vbox_stops)}"
    assert vbox_stops[0]["event_type"] == "APPLICATION_STOPPED"
    print("   [PASS] Exactly 1 APPLICATION_STOPPED emitted on VirtualBox termination.")

    # Step 3: Relaunch VirtualBox
    print("\n3. Relaunching VirtualBox...")
    p = subprocess.Popen([vbox_exe])
    time.sleep(3)

    start_events = collector.collect()
    print(f"   Events emitted on VirtualBox relaunch ({len(start_events)} total):")
    for e in start_events:
        print(f"     -> {e['event_type']}: {e['application_name']} (PID: {e['pid']})")

    vbox_starts = [e for e in start_events if "virtualbox" in e.get("application_name", "").lower() or "virtualbox" in e.get("process_name", "").lower()]
    assert len(vbox_starts) == 1, f"Expected exactly 1 APPLICATION_STARTED for VirtualBox, got {len(vbox_starts)}"
    assert vbox_starts[0]["event_type"] == "APPLICATION_STARTED"
    print("   [PASS] Exactly 1 APPLICATION_STARTED emitted on VirtualBox relaunch.")

    print("\n" + "=" * 70)
    print("VIRTUALBOX DYNAMIC LIFECYCLE VERIFICATION SUCCEEDED!")
    print("=" * 70)

if __name__ == "__main__":
    main()
