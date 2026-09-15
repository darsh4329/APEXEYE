"""
Live Windows Application Detection Script
Inspects currently running applications on the physical Windows workstation.
"""
import json
import sys
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.collectors.events import ProcessSnapshot, EventCollector

def main():
    print("=" * 60)
    print("APEXEYE LIVE WORKSTATION RUNNING APPLICATIONS SNAPSHOT")
    print("=" * 60)
    snapshot = ProcessSnapshot()
    snapshot.capture()
    apps = snapshot.get_running_applications()
    print(f"Total Logical Applications Detected: {len(apps)}\n")
    for app in apps:
        print(f"[{app['category']}] {app['application_name']}")
        print(f"   Executable: {app['executable']}")
        print(f"   Primary PID: {app['primary_pid']} | Process Count: {app['process_count']} | PIDs: {app['pids']}")
        safe_title = app['window_title'].encode('ascii', errors='replace').decode('ascii')
        print(f"   Foreground: {app['is_foreground']} | Window Title: {safe_title}")
        print("-" * 50)

if __name__ == "__main__":
    main()
