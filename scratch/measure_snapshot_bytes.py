"""
Measure memory of ProcessSnapshot and string interning impact.
"""
import sys
import gc
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.collectors.events import ProcessSnapshot

def inspect_snapshot_memory():
    gc.collect()
    snap = ProcessSnapshot()
    snap.capture()

    proc_count = len(snap.processes)
    apps = snap.get_running_applications()
    app_count = len(apps)

    # Measure exact byte size of snapshot structures
    p_size = sys.getsizeof(snap.processes) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in snap.processes.items())
    l_size = sys.getsizeof(snap._logical_apps) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in snap._logical_apps.items())
    apps_size = sys.getsizeof(apps) + sum(sys.getsizeof(a) for a in apps)

    print(f"Running Processes tracked: {proc_count}")
    print(f"Logical Applications tracked: {app_count}")
    print(f"snap.processes size: {p_size:,} bytes ({p_size/1024:.2f} KB)")
    print(f"snap._logical_apps size: {l_size:,} bytes ({l_size/1024:.2f} KB)")
    print(f"get_running_applications() size: {apps_size:,} bytes ({apps_size/1024:.2f} KB)")
    print(f"Total snapshot in-memory representation: {(p_size + l_size + apps_size)/1024:.2f} KB")

if __name__ == "__main__":
    inspect_snapshot_memory()
