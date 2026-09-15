import sys
import time
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.collectors.events import ProcessSnapshot

snap = ProcessSnapshot()
# Warm
snap.capture()

times = []
for _ in range(5):
    t0 = time.perf_counter()
    snap.capture()
    times.append((time.perf_counter() - t0) * 1000)

avg_ms = sum(times) / len(times)
print(f"OPT-1 capture() avg time: {avg_ms:.2f} ms (min={min(times):.2f}, max={max(times):.2f})")
print(f"Apps detected: {len(snap.app_groups)}")
