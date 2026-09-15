"""
Comprehensive empirical profiling script for APEXEYE Client.
Measures:
1. Execution time of each collector individually.
2. Breakdown of ProcessSnapshot.capture() and EventCollector.collect().
3. psutil call overhead (cpu_percent, disk_partitions, net_connections, process_iter).
4. Memory usage (RSS, VMS) at startup and steady state.
5. CPU consumption breakdown across threads.
"""

import sys
import time
import cProfile
import pstats
import io
import psutil
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.collectors.cpu import CPUCollector
from client.app.collectors.memory import MemoryCollector
from client.app.collectors.disk import DiskCollector
from client.app.collectors.network import NetworkCollector
from client.app.collectors.os_info import OSInfoCollector
from client.app.collectors.events import EventCollector, ProcessSnapshot, _get_services_exe_pids, _is_user_application_process

def profile_collectors():
    print("=" * 70)
    print("1. INDIVIDUAL COLLECTOR EXECUTION TIMES (10 iterations each)")
    print("=" * 70)

    collectors = {
        "MemoryCollector": MemoryCollector(),
        "DiskCollector": DiskCollector(),
        "NetworkCollector": NetworkCollector(),
        "OSInfoCollector": OSInfoCollector(),
        "CPUCollector (interval=1)": CPUCollector(),
    }

    for name, col in collectors.items():
        durations = []
        for _ in range(5):  # 5 runs to avoid waiting too long on 1s intervals
            t0 = time.perf_counter()
            col.collect()
            durations.append(time.perf_counter() - t0)
        avg_ms = (sum(durations) / len(durations)) * 1000
        min_ms = min(durations) * 1000
        max_ms = max(durations) * 1000
        print(f"{name:<30}: avg={avg_ms:8.2f} ms | min={min_ms:8.2f} ms | max={max_ms:8.2f} ms")

def profile_event_collector():
    print("\n" + "=" * 70)
    print("2. EVENT COLLECTOR & PROCESS SNAPSHOT PROFILING")
    print("=" * 70)

    # Count total processes currently running
    procs = list(psutil.process_iter(["pid", "name"]))
    print(f"Total OS processes running: {len(procs)}")

    # Time _get_services_exe_pids()
    t0 = time.perf_counter()
    pids = _get_services_exe_pids()
    t_get_services = (time.perf_counter() - t0) * 1000
    print(f"_get_services_exe_pids() single call time: {t_get_services:.2f} ms (found PIDs: {pids})")

    # Measure capture() without caching
    snap = ProcessSnapshot()
    t0 = time.perf_counter()
    snap.capture()
    t_capture = (time.perf_counter() - t0) * 1000
    print(f"ProcessSnapshot.capture() run 1 (cold): {t_capture:.2f} ms")
    print(f"  Detected logical applications: {len(snap.app_groups)}")
    for app, (cat, pids_list, exe) in snap.app_groups.items():
        print(f"    - {app} ({cat}): {len(pids_list)} proc(s) [{exe}]")

    t0 = time.perf_counter()
    snap.capture()
    t_capture2 = (time.perf_counter() - t0) * 1000
    print(f"ProcessSnapshot.capture() run 2 (warm): {t_capture2:.2f} ms")

    # Profile EventCollector.collect() using cProfile
    print("\n--- cProfile of ProcessSnapshot.capture() ---")
    pr = cProfile.Profile()
    pr.enable()
    snap.capture()
    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats(25)
    print(s.getvalue())

def profile_psutil_calls():
    print("\n" + "=" * 70)
    print("3. LOW-LEVEL PSUTIL CALL BENCHMARKS")
    print("=" * 70)

    # Measure process_iter vs process_iter with attrs
    t0 = time.perf_counter()
    for _ in range(10):
        list(psutil.process_iter())
    t_iter = ((time.perf_counter() - t0) / 10) * 1000

    t0 = time.perf_counter()
    for _ in range(10):
        list(psutil.process_iter(["pid", "name"]))
    t_iter_attrs = ((time.perf_counter() - t0) / 10) * 1000

    t0 = time.perf_counter()
    for _ in range(5):
        psutil.net_connections(kind="inet")
    t_net_conn = ((time.perf_counter() - t0) / 5) * 1000

    t0 = time.perf_counter()
    for _ in range(10):
        psutil.disk_partitions(all=False)
    t_partitions = ((time.perf_counter() - t0) / 10) * 1000

    t0 = time.perf_counter()
    for _ in range(10):
        psutil.virtual_memory()
    t_vmem = ((time.perf_counter() - t0) / 10) * 1000

    print(f"psutil.process_iter()                     : {t_iter:8.2f} ms")
    print(f"psutil.process_iter(['pid', 'name'])      : {t_iter_attrs:8.2f} ms")
    print(f"psutil.net_connections(kind='inet')       : {t_net_conn:8.2f} ms")
    print(f"psutil.disk_partitions(all=False)         : {t_partitions:8.2f} ms")
    print(f"psutil.virtual_memory()                   : {t_vmem:8.2f} ms")

def profile_memory():
    print("\n" + "=" * 70)
    print("4. PROCESS RAM PROFILE (RSS & VMS)")
    print("=" * 70)

    cur_proc = psutil.Process()
    mem_info = cur_proc.memory_info()
    print(f"Initial RSS: {mem_info.rss / (1024*1024):.2f} MB | VMS: {mem_info.vms / (1024*1024):.2f} MB")

    # Run EventCollector 20 times to measure memory leak / growth
    ec = EventCollector()
    rss_samples = []
    for i in range(20):
        ec.collect()
        rss_samples.append(cur_proc.memory_info().rss / (1024*1024))

    print(f"After 20 EventCollector cycles: RSS: {rss_samples[-1]:.2f} MB (Delta: {rss_samples[-1] - rss_samples[0]:+.2f} MB)")
    print(f"Min RSS: {min(rss_samples):.2f} MB, Max RSS: {max(rss_samples):.2f} MB")

if __name__ == "__main__":
    profile_collectors()
    profile_event_collector()
    profile_psutil_calls()
    profile_memory()
