"""
APEXEYE Deep RAM Profiler for Windows and Linux Clients
Collects precise RSS, VMS, Python heap, tracemalloc, gc object counts,
cache sizes, and lifecycle memory behavior.
"""

import sys
import os
import gc
import time
import json
import tracemalloc
import threading
import psutil
from pathlib import Path

# Add project root
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def get_mem():
    """Return RSS and VMS in MB."""
    p = psutil.Process()
    mi = p.memory_info()
    return mi.rss / (1024 * 1024), mi.vms / (1024 * 1024)

class MockConn:
    def __init__(self, master_url="http://127.0.0.1:9100"):
        self.master_url = master_url
        self.is_authenticated = True
        self._device_id = "test-device"
        self._auth_token = "test-token"
        self._unauthorized_callback = None
    def send_telemetry(self, p): return True
    def send_heartbeat(self, s="running"): return True
    def send_host_info(self, h): return True
    def send_events(self, e): return True
    def get_firewall_policy(self): return {"version": 1, "enabled": False, "blocked_domains": []}
    def check_master_connectivity(self): return {"tcp_ok": True, "http_ok": True}
    def set_identity(self, d, t): self._device_id = d; self._auth_token = t
    def clear_identity(self): self._device_id = None; self._auth_token = None
    def set_unauthorized_callback(self, cb): self._unauthorized_callback = cb

def profile_windows_client_lifecycle():
    print("\n" + "=" * 70)
    print("PROFILING WINDOWS CLIENT (client/)")
    print("=" * 70)
    gc.collect()
    rss0, vms0 = get_mem()
    print(f"[Baseline before imports] RSS: {rss0:.2f} MB, VMS: {vms0:.2f} MB")

    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()

    from client.app.config import config as win_config
    from client.app.communication import MasterConnection as WinConn
    from client.app.auth import ClientAuth as WinAuth
    from client.app.collectors.events import (
        ProcessSnapshot as WinSnapshot,
        EventCollector as WinEventCollector,
        _CLASSIFICATION_CACHE,
        _PE_METADATA_CACHE,
        _SERVICES_EXE_PIDS_CACHE,
    )
    from client.app.collectors.cpu import CPUCollector as WinCPU
    from client.app.collectors.memory import MemoryCollector as WinMem
    from client.app.collectors.disk import DiskCollector as WinDisk
    from client.app.collectors.network import NetworkCollector as WinNet
    from client.app.collectors.os_info import OSInfoCollector as WinOS
    from client.app.agent import Agent as WinAgent
    from client.app.ui.dashboard import create_client_ui_app as win_create_ui

    gc.collect()
    rss_imported, _ = get_mem()
    print(f"[After module imports] RSS: {rss_imported:.2f} MB (Delta: +{rss_imported - rss0:.2f} MB)")

    # 1. Collector initializations
    cpu = WinCPU()
    mem = WinMem()
    disk = WinDisk()
    net = WinNet()
    osi = WinOS()
    ev = WinEventCollector()

    gc.collect()
    rss_colls, _ = get_mem()
    print(f"[After collectors init] RSS: {rss_colls:.2f} MB (Delta: +{rss_colls - rss_imported:.2f} MB)")

    # 2. Process snapshot inspection
    snap = WinSnapshot()
    snap.capture()
    snap_apps = snap.get_running_applications()
    print(f"[Snapshot capture] Detected {len(snap.processes)} processes, {len(snap_apps)} user apps")
    print(f"  Classification cache entries: {len(_CLASSIFICATION_CACHE)}")
    print(f"  PE metadata cache entries: {len(_PE_METADATA_CACHE)}")
    print(f"  Services.exe PIDs cached: {len(_SERVICES_EXE_PIDS_CACHE)}")

    # 3. Process scan churn: run 20 event collections
    for _ in range(20):
        ev.collect()
    gc.collect()
    rss_scans, _ = get_mem()
    print(f"[After 20 event scan cycles] RSS: {rss_scans:.2f} MB (Delta: {rss_scans - rss_colls:+.2f} MB)")

    # 4. Telemetry cycles churn
    for _ in range(20):
        c = cpu.collect()
        m = mem.collect()
        d = disk.collect()
        n = net.collect()
    gc.collect()
    rss_telem, _ = get_mem()
    print(f"[After 20 telemetry cycles] RSS: {rss_telem:.2f} MB (Delta: {rss_telem - rss_scans:+.2f} MB)")

    # 5. Agent running in threads
    mock_conn = MockConn()
    mock_auth = WinAuth(mock_conn)
    agent = WinAgent(mock_conn)
    agent.start()
    time.sleep(2.0)
    rss_agent_running, _ = get_mem()
    print(f"[Agent running with 5 threads] RSS: {rss_agent_running:.2f} MB (Delta: {rss_agent_running - rss_telem:+.2f} MB)")
    print(f"  Active threads: {threading.active_count()}")

    # 6. UI Flask app creation and request simulation
    ui_app = win_create_ui(mock_auth, mock_conn)
    client = ui_app.test_client()
    # Unauthenticated /
    client.get("/")
    # Auth
    mock_auth._authenticated = True
    # Authenticated /
    client.get("/")
    # Metrics, status, firewall
    for _ in range(20):
        client.get("/api/local/metrics")
        client.get("/api/local/status")
        client.get("/api/local/firewall-status")
    gc.collect()
    rss_ui, _ = get_mem()
    print(f"[After UI init + 60 Flask requests] RSS: {rss_ui:.2f} MB (Delta: {rss_ui - rss_agent_running:+.2f} MB)")

    # 7. Stop agent
    agent.stop(timeout=2.0)
    gc.collect()
    rss_stopped, _ = get_mem()
    print(f"[After Agent stop] RSS: {rss_stopped:.2f} MB")

    snap_after = tracemalloc.take_snapshot()
    top_stats = snap_after.compare_to(snap_before, 'lineno')
    print("\n--- Top 10 tracemalloc allocations in Windows Client ---")
    for stat in top_stats[:10]:
        print(f"  {stat}")

    tracemalloc.stop()
    return rss_ui

def profile_linux_client_lifecycle():
    print("\n" + "=" * 70)
    print("PROFILING LINUX CLIENT (client_linux/)")
    print("=" * 70)
    gc.collect()
    rss0, vms0 = get_mem()
    print(f"[Baseline before imports] RSS: {rss0:.2f} MB, VMS: {vms0:.2f} MB")

    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()

    from client_linux.app.config import config as lnx_config
    from client_linux.app.communication import MasterConnection as LnxConn
    from client_linux.app.auth import ClientAuth as LnxAuth
    from client_linux.app.collectors.events import (
        ProcessSnapshot as LnxSnapshot,
        EventCollector as LnxEventCollector,
        _LINUX_CLASSIFICATION_CACHE,
        _DESKTOP_ENTRY_CACHE,
    )
    from client_linux.app.collectors.cpu import CPUCollector as LnxCPU
    from client_linux.app.collectors.memory import MemoryCollector as LnxMem
    from client_linux.app.collectors.disk import DiskCollector as LnxDisk
    from client_linux.app.collectors.network import NetworkCollector as LnxNet
    from client_linux.app.collectors.os_info import OSInfoCollector as LnxOS
    from client_linux.app.agent import Agent as LnxAgent
    from client_linux.app.ui.dashboard import create_client_ui_app as lnx_create_ui

    gc.collect()
    rss_imported, _ = get_mem()
    print(f"[After module imports] RSS: {rss_imported:.2f} MB (Delta: +{rss_imported - rss0:.2f} MB)")

    # Collectors init
    cpu = LnxCPU()
    mem = LnxMem()
    disk = LnxDisk()
    net = LnxNet()
    osi = LnxOS()
    ev = LnxEventCollector()

    gc.collect()
    rss_colls, _ = get_mem()
    print(f"[After collectors init] RSS: {rss_colls:.2f} MB (Delta: +{rss_colls - rss_imported:.2f} MB)")

    # Snapshot
    snap = LnxSnapshot()
    snap.capture()
    snap_apps = snap.get_running_applications()
    print(f"[Snapshot capture] Detected {len(snap.processes)} processes, {len(snap_apps)} user apps")
    print(f"  Linux classification cache entries: {len(_LINUX_CLASSIFICATION_CACHE)}")
    print(f"  Desktop entry cache entries: {len(_DESKTOP_ENTRY_CACHE)}")

    # 20 event cycles
    for _ in range(20):
        ev.collect()
    gc.collect()
    rss_scans, _ = get_mem()
    print(f"[After 20 event scan cycles] RSS: {rss_scans:.2f} MB (Delta: {rss_scans - rss_colls:+.2f} MB)")

    # 20 telemetry cycles
    for _ in range(20):
        cpu.collect()
        mem.collect()
        disk.collect()
        net.collect()
    gc.collect()
    rss_telem, _ = get_mem()
    print(f"[After 20 telemetry cycles] RSS: {rss_telem:.2f} MB (Delta: {rss_telem - rss_scans:+.2f} MB)")

    # Agent running
    mock_conn = MockConn()
    mock_auth = LnxAuth(mock_conn)
    agent = LnxAgent(mock_conn)
    agent.start()
    time.sleep(2.0)
    rss_agent_running, _ = get_mem()
    print(f"[Agent running with 5 threads] RSS: {rss_agent_running:.2f} MB (Delta: {rss_agent_running - rss_telem:+.2f} MB)")

    # UI Flask app
    ui_app = lnx_create_ui(mock_auth, mock_conn)
    client = ui_app.test_client()
    client.get("/")
    mock_auth._authenticated = True
    client.get("/")
    for _ in range(20):
        client.get("/api/local/metrics")
        client.get("/api/local/status")
        client.get("/api/local/firewall-status")
    gc.collect()
    rss_ui, _ = get_mem()
    print(f"[After UI init + 60 Flask requests] RSS: {rss_ui:.2f} MB (Delta: {rss_ui - rss_agent_running:+.2f} MB)")

    agent.stop(timeout=2.0)
    gc.collect()
    rss_stopped, _ = get_mem()
    print(f"[After Agent stop] RSS: {rss_stopped:.2f} MB")

    snap_after = tracemalloc.take_snapshot()
    top_stats = snap_after.compare_to(snap_before, 'lineno')
    print("\n--- Top 10 tracemalloc allocations in Linux Client ---")
    for stat in top_stats[:10]:
        print(f"  {stat}")

    tracemalloc.stop()
    return rss_ui

if __name__ == "__main__":
    profile_windows_client_lifecycle()
    profile_linux_client_lifecycle()
