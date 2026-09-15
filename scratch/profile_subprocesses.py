"""
Detailed isolated profiler for APEXEYE Windows and Linux clients.
Runs in fresh subprocesses to eliminate any cross-contamination.
Measures:
- Startup RSS
- Stabilized RSS
- Telemetry churn (10, 50 cycles)
- Event scan churn (10, 50 cycles)
- Reauthentication churn (10 cycles)
- Flask UI idle vs open dashboard polling
- Heap object counts and sizes by type
- Cache memory consumption
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

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def get_mem():
    p = psutil.Process()
    mi = p.memory_info()
    return mi.rss / (1024 * 1024), mi.vms / (1024 * 1024)

class CleanMockConn:
    def __init__(self, master_url="http://127.0.0.1:9100"):
        self.master_url = master_url
        self.is_authenticated = True
        self._device_id = "test-device"
        self._auth_token = "test-token"
        self._unauthorized_callback = None
    def send_telemetry(self, p): return True
    def send_heartbeat(self, client_status="running"): return True
    def send_host_info(self, h): return True
    def send_events(self, e): return True
    def get_firewall_policy(self): return {"version": 1, "enabled": False, "blocked_domains": []}
    def report_firewall_status(self, *args, **kwargs): return True
    def check_master_connectivity(self): return {"tcp_ok": True, "http_ok": True}
    def set_identity(self, d, t): self._device_id = d; self._auth_token = t
    def clear_identity(self): self._device_id = None; self._auth_token = None
    def set_unauthorized_callback(self, cb): self._unauthorized_callback = cb

def profile_windows_deep():
    gc.collect()
    rss_init, _ = get_mem()

    tracemalloc.start()
    t0 = time.time()

    # Import
    from client.app.config import config
    from client.app.communication import MasterConnection
    from client.app.auth import ClientAuth
    from client.app.collectors.events import (
        ProcessSnapshot, EventCollector,
        _CLASSIFICATION_CACHE, _PE_METADATA_CACHE, _SERVICES_EXE_PIDS_CACHE,
        APPLICATION_TAXONOMY, IGNORED_SYSTEM_PROCESSES
    )
    from client.app.collectors.cpu import CPUCollector
    from client.app.collectors.memory import MemoryCollector
    from client.app.collectors.disk import DiskCollector
    from client.app.collectors.network import NetworkCollector
    from client.app.collectors.os_info import OSInfoCollector
    from client.app.agent import Agent
    from client.app.ui.dashboard import create_client_ui_app

    gc.collect()
    rss_after_import, _ = get_mem()

    # Initial objects
    mock_conn = CleanMockConn()
    auth = ClientAuth(mock_conn)
    auth._authenticated = True
    auth._device_id = "DEV-TEST-01"

    agent = Agent(mock_conn)
    gc.collect()
    rss_after_agent_init, _ = get_mem()

    # Start Agent
    agent.start()
    time.sleep(1.0)
    rss_agent_running, _ = get_mem()

    # Process scan iterations (1 to 30)
    rss_scans = []
    for i in range(30):
        agent._events.collect()
        if i in (0, 4, 9, 19, 29):
            gc.collect()
            r, _ = get_mem()
            rss_scans.append((i+1, r))

    # Telemetry churn (1 to 30)
    rss_telem = []
    for i in range(30):
        agent._cpu.collect()
        agent._memory.collect()
        agent._disk.collect()
        agent._network.collect()
        if i in (0, 4, 9, 19, 29):
            gc.collect()
            r, _ = get_mem()
            rss_telem.append((i+1, r))

    # UI Dashboard
    ui_app = create_client_ui_app(auth, mock_conn)
    client = ui_app.test_client()
    client.get("/")
    rss_ui_open, _ = get_mem()

    # Simulate 50 UI polling requests
    for _ in range(50):
        client.get("/api/local/metrics")
        client.get("/api/local/status")
        client.get("/api/local/firewall-status")
    gc.collect()
    rss_ui_polled, _ = get_mem()

    # Reauthentication lifecycle test: 10 cycles
    rss_reauth = []
    for cycle in range(10):
        # 1. Trigger disconnect
        mock_conn.clear_identity()
        auth._clear_credentials()
        # 2. Stop agent
        agent.stop(timeout=1.0)
        # 3. Simulate WAITING_FOR_PAIRING state
        # 4. Re-pair / on_authenticated
        auth._authenticated = True
        auth._device_id = "DEV-TEST-01"
        auth._token = "test-token"
        mock_conn.set_identity(auth._device_id, auth._token)
        # 5. Restart agent
        agent = Agent(mock_conn)
        agent.start()
        time.sleep(0.1)
        gc.collect()
        r, _ = get_mem()
        rss_reauth.append((cycle + 1, r))

    agent.stop(timeout=1.0)
    gc.collect()
    rss_final, _ = get_mem()

    # Analyze Python heap objects via gc
    type_counts = {}
    type_sizes = {}
    for obj in gc.get_objects():
        tname = type(obj).__name__
        type_counts[tname] = type_counts.get(tname, 0) + 1
        try:
            sz = sys.getsizeof(obj)
            type_sizes[tname] = type_sizes.get(tname, 0) + sz
        except Exception:
            pass

    sorted_types = sorted(type_sizes.items(), key=lambda x: x[1], reverse=True)[:15]

    # Measure cache sizes in bytes
    cache_info = {
        "_CLASSIFICATION_CACHE": (len(_CLASSIFICATION_CACHE), sys.getsizeof(_CLASSIFICATION_CACHE) + sum(sys.getsizeof(k)+sys.getsizeof(v) for k, v in _CLASSIFICATION_CACHE.items())),
        "_PE_METADATA_CACHE": (len(_PE_METADATA_CACHE), sys.getsizeof(_PE_METADATA_CACHE) + sum(sys.getsizeof(k)+sys.getsizeof(v) for k, v in _PE_METADATA_CACHE.items())),
        "_SERVICES_EXE_PIDS_CACHE": (len(_SERVICES_EXE_PIDS_CACHE), sys.getsizeof(_SERVICES_EXE_PIDS_CACHE)),
        "APPLICATION_TAXONOMY": (len(APPLICATION_TAXONOMY), sys.getsizeof(APPLICATION_TAXONOMY) + sum(sys.getsizeof(k)+sys.getsizeof(v) for k, v in APPLICATION_TAXONOMY.items())),
        "IGNORED_SYSTEM_PROCESSES": (len(IGNORED_SYSTEM_PROCESSES), sys.getsizeof(IGNORED_SYSTEM_PROCESSES)),
    }

    results = {
        "platform": "Windows",
        "rss_init": rss_init,
        "rss_after_import": rss_after_import,
        "rss_after_agent_init": rss_after_agent_init,
        "rss_agent_running": rss_agent_running,
        "rss_scans": rss_scans,
        "rss_telem": rss_telem,
        "rss_ui_open": rss_ui_open,
        "rss_ui_polled": rss_ui_polled,
        "rss_reauth": rss_reauth,
        "rss_final": rss_final,
        "cache_info": cache_info,
        "top_types": sorted_types,
    }

    print(json.dumps(results, indent=2))

def profile_linux_deep():
    gc.collect()
    rss_init, _ = get_mem()

    tracemalloc.start()

    from client_linux.app.config import config
    from client_linux.app.communication import MasterConnection
    from client_linux.app.auth import ClientAuth
    from client_linux.app.collectors.events import (
        ProcessSnapshot, EventCollector,
        _LINUX_CLASSIFICATION_CACHE, _DESKTOP_ENTRY_CACHE,
        LINUX_PROCESS_TAXONOMY, IGNORED_SYSTEM_PROCESSES
    )
    from client_linux.app.collectors.cpu import CPUCollector
    from client_linux.app.collectors.memory import MemoryCollector
    from client_linux.app.collectors.disk import DiskCollector
    from client_linux.app.collectors.network import NetworkCollector
    from client_linux.app.collectors.os_info import OSInfoCollector
    from client_linux.app.agent import Agent
    from client_linux.app.ui.dashboard import create_client_ui_app

    gc.collect()
    rss_after_import, _ = get_mem()

    mock_conn = CleanMockConn()
    auth = ClientAuth(mock_conn)
    auth._authenticated = True
    auth._device_id = "LNX-TEST-01"

    agent = Agent(mock_conn)
    gc.collect()
    rss_after_agent_init, _ = get_mem()

    agent.start()
    time.sleep(1.0)
    rss_agent_running, _ = get_mem()

    # Process scan churn
    rss_scans = []
    for i in range(30):
        agent._events.collect()
        if i in (0, 4, 9, 19, 29):
            gc.collect()
            r, _ = get_mem()
            rss_scans.append((i+1, r))

    # Telemetry churn
    rss_telem = []
    for i in range(30):
        agent._cpu.collect()
        agent._memory.collect()
        agent._disk.collect()
        agent._network.collect()
        if i in (0, 4, 9, 19, 29):
            gc.collect()
            r, _ = get_mem()
            rss_telem.append((i+1, r))

    # UI Dashboard
    ui_app = create_client_ui_app(auth, mock_conn)
    client = ui_app.test_client()
    client.get("/")
    rss_ui_open, _ = get_mem()

    for _ in range(50):
        client.get("/api/local/metrics")
        client.get("/api/local/status")
        client.get("/api/local/firewall-status")
    gc.collect()
    rss_ui_polled, _ = get_mem()

    # Reauthentication lifecycle test: 10 cycles
    rss_reauth = []
    for cycle in range(10):
        mock_conn.clear_identity()
        auth._clear_credentials()
        agent.stop(timeout=1.0)
        auth._authenticated = True
        auth._device_id = "LNX-TEST-01"
        auth._token = "test-token"
        mock_conn.set_identity(auth._device_id, auth._token)
        agent = Agent(mock_conn)
        agent.start()
        time.sleep(0.1)
        gc.collect()
        r, _ = get_mem()
        rss_reauth.append((cycle + 1, r))

    agent.stop(timeout=1.0)
    gc.collect()
    rss_final, _ = get_mem()

    type_counts = {}
    type_sizes = {}
    for obj in gc.get_objects():
        tname = type(obj).__name__
        type_counts[tname] = type_counts.get(tname, 0) + 1
        try:
            sz = sys.getsizeof(obj)
            type_sizes[tname] = type_sizes.get(tname, 0) + sz
        except Exception:
            pass

    sorted_types = sorted(type_sizes.items(), key=lambda x: x[1], reverse=True)[:15]

    cache_info = {
        "_LINUX_CLASSIFICATION_CACHE": (len(_LINUX_CLASSIFICATION_CACHE), sys.getsizeof(_LINUX_CLASSIFICATION_CACHE) + sum(sys.getsizeof(k)+sys.getsizeof(v) for k, v in _LINUX_CLASSIFICATION_CACHE.items())),
        "_DESKTOP_ENTRY_CACHE": (len(_DESKTOP_ENTRY_CACHE), sys.getsizeof(_DESKTOP_ENTRY_CACHE) + sum(sys.getsizeof(k)+sys.getsizeof(v) for k, v in _DESKTOP_ENTRY_CACHE.items())),
        "LINUX_PROCESS_TAXONOMY": (len(LINUX_PROCESS_TAXONOMY), sys.getsizeof(LINUX_PROCESS_TAXONOMY) + sum(sys.getsizeof(k)+sys.getsizeof(v) for k, v in LINUX_PROCESS_TAXONOMY.items())),
        "IGNORED_SYSTEM_PROCESSES": (len(IGNORED_SYSTEM_PROCESSES), sys.getsizeof(IGNORED_SYSTEM_PROCESSES)),
    }

    results = {
        "platform": "Linux",
        "rss_init": rss_init,
        "rss_after_import": rss_after_import,
        "rss_after_agent_init": rss_after_agent_init,
        "rss_agent_running": rss_agent_running,
        "rss_scans": rss_scans,
        "rss_telem": rss_telem,
        "rss_ui_open": rss_ui_open,
        "rss_ui_polled": rss_ui_polled,
        "rss_reauth": rss_reauth,
        "rss_final": rss_final,
        "cache_info": cache_info,
        "top_types": sorted_types,
    }

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "windows"
    if mode == "windows":
        profile_windows_deep()
    elif mode == "linux":
        profile_linux_deep()
