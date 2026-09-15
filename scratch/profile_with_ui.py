"""
Profile running agent WITH local Flask UI polling.
Simulates browser dashboard:
- Polling /api/local/metrics every 3s
- Polling /api/local/status every 2s
- Polling /api/local/firewall-status every 3s
"""

import sys
import time
import threading
import urllib.request
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.config import config
from client.app.communication import MasterConnection
from client.app.agent import Agent
from client.app.auth import ClientAuth
from client.app.ui.dashboard import start_client_ui_server

class MockMasterConn:
    def __init__(self):
        self.is_authenticated = True
        self.master_url = "http://127.0.0.1:9100"
        self.client_id = "test-client"
        self.token = "mock-token"

    def send_telemetry(self, payload):
        return True

    def send_heartbeat(self, client_status="running"):
        return True

    def send_host_info(self, host_data):
        return True

    def send_events(self, events):
        return True

    def get_firewall_policy(self):
        return {"version": 1, "enabled": False, "blocked_domains": []}

class MockFirewallAgent:
    def __init__(self):
        self._stop_event = threading.Event()
    def start(self):
        pass
    def stop(self):
        pass
    def run_sync_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(5.0)

def profile_with_ui(duration_sec=20):
    print("=" * 70)
    print(f"PROFILING RUNNING AGENT WITH BROWSER UI POLLING ({duration_sec}s)")
    print("=" * 70)

    cur_proc = psutil.Process()
    cur_proc.cpu_percent(interval=None)

    mock_conn = MockMasterConn()
    mock_fw = MockFirewallAgent()
    auth = ClientAuth(mock_conn)
    auth._authenticated = True
    auth._device_id = "test-device"

    # Start UI server on port 9299 to avoid collision
    port = 9299
    start_client_ui_server(auth, mock_conn, port=port, firewall_agent=mock_fw)
    time.sleep(0.5)

    agent = Agent(mock_conn, firewall_agent=mock_fw)
    agent.start()

    stop_poller = threading.Event()

    def poller(endpoint, interval):
        url = f"http://127.0.0.1:{port}{endpoint}"
        while not stop_poller.is_set():
            try:
                with urllib.request.urlopen(url, timeout=2.0) as resp:
                    resp.read()
            except Exception:
                pass
            stop_poller.wait(interval)

    # Start poller threads simulating open dashboard in browser
    t_metrics = threading.Thread(target=poller, args=("/api/local/metrics", 3.0), daemon=True)
    t_status = threading.Thread(target=poller, args=("/api/local/status", 2.0), daemon=True)
    t_fw = threading.Thread(target=poller, args=("/api/local/firewall-status", 3.0), daemon=True)
    t_metrics.start()
    t_status.start()
    t_fw.start()

    cpu_samples = []
    mem_samples = []

    print("\nMeasuring CPU & Memory with active UI dashboard polling...")
    for i in range(duration_sec):
        time.sleep(1.0)
        cpu = cur_proc.cpu_percent(interval=None)
        mem = cur_proc.memory_info()
        rss_mb = mem.rss / (1024 * 1024)
        cpu_samples.append(cpu)
        mem_samples.append(rss_mb)
        print(f"  Sec {i+1:02d}: CPU = {cpu:5.1f}% | RAM (RSS) = {rss_mb:6.2f} MB")

    stop_poller.set()
    agent.stop()

    print("\n--- SUMMARY WITH UI POLLING ---")
    print(f"Startup spike: {max(cpu_samples[:2]):.1f}%")
    print(f"Steady-state avg CPU: {sum(cpu_samples[2:]) / len(cpu_samples[2:]):.1f}%")
    print(f"Peak CPU: {max(cpu_samples):.1f}%")
    print(f"RAM range: {min(mem_samples):.2f} MB - {max(mem_samples):.2f} MB")

if __name__ == "__main__":
    profile_with_ui(15)
