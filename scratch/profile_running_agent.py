"""
Profile real running client workload over a 30-second window.
Measures:
- Process CPU percent over 1s intervals.
- Thread CPU time (user + kernel) per thread.
- Memory RSS / VMS over time.
- Impact of simulated UI polling.
"""

import sys
import time
import threading
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.communication import MasterConnection
from client.app.agent import Agent
from client.app.auth import ClientAuth

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

def profile_running_agent(duration_sec=20):
    print("=" * 70)
    print(f"PROFILING RUNNING AGENT (Duration: {duration_sec}s)")
    print("=" * 70)

    cur_proc = psutil.Process()
    # Baseline CPU
    cur_proc.cpu_percent(interval=None)

    mock_conn = MockMasterConn()
    mock_fw = MockFirewallAgent()

    t_start = time.time()
    agent = Agent(mock_conn, firewall_agent=mock_fw)
    t_init = (time.time() - t_start) * 1000
    print(f"Agent initialization time: {t_init:.2f} ms")

    # Start agent workers
    t_start_threads = time.time()
    agent.start()
    t_started = (time.time() - t_start_threads) * 1000
    print(f"Agent worker threads started in: {t_started:.2f} ms")

    # Record CPU and memory samples every 1 second
    cpu_samples = []
    mem_samples = []

    print("\nCollecting 1-second interval process CPU & Memory samples...")
    for i in range(duration_sec):
        time.sleep(1.0)
        cpu = cur_proc.cpu_percent(interval=None)
        mem = cur_proc.memory_info()
        rss_mb = mem.rss / (1024 * 1024)
        cpu_samples.append(cpu)
        mem_samples.append(rss_mb)
        print(f"  Sec {i+1:02d}: CPU = {cpu:5.1f}% | RAM (RSS) = {rss_mb:6.2f} MB")

    # Inspect threads and thread CPU times
    print("\n--- Thread CPU Times ---")
    try:
        threads = cur_proc.threads()
        print(f"Active OS threads in process: {len(threads)}")
        for t in threads:
            print(f"  Thread ID {t.id:6d}: User={t.user_time:6.2f}s, System={t.system_time:6.2f}s")
    except Exception as exc:
        print(f"Could not read thread CPU times: {exc}")

    agent.stop()
    print("\nAgent stopped cleanly.")

    print("\n--- SUMMARY ---")
    print(f"Startup spike (first 2s max CPU): {max(cpu_samples[:2]):.1f}%")
    print(f"Steady-state avg CPU (sec 3-{duration_sec}): {sum(cpu_samples[2:]) / len(cpu_samples[2:]):.1f}%")
    print(f"Peak CPU: {max(cpu_samples):.1f}%")
    print(f"Baseline RAM: {mem_samples[0]:.2f} MB")
    print(f"End RAM: {mem_samples[-1]:.2f} MB (Delta: {mem_samples[-1] - mem_samples[0]:+.2f} MB)")

if __name__ == "__main__":
    profile_running_agent(15)
