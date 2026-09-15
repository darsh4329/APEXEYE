"""
Benchmark OPT-5: Targeted GC during agent stop / reauth transition.
"""
import sys
import time
import gc
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.communication import MasterConnection
from client.app.agent import Agent
from client.app.auth import ClientAuth

class MockConn:
    def __init__(self):
        self.master_url = "http://127.0.0.1:9100"
        self.is_authenticated = True
        self._device_id = "DEV-01"
        self._auth_token = "TOK-01"
    def send_telemetry(self, p): return True
    def send_heartbeat(self, client_status="running"): return True
    def send_host_info(self, h): return True
    def send_events(self, e): return True
    def get_firewall_policy(self): return {"version": 1, "enabled": False, "blocked_domains": []}
    def report_firewall_status(self, *args, **kwargs): return True
    def clear_identity(self): pass
    def set_identity(self, d, t): pass

def test_targeted_gc():
    p = psutil.Process()
    conn = MockConn()
    agent = Agent(conn)
    agent.start()

    # Simulate 5 event and telemetry cycles
    for _ in range(5):
        agent._events.collect()
        agent._cpu.collect()
        agent._memory.collect()

    r_running = p.memory_info().rss / (1024 * 1024)
    print(f"Agent running RSS: {r_running:.2f} MB", flush=True)

    # Stop agent
    agent.stop(timeout=1.0)
    agent = None

    r_stopped_nogc = p.memory_info().rss / (1024 * 1024)
    print(f"Agent stopped (NO explicit GC): {r_stopped_nogc:.2f} MB", flush=True)

    # Targeted GC benchmark
    t0 = time.perf_counter()
    collected = gc.collect()
    t_gc_ms = (time.perf_counter() - t0) * 1000

    r_stopped_gc = p.memory_info().rss / (1024 * 1024)
    print(f"Agent stopped (WITH targeted GC): {r_stopped_gc:.2f} MB (Delta: {r_stopped_gc - r_stopped_nogc:+.2f} MB, Objects collected: {collected}, GC time: {t_gc_ms:.2f} ms)", flush=True)

if __name__ == "__main__":
    test_targeted_gc()
