"""
Measure real memory of client/main.py and client_linux/main.py startup.
"""
import os
import sys
import time
import threading
import psutil
from pathlib import Path
from unittest.mock import patch

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def run_main_profile(client_type="windows"):
    p = psutil.Process()
    print(f"=== {client_type.upper()} CLIENT REAL RUNTIME PROFILE ===")
    r0 = p.memory_info().rss / (1024 * 1024)
    print(f"Initial process RSS: {r0:.2f} MB")

    if client_type == "windows":
        from client.app.config import config
        from client.app.communication import MasterConnection
        from client.app.auth import ClientAuth
        from client.app.ui.dashboard import start_client_ui_server
        from client.app.agent import Agent
        from client.app.services.command_handler import CommandHandler
        from client.app.services.firewall_agent import FirewallAgent
    else:
        from client_linux.app.config import config
        from client_linux.app.communication import MasterConnection
        from client_linux.app.auth import ClientAuth
        from client_linux.app.ui.dashboard import start_client_ui_server
        from client_linux.app.agent import Agent
        from client_linux.app.services.command_handler import CommandHandler
        from client_linux.app.services.firewall_agent import FirewallAgent

    r_imp = p.memory_info().rss / (1024 * 1024)
    print(f"RSS after all imports: {r_imp:.2f} MB (Delta: +{r_imp - r0:.2f} MB)")

    # Initialize subsystems exactly as in main.py
    conn = MasterConnection(config.master_url)
    conn.check_master_health = lambda: (True, {"status": "healthy"})
    conn.check_master_connectivity = lambda: {"tcp_ok": True, "http_ok": True}
    conn.send_telemetry = lambda p: True
    conn.send_heartbeat = lambda client_status="running": True
    conn.send_host_info = lambda h: True
    conn.send_events = lambda e: True
    conn.get_firewall_policy = lambda: {"version": 1, "enabled": False, "blocked_domains": []}

    auth = ClientAuth(conn)
    stop_event = threading.Event()
    authenticated_event = threading.Event()

    cmd_handler = CommandHandler(conn=conn, auth=auth)
    firewall_agent = FirewallAgent(conn, stop_event)
    firewall_agent.apply_cached_policy()

    r_fw = p.memory_info().rss / (1024 * 1024)
    print(f"RSS after FirewallAgent init & cached policy: {r_fw:.2f} MB")

    # Start UI server
    port = 9399 if client_type == "windows" else 9398
    app, ui_thread = start_client_ui_server(
        auth, conn, port=port, cmd_handler=cmd_handler, firewall_agent=firewall_agent
    )
    time.sleep(0.5)
    r_ui = p.memory_info().rss / (1024 * 1024)
    print(f"RSS after UI server running on port {port}: {r_ui:.2f} MB")

    # Authenticate and start Agent
    auth._authenticated = True
    auth._device_id = "PROFILED-DEVICE"
    conn.set_identity(auth._device_id, "token-123")
    authenticated_event.set()

    agent = Agent(conn, firewall_agent=firewall_agent)
    agent.start()
    time.sleep(1.0)
    r_agent = p.memory_info().rss / (1024 * 1024)
    print(f"RSS with Agent running (all 5 workers): {r_agent:.2f} MB")

    # Run for 10 seconds idle
    print("Running for 10 seconds (telemetry & events flowing)...")
    for sec in range(1, 11):
        time.sleep(1.0)
        cur = p.memory_info().rss / (1024 * 1024)
        print(f"  Sec {sec:02d}: RSS = {cur:5.2f} MB")

    stop_event.set()
    agent.stop(timeout=2.0)
    firewall_agent.stop()
    r_stop = p.memory_info().rss / (1024 * 1024)
    print(f"RSS after agent stop: {r_stop:.2f} MB")

if __name__ == "__main__":
    c_type = sys.argv[1] if len(sys.argv) > 1 else "windows"
    run_main_profile(c_type)
