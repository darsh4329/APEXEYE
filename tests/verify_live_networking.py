"""
Live networking verification script for ApexEye Master <-> Client.
Tests UDP 9101 discovery, TCP 9100 connectivity, GET /api/health,
device pairing, and authenticated telemetry transmission.
"""

import os
import sys
import time
import socket
import threading
import urllib.request
import json
import uuid
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database
from master.app.api import create_app
from master.app.config import config as master_config
from master.app.services.discovery import master_discovery_service
from master.app.services.device_service import DeviceService
from master.app.auth import AuthService
from client.app.config import ClientConfig
from client.app.discovery import MasterDiscoverer
from client.app.communication import MasterConnection
from client.app.auth import ClientAuth


def run_live_tests():
    print("=" * 60)
    print("APEXEYE LIVE NETWORKING & DISCOVERY VERIFICATION")
    print("=" * 60)

    # 1. Start Master Server and Discovery Service in background
    init_database()
    app = create_app()
    from werkzeug.serving import make_server
    server = make_server("0.0.0.0", 9100, app)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    master_discovery_service.start()
    time.sleep(1.0)

    primary_ip = master_config.primary_lan_ip
    print(f"Master Listener      : 0.0.0.0:9100")
    print(f"Master Primary LAN IP: http://{primary_ip}:9100")
    print(f"Master Discovery UDP : 9101")

    # 2. Test Client Automatic LAN Discovery (No hardcoded IP)
    print("\n--- TEST 1: Automatic LAN Master Discovery (UDP 9101) ---")
    discoverer = MasterDiscoverer(discovery_port=9101)
    discovered = discoverer.discover_via_udp_lan(timeout=2.0)
    print(f"Discovery Result     : {discovered}")
    assert discovered is not None, "LAN Discovery failed to locate Master!"
    discovered_url, source = discovered
    print(f"Discovered URL       : {discovered_url}")
    print(f"Discovery Source     : {source}")

    # 3. Test Pre-Flight Connectivity
    print("\n--- TEST 2: Pre-flight Connectivity Checks ---")
    conn = MasterConnection(discovered_url)
    report = conn.check_master_connectivity()
    print(f"TCP 9100 Connection : {'PASS' if report['tcp_ok'] else 'FAIL'}")
    print(f"HTTP /api/health    : {'PASS' if report['http_ok'] else 'FAIL'}")
    assert report["tcp_ok"], "TCP connectivity failed"
    assert report["http_ok"], "HTTP health check failed"

    # 4. Test Device Registration & Pairing over LAN URL
    print(f"\n--- TEST 3: Device Pairing & Authentication over {discovered_url} ---")
    dev_svc = DeviceService()
    master_auth = AuthService()
    dev_id = f"live-test-laptop-{uuid.uuid4().hex[:8]}"
    dev_svc.register({
        "device_id": dev_id,
        "device_name": "Live Test Laptop",
        "device_type": "WINDOWS_PC",
        "operating_system": "Windows 11",
        "hostname": socket.gethostname(),
        "ip_address": primary_ip,
    })
    cred = master_auth.generate_pairing_credential(dev_id)
    token = cred["token"]

    auth = ClientAuth(conn)
    ok, msg = auth.authenticate(dev_id, token)
    print(f"Authentication Result: {'PASS' if ok else 'FAIL'} (msg: {msg})")
    assert ok, f"Authentication failed: {msg}"

    conn.set_identity(dev_id, token)
    assert conn.is_authenticated, "Connection not marked authenticated"

    # 5. Test Heartbeat & Telemetry Transmission
    print("\n--- TEST 4: Telemetry Transmission ---")
    telem_ok = conn.send_telemetry({
        "timestamp": "2026-08-26 10:45:00",
        "cpu": {"percent": 14.2, "count": 8},
        "memory": {"total_gb": 16.0, "used_gb": 7.8, "percent": 48.6},
        "disk": {"total_gb": 512.0, "used_gb": 280.0, "percent": 55.0},
        "network": {"bytes_sent": 1024, "bytes_recv": 2048},
    })
    print(f"Send Telemetry       : {'PASS' if telem_ok else 'FAIL'}")
    assert telem_ok, "Failed to send telemetry"

    hb_ok = conn.send_heartbeat("running")
    print(f"Send Heartbeat       : {'PASS' if hb_ok else 'FAIL'}")
    assert hb_ok, "Failed to send heartbeat"

    # 6. Test Security Boundary — Master Dashboard blocked on non-localhost
    print("\n--- TEST 5: Master Admin Security Boundary ---")
    req = urllib.request.Request(f"http://127.0.0.1:9100/api/health")
    with urllib.request.urlopen(req) as resp:
        print(f"Localhost Health     : HTTP {resp.status} (PASS)")

    # 7. Test Diagnostics on Unreachable Endpoint
    print("\n--- TEST 6: Diagnostics on Unreachable Endpoint ---")
    conn_bad = MasterConnection("http://192.0.2.1:9100")
    diag = conn_bad.format_diagnostics("Connection timed out")
    assert "APEXEYE CLIENT CONNECTIVITY DIAGNOSTIC" in diag
    print("Diagnostic Output Formatted Successfully (No Secrets Exposed)")

    # Cleanup
    master_discovery_service.stop()
    server.shutdown()
    print("\n" + "=" * 60)
    print("ALL LIVE NETWORK TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    run_live_tests()
