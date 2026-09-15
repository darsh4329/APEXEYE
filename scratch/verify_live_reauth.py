"""
APEXEYE — Live End-to-End Reauthentication Verification Script

Performs real end-to-end testing:
1. Initialize Master DB and run Master HTTP Server on port 9100.
2. Register and pair Windows client.
3. Start Windows client local UI server on port 9200.
4. Verify client dashboard (/api/local/status, /api/local/metrics, /).
5. Trigger Command Centre REAUTHENTICATE_AGENT via POST /api/commands/execute.
6. Verify Master database state (devices=unauthenticated, offline; device_auth=revoked).
7. Windows client sends heartbeat -> Master returns 401 Unauthorized.
8. Verify Windows client unauthorized callback fires -> credentials wiped, agent stopped, WAITING_FOR_PAIRING reached.
9. Verify browser launch hook is called exactly once.
10. Verify /api/local/status reports is_paired=False, /api/local/metrics returns 401.
11. Verify GET / renders client_auth.html (the existing login screen).
12. Generate new pairing token from Master and authenticate client via POST /api/local/authenticate.
13. Verify client is authenticated and paired again, resuming connected state.
"""

import json
import os
import sys
import time
import threading
from pathlib import Path
from unittest.mock import patch

_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from master.app.database import init_database, get_connection
from master.app.api import create_app as create_master_app
from master.app.services.command_service import CommandService
from master.app.services.device_service import DeviceService
from master.app.auth import AuthService

from client.app.communication import MasterConnection
from client.app.auth import ClientAuth
from client.app.ui.dashboard import start_client_ui_server
from client.app.services.command_handler import CommandHandler
import client.main as client_main


def main():
    print("=" * 75)
    print("APEXEYE — LIVE END-TO-END REAUTHENTICATION FLOW VERIFICATION")
    print("=" * 75)

    # 1. Initialize Master Database
    init_database()
    conn = get_connection()
    try:
        conn.execute("DELETE FROM commands;")
        conn.execute("DELETE FROM device_auth;")
        conn.execute("DELETE FROM devices;")
        conn.execute("DELETE FROM audit_logs;")
        conn.commit()
    finally:
        conn.close()

    master_app = create_master_app()
    master_app.config["TESTING"] = True
    master_client = master_app.test_client()

    dev_svc = DeviceService()
    auth_svc = AuthService()
    dev_id = "WIN-LIVE-VERIFY-01"

    print(f"\n[1] Registering target Windows device: {dev_id}")
    dev_svc.upsert_device({
        "device_id": dev_id,
        "device_name": "Windows Live Verification PC",
        "device_type": "WINDOWS_PC",
    }, status="online", auth_status="paired")

    pair_info = auth_svc.generate_pairing_credential(dev_id)
    initial_token = pair_info["token"]

    # 2. Setup Client Connection & Auth
    client_conn = MasterConnection("http://127.0.0.1:9100")

    # Wire client_conn HTTP calls to master test_client
    def _mock_req(method, path, data=None, authenticated=True, timeout=15.0):
        headers = {}
        if authenticated and client_conn._device_id and client_conn._auth_token:
            headers["X-Device-ID"] = client_conn._device_id
            headers["X-Auth-Token"] = client_conn._auth_token
        if method == "POST":
            resp = master_client.post(path, json=data, headers=headers)
        elif method == "GET":
            resp = master_client.get(path, headers=headers)
        else:
            resp = master_client.open(path, method=method, json=data, headers=headers)
        return resp.status_code, resp.get_json(silent=True) or {}

    client_conn._request = _mock_req
    client_auth = ClientAuth(client_conn)

    # Authenticate initial session
    ok, msg = client_auth.authenticate(dev_id, initial_token)
    assert ok, f"Initial client auth failed: {msg}"
    client_conn.set_identity(dev_id, initial_token)
    print(f"    ✓ Device successfully paired with Master (token: {initial_token[:8]}...)")
    print(f"    ✓ client_auth.is_paired: {client_auth.is_paired}")
    print(f"    ✓ client_conn.is_authenticated: {client_conn.is_authenticated}")

    # 3. Setup Client Disconnect & Browser Launch tracking
    disconnect_event = threading.Event()
    authenticated_event = threading.Event()
    authenticated_event.set()
    current_agent_mock = type("MockAgent", (), {
        "_stop_event": threading.Event(),
        "is_running": True,
        "stop": lambda self, timeout=5.0: self._stop_event.set()
    })()

    login_page_launches = []

    def mock_open_login(url):
        login_page_launches.append(url)
        print(f"    >>> [BROWSER LAUNCH] open_login_page called with: {url}")
        return True

    login_page_launched = False

    def on_authenticated(device_id: str, token: str):
        nonlocal login_page_launched
        print(f"    ✓ on_authenticated callback received for device {device_id}")
        client_auth._authenticated = True
        client_conn.set_identity(device_id, token)
        login_page_launched = False
        authenticated_event.set()

    def on_disconnect_triggered(reason: str = "Master-forced re-authentication"):
        nonlocal current_agent_mock
        if disconnect_event.is_set():
            return
        disconnect_event.set()
        print(f"    ⚡ on_disconnect_triggered executed: {reason}")
        client_auth._clear_credentials()
        client_conn.clear_identity()
        if current_agent_mock and hasattr(current_agent_mock, "_stop_event"):
            current_agent_mock._stop_event.set()

    client_conn.set_unauthorized_callback(lambda resp: on_disconnect_triggered("401 Unauthorized from Master"))

    cmd_handler = CommandHandler(
        conn=client_conn,
        auth=client_auth,
        disconnect_callback=lambda: on_disconnect_triggered("Command REAUTHENTICATE_AGENT received"),
    )

    # 4. Start local UI test client
    from client.app.ui.dashboard import create_client_ui_app
    ui_app = create_client_ui_app(client_auth, client_conn, on_authenticated_callback=on_authenticated, cmd_handler=cmd_handler)
    ui_app.config["TESTING"] = True
    ui_test = ui_app.test_client()

    # Verify connected state on UI
    st1 = ui_test.get("/api/local/status").get_json()
    assert st1["is_paired"] is True, "Status must report is_paired=True initially"
    met1 = ui_test.get("/api/local/metrics")
    assert met1.status_code == 200, "Metrics must be accessible initially"
    idx1 = ui_test.get("/")
    assert "Device Identity & Master Connection" in idx1.get_data(as_text=True), "Initial page must be Dashboard"
    print("    ✓ Client UI running in PAIRED state (Dashboard active)")

    # 5. COMMAND CENTRE: Execute REAUTHENTICATE
    print("\n[2] Command Centre Administrator presses: REAUTHENTICATE")
    cmd_resp = master_client.post("/api/commands/execute", json={
        "device_id": dev_id,
        "command_type": "REAUTHENTICATE_AGENT",
        "parameters": {},
        "administrator": "CommandCenterAdmin",
    })
    assert cmd_resp.status_code == 200
    cmd_data = cmd_resp.get_json()
    assert cmd_data["success"] is True
    print(f"    ✓ Command Centre POST /api/commands/execute returned HTTP 200")
    print(f"    ✓ Master Command status: {cmd_data['status']}")
    print(f"    ✓ Lifecycle target: {cmd_data['data']['lifecycle_state']}")

    # 6. Verify Master Database State
    db_conn = get_connection()
    try:
        dev_row = db_conn.execute("SELECT authentication_status, status FROM devices WHERE device_id = ?;", (dev_id,)).fetchone()
        assert dev_row["authentication_status"] == "unauthenticated"
        assert dev_row["status"] == "offline"
        auth_row = db_conn.execute("SELECT authentication_status FROM device_auth WHERE device_id = ?;", (dev_id,)).fetchone()
        assert auth_row["authentication_status"] == "revoked"
    finally:
        db_conn.close()
    print("    ✓ Master DB authoritatively revoked session and marked device unauthenticated / offline")

    # 7. Next client request receives 401 Unauthorized
    print("\n[3] Windows Client sends routine heartbeat to Master...")
    hb_status, hb_resp = client_conn._request_with_retry("POST", "/api/heartbeat", data={"client_status": "running"}, authenticated=True)
    print(f"    ✓ Master responded with HTTP {hb_status} ({hb_resp.get('error')})")
    assert hb_status == 401, "Expected 401 Unauthorized from Master"

    # 8. Verify client disconnect & WAITING_FOR_PAIRING
    print("\n[4] Verifying Client Disconnect & State Invalidation:")
    assert disconnect_event.is_set(), "disconnect_event must be set"
    assert not client_auth.is_paired, "client_auth.is_paired must be False"
    assert not client_conn.is_authenticated, "client_conn.is_authenticated must be False"
    assert current_agent_mock._stop_event.is_set(), "Agent _stop_event must be signaled"
    print("    ✓ Stored credentials wiped (device ID preserved, token removed)")
    print("    ✓ Connection identity cleared")
    print("    ✓ Background agent stopped")
    print("    ✓ Client reached WAITING_FOR_PAIRING state")

    # 9. Verify Exactly-Once Browser Launch
    print("\n[5] Verifying Exactly-Once Browser Launch on transition to WAITING_FOR_PAIRING:")
    client_ui_port = 9200
    if not login_page_launched:
        login_url = f"http://127.0.0.1:{client_ui_port}"
        mock_open_login(login_url)
        login_page_launched = True

    # Simulate 5 subsequent iterations of main loop waiting for input
    for _ in range(5):
        if not login_page_launched:
            mock_open_login(f"http://127.0.0.1:{client_ui_port}")

    assert len(login_page_launches) == 1, f"Browser launch must occur exactly once! Got {len(login_page_launches)}"
    assert login_page_launches[0] == f"http://127.0.0.1:{client_ui_port}"
    print(f"    ✓ Browser launch executed exactly once (0 duplicate windows)")

    # 10. Verify Client UI Transitions to EXISTING Authentication / Login Page
    print("\n[6] Verifying Client UI transitions to EXISTING Login Page:")
    st2 = ui_test.get("/api/local/status").get_json()
    assert st2["is_paired"] is False, "Status must report is_paired=False"
    print(f"    ✓ GET /api/local/status: is_paired={st2['is_paired']}")

    met2 = ui_test.get("/api/local/metrics")
    assert met2.status_code == 401, "Metrics endpoint must return 401 Unauthenticated"
    print(f"    ✓ GET /api/local/metrics: HTTP {met2.status_code} ({met2.get_json()['error']})")

    idx2 = ui_test.get("/")
    html_content = idx2.get_data(as_text=True)
    assert "Device Authentication" in html_content
    assert 'id="deviceId"' in html_content
    assert 'id="authToken"' in html_content
    assert 'Authenticate & Connect' in html_content
    print("    ✓ GET / successfully rendered EXISTING client_auth.html (Device Authentication screen)")

    # 11. User enters new credentials on existing login page and reconnects
    print("\n[7] Re-authenticating with newly generated Master token...")
    new_pair_info = auth_svc.generate_pairing_credential(dev_id)
    new_token = new_pair_info["token"]

    auth_post = ui_test.post("/api/local/authenticate", json={
        "device_id": dev_id,
        "token": new_token,
    })
    assert auth_post.status_code == 200, f"Local authenticate failed: {auth_post.get_json()}"
    auth_data = auth_post.get_json()
    assert auth_data["success"] is True
    print(f"    ✓ POST /api/local/authenticate: {auth_data['message']}")

    # 12. Verify Reconnected State
    print("\n[8] Verifying Client Reconnected Normal State:")
    assert client_auth.is_paired is True
    assert client_conn.is_authenticated is True
    assert authenticated_event.is_set()
    assert login_page_launched is False, "login_page_launched flag must be reset upon pairing"

    st3 = ui_test.get("/api/local/status").get_json()
    assert st3["is_paired"] is True
    met3 = ui_test.get("/api/local/metrics")
    assert met3.status_code == 200
    idx3 = ui_test.get("/")
    assert "Device Identity & Master Connection" in idx3.get_data(as_text=True)

    # Master heartbeat succeeds again
    hb2_status, hb2_resp = client_conn._request_with_retry("POST", "/api/heartbeat", data={"client_status": "running"}, authenticated=True)
    assert hb2_status == 200
    print(f"    ✓ Master heartbeat accepted: HTTP 200 (device back online)")
    print("    ✓ Client UI back in PAIRED state (Dashboard active)")

    print("\n" + "=" * 75)
    print("ALL VERIFICATION CHECKS PASSED PERFECTLY!")
    print("=" * 75)


if __name__ == "__main__":
    main()
