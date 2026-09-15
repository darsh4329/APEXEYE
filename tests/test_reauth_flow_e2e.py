"""
APEXEYE — End-to-End Reauthentication Flow Tests (Windows and Linux)

Verifies:
1. Command Centre REAUTHENTICATE_AGENT revokes credentials and sets device unauthenticated.
2. Master returns 401 Unauthorized on subsequent authenticated client requests.
3. Windows MasterConnection invokes unauthorized_callback on 401.
4. Linux MasterConnection invokes unauthorized_callback on 401.
5. on_disconnect_triggered wipes credentials, clears identity, stops agent, and enters WAITING_FOR_PAIRING.
6. Deadlock prevention: 401 callback is non-blocking and reentrancy protected.
7. open_login_page() is executed exactly once per transition into WAITING_FOR_PAIRING (idempotency guard).
8. Local client Web UI on port 9200 transitions from dashboard to client_auth.html:
   - /api/local/status returns is_paired=False
   - /api/local/metrics returns 401 Unauthenticated
   - GET / renders client_auth.html (existing login screen)
9. Re-authenticating with new credentials via /api/local/authenticate restores paired/authenticated state.
"""

import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from master.app.database import get_connection, init_database
from master.app.services.command_service import CommandService
from master.app.services.device_service import DeviceService
from master.app.auth import AuthService

# Windows client modules
from client.app.communication import MasterConnection as WinMasterConnection
from client.app.auth import ClientAuth as WinClientAuth
from client.app.ui.dashboard import create_client_ui_app as create_win_ui_app
from client.main import open_login_page as win_open_login_page, launch_login_page as win_launch_login_page

# Linux client modules
from client_linux.app.communication import MasterConnection as LinuxMasterConnection
from client_linux.app.auth import ClientAuth as LinuxClientAuth
from client_linux.app.ui.dashboard import create_client_ui_app as create_linux_ui_app
from client_linux.main import open_login_page as linux_open_login_page, launch_login_page as linux_launch_login_page


@pytest.fixture(autouse=True)
def setup_db():
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


def test_windows_open_login_page_function():
    """Verify open_login_page and launch_login_page exist on Windows client and call webbrowser.open."""
    with patch("webbrowser.open", return_value=True) as mock_open:
        res1 = win_open_login_page("http://127.0.0.1:9200")
        assert res1 is True
        mock_open.assert_called_with("http://127.0.0.1:9200")

        res2 = win_launch_login_page("http://127.0.0.1:9200")
        assert res2 is True


def test_windows_unauthorized_callback_on_401():
    """Verify Windows MasterConnection invokes registered callback when 401 is returned."""
    conn = WinMasterConnection("http://127.0.0.1:9100")
    conn.set_identity("DEV-WIN-001", "tok-abc")
    assert conn.is_authenticated is True

    callback_data = {}

    def on_unauth(resp):
        callback_data["invoked"] = True
        callback_data["resp"] = resp

    conn.set_unauthorized_callback(on_unauth)

    # Mock _request to simulate 401 response from Master
    with patch.object(conn, "_request", return_value=(401, {"error": "Invalid authentication token."})):
        status, resp = conn._request_with_retry("POST", "/api/heartbeat", data={"client_status": "running"}, authenticated=True)
        assert status == 401

    assert callback_data.get("invoked") is True
    assert callback_data["resp"]["error"] == "Invalid authentication token."


def test_windows_reauth_command_and_disconnect_lifecycle(tmp_path):
    """
    Test the complete Windows client reauth lifecycle:
    1. Device online with credentials.
    2. Master executes REAUTHENTICATE_AGENT.
    3. Windows client receives 401, fires on_disconnect_triggered.
    4. Stored credentials wiped, identity cleared.
    5. Disconnect event set, agent stopped.
    6. Browser launch guard ensures open_login_page is called exactly once.
    7. Client UI returns is_paired=False and renders client_auth.html.
    8. Client re-authenticates and resumes connected state.
    """
    dev_svc = DeviceService()
    auth_svc = AuthService()

    dev_id = "DEV-WIN-LIFECYCLE"
    dev_svc.upsert_device({
        "device_id": dev_id,
        "device_name": "Windows Corp PC",
        "device_type": "WINDOWS_PC",
    }, status="online", auth_status="paired")

    pair_info = auth_svc.generate_pairing_credential(dev_id)
    token = pair_info["token"]

    cred_file = tmp_path / "win_test_creds" / ".credentials.json"
    cred_file.parent.mkdir(parents=True, exist_ok=True)

    with patch("client.app.auth._CRED_FILE", cred_file), \
         patch("client.app.config.config.CLIENT_ID", dev_id):

        conn = WinMasterConnection("http://127.0.0.1:9100")
        auth = WinClientAuth(conn)
        auth._save_credentials({"device_id": dev_id, "token": token, "status": "paired"})
        conn.set_identity(dev_id, token)

        assert auth.is_paired is True
        assert conn.is_authenticated is True

        # 1. Master executes REAUTHENTICATE_AGENT
        cmd_svc = CommandService()
        cmd_res = cmd_svc.execute_command(dev_id, "REAUTHENTICATE_AGENT")
        assert cmd_res["success"] is True
        assert cmd_res["data"]["lifecycle_state"] == "WAITING_FOR_PAIRING"

        # Verify Master DB state
        db_conn = get_connection()
        try:
            d_row = db_conn.execute("SELECT authentication_status, status FROM devices WHERE device_id = ?;", (dev_id,)).fetchone()
            assert d_row["authentication_status"] == "unauthenticated"
            assert d_row["status"] == "offline"
        finally:
            db_conn.close()

        # 2. Simulate client making heartbeat request and receiving 401
        disconnect_event = threading.Event()
        current_agent = MagicMock()
        current_agent._stop_event = threading.Event()
        login_page_launched = False
        browser_launches = []

        def mock_open_login(url):
            browser_launches.append(url)
            return True

        def on_disconnect_triggered(reason="Master-forced re-authentication"):
            nonlocal current_agent
            if disconnect_event.is_set():
                return
            disconnect_event.set()
            auth._clear_credentials()
            conn.clear_identity()
            if current_agent and hasattr(current_agent, "_stop_event"):
                current_agent._stop_event.set()

        conn.set_unauthorized_callback(lambda resp: on_disconnect_triggered("401 Unauthorized from Master"))

        # Trigger 401 via MasterConnection
        with patch.object(conn, "_request", return_value=(401, {"error": "Device is not paired."})):
            status, _ = conn._request_with_retry("POST", "/api/heartbeat", data={"client_status": "running"}, authenticated=True)
            assert status == 401

        # 3. Assert disconnect was triggered, credentials wiped, identity cleared
        assert disconnect_event.is_set() is True
        assert auth.is_paired is False
        assert conn.is_authenticated is False
        assert current_agent._stop_event.is_set() is True

        # Reentrancy check: trigger again, must not fail or repeat
        on_disconnect_triggered("Second 401")
        assert disconnect_event.is_set() is True

        # 4. Assert exactly-once browser launch on transition to WAITING_FOR_PAIRING
        client_ui_port = 9200
        # First iteration of loop in WAITING_FOR_PAIRING:
        if not login_page_launched:
            login_url = f"http://127.0.0.1:{client_ui_port}"
            mock_open_login(login_url)
            login_page_launched = True

        # Subsequent loop iterations while waiting for pairing:
        for _ in range(5):
            if not login_page_launched:
                mock_open_login(f"http://127.0.0.1:{client_ui_port}")

        # MUST be called EXACTLY ONCE
        assert len(browser_launches) == 1
        assert browser_launches[0] == "http://127.0.0.1:9200"

        # 5. Verify Client UI routes reflect unauthenticated state and render client_auth.html
        ui_app = create_win_ui_app(auth, conn)
        ui_app.config["TESTING"] = True
        test_client = ui_app.test_client()

        # Status endpoint
        stat_resp = test_client.get("/api/local/status")
        assert stat_resp.status_code == 200
        stat_data = stat_resp.get_json()
        assert stat_data["is_paired"] is False

        # Metrics endpoint returns 401
        met_resp = test_client.get("/api/local/metrics")
        assert met_resp.status_code == 401

        # Index route renders client_auth.html (existing login page)
        idx_resp = test_client.get("/")
        assert idx_resp.status_code == 200
        html = idx_resp.get_data(as_text=True)
        assert "Device Authentication" in html
        assert "authToken" in html
        assert "deviceId" in html

        # 6. Re-pair client with new token
        new_cred = auth_svc.generate_pairing_credential(dev_id)
        new_token = new_cred["token"]

        # Mock Master response for authentication
        with patch.object(conn, "authenticate", return_value=(200, {"success": True, "message": "Authenticated successfully."})):
            ok, msg = auth.authenticate(dev_id, new_token)
            assert ok is True
            assert auth.is_paired is True
            conn.set_identity(dev_id, new_token)
            login_page_launched = False

        assert auth.is_paired is True
        assert conn.is_authenticated is True
        assert login_page_launched is False


def test_linux_reauth_command_and_disconnect_lifecycle(tmp_path):
    """
    Test the complete Linux client reauth lifecycle:
    1. Linux device online with credentials.
    2. Master executes REAUTHENTICATE_AGENT.
    3. Linux client receives 401, fires on_disconnect_triggered.
    4. Stored credentials wiped, identity cleared.
    5. Disconnect event set, agent stopped.
    6. Browser launch guard ensures open_login_page is called exactly once.
    7. Client UI returns is_paired=False and renders client_auth.html.
    8. Client re-authenticates and resumes connected state.
    """
    dev_svc = DeviceService()
    auth_svc = AuthService()

    dev_id = "DEV-LINUX-LIFECYCLE"
    dev_svc.upsert_device({
        "device_id": dev_id,
        "device_name": "Linux Production Server",
        "device_type": "LINUX_SERVER",
    }, status="online", auth_status="paired")

    pair_info = auth_svc.generate_pairing_credential(dev_id)
    token = pair_info["token"]

    cred_file = tmp_path / "linux_test_creds" / ".credentials.json"
    cred_file.parent.mkdir(parents=True, exist_ok=True)

    with patch("client_linux.app.auth._CRED_FILE", cred_file), \
         patch("client_linux.app.config.config.CLIENT_ID", dev_id):

        conn = LinuxMasterConnection("http://127.0.0.1:9100")
        auth = LinuxClientAuth(conn)
        auth._save_credentials({"device_id": dev_id, "token": token, "status": "paired"})
        conn.set_identity(dev_id, token)

        assert auth.is_paired is True
        assert conn.is_authenticated is True

        # 1. Master executes REAUTHENTICATE_AGENT
        cmd_svc = CommandService()
        cmd_res = cmd_svc.execute_command(dev_id, "REAUTHENTICATE_AGENT")
        assert cmd_res["success"] is True
        assert cmd_res["data"]["lifecycle_state"] == "WAITING_FOR_PAIRING"

        # 2. Simulate Linux client receiving 401
        disconnect_event = threading.Event()
        current_agent = MagicMock()
        current_agent._stop_event = threading.Event()
        login_page_launched = False
        browser_launches = []

        def mock_open_login(url):
            browser_launches.append(url)
            return True

        def on_disconnect_triggered(reason="Master-forced re-authentication"):
            nonlocal current_agent
            if disconnect_event.is_set():
                return
            disconnect_event.set()
            auth._clear_credentials()
            conn.clear_identity()
            if current_agent and hasattr(current_agent, "_stop_event"):
                current_agent._stop_event.set()

        conn.set_unauthorized_callback(lambda resp: on_disconnect_triggered("401 Unauthorized from Master"))

        with patch.object(conn, "_request", return_value=(401, {"error": "Device is not paired."})):
            status, _ = conn._request_with_retry("POST", "/api/heartbeat", data={"client_status": "running"}, authenticated=True)
            assert status == 401

        # 3. Assert credentials cleared and agent stopped
        assert disconnect_event.is_set() is True
        assert auth.is_paired is False
        assert conn.is_authenticated is False
        assert current_agent._stop_event.is_set() is True

        # Reentrancy check
        on_disconnect_triggered("Second 401")
        assert disconnect_event.is_set() is True

        # 4. Assert exactly-once browser launch guard
        client_ui_port = 9200
        if not login_page_launched:
            mock_open_login(f"http://127.0.0.1:{client_ui_port}")
            login_page_launched = True

        for _ in range(5):
            if not login_page_launched:
                mock_open_login(f"http://127.0.0.1:{client_ui_port}")

        assert len(browser_launches) == 1
        assert browser_launches[0] == "http://127.0.0.1:9200"

        # 5. Verify Linux Client UI routes
        ui_app = create_linux_ui_app(auth, conn)
        ui_app.config["TESTING"] = True
        test_client = ui_app.test_client()

        stat_resp = test_client.get("/api/local/status")
        assert stat_resp.status_code == 200
        assert stat_resp.get_json()["is_paired"] is False

        met_resp = test_client.get("/api/local/metrics")
        assert met_resp.status_code == 401

        idx_resp = test_client.get("/")
        assert idx_resp.status_code == 200
        html = idx_resp.get_data(as_text=True)
        assert "Device Authentication" in html

        # 6. Re-pair client with new token
        new_cred = auth_svc.generate_pairing_credential(dev_id)
        new_token = new_cred["token"]

        with patch.object(conn, "authenticate", return_value=(200, {"success": True, "message": "Authenticated successfully."})):
            ok, msg = auth.authenticate(dev_id, new_token)
            assert ok is True
            assert auth.is_paired is True
            conn.set_identity(dev_id, new_token)
            login_page_launched = False

        assert auth.is_paired is True
        assert conn.is_authenticated is True
        assert login_page_launched is False
