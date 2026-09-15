"""
APEXEYE — Comprehensive Regression Tests for UI Labels, Modal Lifecycle,
Normal Persistence, and Master-Forced Re-Authentication Security Disconnect.

Covers:
1. Production UI cleanup (no stale Phase or development labels).
2. Command Center modal state machine (Cancel never executes, Confirm closes on success, all 5 commands wired).
3. Normal startup persistence (credentials preserved, no re-pairing prompt).
4. Normal startup network error resilience (credentials never deleted on network failure).
5. Master-forced re-authentication (session revoked, device preserved, client disconnected, WAITING_FOR_PAIRING).
6. Safe connection identity reset and successful re-pairing.
"""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from master.app.database import get_connection, init_database
from master.app.services.command_service import CommandService
from master.app.services.device_service import DeviceService
from master.app.auth import AuthService
from client_linux.app.auth import ClientAuth, _CRED_FILE
from client_linux.app.communication import MasterConnection
from client_linux.app.services.command_handler import CommandHandler as LinuxCommandHandler


REPO_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_HTML_PATH = REPO_ROOT / "master" / "app" / "api" / "templates" / "dashboard.html"


# ═══════════════════════════════════════════════════════════════════════════
# 1. UI CLEANUP TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_ui_no_stale_phase_or_development_labels():
    """Verify that dashboard.html does not display stale Phase or development build labels."""
    content = DASHBOARD_HTML_PATH.read_text(encoding="utf-8")

    # Stale phase labels specifically cited in user requirements
    assert "CCTV & IP Camera Monitoring (Phase 4)" not in content
    assert "Centralized Activity & System Logs (Phase 5)" not in content
    assert "📷 CCTV & IP Camera Monitoring" in content
    assert "📜 Centralized Activity & System Logs" in content

    # Stale development feature wording
    assert "Development feature" not in content
    assert "development feature" not in content

    # Strip code comments (<!-- ... --> and /* ... */) to verify visible content has no "(Phase X)"
    without_html_comments = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)
    without_comments = re.sub(r"/\*.*?\*/", "", without_html_comments, flags=re.DOTALL)

    matches = re.findall(r"\(Phase\s+\d+\)", without_comments, flags=re.IGNORECASE)
    assert len(matches) == 0, f"Found stale visible Phase labels in dashboard: {matches}"


# ═══════════════════════════════════════════════════════════════════════════
# 2. COMMAND CENTER MODAL STATE MACHINE & CANCEL BEHAVIOR TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_command_center_modal_structure_and_overlay_class():
    """Ensure #modal-command-confirm uses modal-overlay class (not unhidden modal-backdrop)."""
    content = DASHBOARD_HTML_PATH.read_text(encoding="utf-8")

    # Root cause check: class must be modal-overlay so active toggle functions properly
    assert '<div id="modal-command-confirm" class="modal-overlay">' in content
    assert '<div id="modal-command-confirm" class="modal-backdrop">' not in content


def test_command_center_modal_cancel_behavior():
    """Ensure clicking Cancel immediately closes modal, sets pending to null, and sends 0 requests."""
    content = DASHBOARD_HTML_PATH.read_text(encoding="utf-8")

    # Cancel button in modal calls closeCommandConfirmModal()
    assert 'onclick="closeCommandConfirmModal()"' in content

    # closeCommandConfirmModal resets pendingCommandToExecute and resets button state without fetch
    assert "function closeCommandConfirmModal()" in content
    assert "pendingCommandToExecute = null;" in content
    assert "closeModal('command-confirm');" in content


def test_command_center_modal_all_five_commands_wired():
    """Ensure all 5 Command Center commands route through prompt confirmation functions."""
    content = DASHBOARD_HTML_PATH.read_text(encoding="utf-8")

    # 1. RUN_HEALTH_CHECK
    assert 'id="btn-cmd-health" onclick="promptHealthCheck()"' in content
    assert "function promptHealthCheck()" in content
    assert "pendingCommandToExecute = { type: 'RUN_HEALTH_CHECK'" in content

    # 2. REAUTHENTICATE_AGENT
    assert 'id="btn-cmd-restart" onclick="promptReauthenticateAgent()"' in content
    assert "function promptReauthenticateAgent()" in content
    assert "pendingCommandToExecute = { type: 'REAUTHENTICATE_AGENT'" in content

    # 3. SYNCHRONIZE_TIME
    assert 'id="btn-cmd-sync-time" onclick="promptSynchronizeTime()"' in content
    assert "function promptSynchronizeTime()" in content
    assert "pendingCommandToExecute = { type: 'SYNCHRONIZE_TIME'" in content

    # 4. CONNECTIVITY_CHECK
    assert 'id="btn-cmd-conn-check" onclick="promptConnectivityCheck()"' in content
    assert "function promptConnectivityCheck()" in content
    assert "pendingCommandToExecute = { type: 'CONNECTIVITY_CHECK'" in content

    # 5. UPDATE_MONITORING_POLICY
    assert 'id="btn-cmd-policy" onclick="promptUpdatePolicy()"' in content
    assert "function promptUpdatePolicy()" in content
    assert "pendingCommandToExecute = { type: 'UPDATE_MONITORING_POLICY'" in content

    # Automatic modal dismissal on successful command completion
    assert "const success = await executeAdminCommand(cmd.type, params);" in content
    assert "if (success) {" in content
    assert "closeCommandConfirmModal();" in content


# ═══════════════════════════════════════════════════════════════════════════
# 3. NORMAL STARTUP PERSISTENCE & NETWORK ERROR RESILIENCE TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_normal_restart_loads_credentials_and_does_not_prompt_re_pairing():
    """
    On normal startup:
    1. Reads .credentials.json
    2. Validates with Master
    3. If valid -> authenticated, resumes monitoring automatically, credentials NOT deleted.
    """
    mock_conn = MagicMock(spec=MasterConnection)
    mock_conn.authenticate.return_value = (200, {"success": True, "device_id": "DEV-TEST-PERSIST"})

    auth = ClientAuth(mock_conn)
    # Save valid credentials
    auth._save_credentials({
        "device_id": "DEV-TEST-PERSIST",
        "token": "secret-token-12345",
        "status": "paired",
    })

    try:
        # Simulate clean restart: new ClientAuth instance initialized from disk
        restart_auth = ClientAuth(mock_conn)
        assert restart_auth.is_paired is True
        assert restart_auth.device_id == "DEV-TEST-PERSIST"
        assert restart_auth.token == "secret-token-12345"

        # Validate with Master
        res = restart_auth.pair()
        assert res is True
        assert restart_auth.is_paired is True

        # Credentials must STILL exist on disk (NEVER deleted on normal restart)
        assert _CRED_FILE.exists()

        # Connection identity was re-armed
        mock_conn.set_identity.assert_called_with("DEV-TEST-PERSIST", "secret-token-12345")

    finally:
        if _CRED_FILE.exists():
            _CRED_FILE.unlink()


def test_normal_restart_network_glitch_never_deletes_credentials():
    """
    If Master is temporarily unreachable (status 0) during startup:
    - pair() returns False
    - Stored credentials on disk MUST NOT BE DELETED!
    """
    mock_conn = MagicMock(spec=MasterConnection)
    # Simulate network failure / Master unreachable
    mock_conn.authenticate.return_value = (0, {"error": "Connection refused"})

    auth = ClientAuth(mock_conn)
    auth._save_credentials({
        "device_id": "DEV-TEST-NETWORK-FAIL",
        "token": "my-secret-token",
        "status": "paired",
    })

    try:
        restart_auth = ClientAuth(mock_conn)
        # Attempting to pair when Master is unreachable
        res = restart_auth.pair()
        assert res is False

        # Crucial check: .credentials.json MUST STILL EXIST! Never deleted on network failure!
        assert _CRED_FILE.exists()
        assert restart_auth._creds is not None
        assert restart_auth._creds.get("device_id") == "DEV-TEST-NETWORK-FAIL"

    finally:
        if _CRED_FILE.exists():
            _CRED_FILE.unlink()


# ═══════════════════════════════════════════════════════════════════════════
# 4. MASTER-FORCED RE-AUTHENTICATION & SECURITY DISCONNECT TESTS
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def clean_db():
    init_database()
    yield


def seed_device_with_auth(device_id: str, token: str = "tok-secret-abc"):
    import hashlib
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO devices (device_id, device_name, device_type, status, authentication_status) "
            "VALUES (?, 'Test PC', 'LINUX_PC', 'online', 'paired');",
            (device_id,),
        )
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT OR REPLACE INTO device_auth (device_id, credential_id, authentication_status) "
            "VALUES (?, ?, 'paired');",
            (device_id, token_hash),
        )
        conn.commit()
    finally:
        conn.close()


def test_master_execute_reauthenticate_agent_security_lifecycle():
    """
    Verify that Master REAUTHENTICATE_AGENT:
    1. Preserves device record and telemetry history.
    2. Marks device authentication_status as 'unauthenticated' and status as 'offline'.
    3. Marks active device_auth credential as 'revoked'.
    4. Returns status: UNAUTHENTICATED, connection_status: DISCONNECTED, lifecycle: WAITING_FOR_PAIRING.
    """
    dev_id = "DEV-SEC-DISCONNECT"
    seed_device_with_auth(dev_id)

    svc = CommandService()
    res = svc.execute_command(dev_id, "REAUTHENTICATE_AGENT")

    assert res["success"] is True
    assert res["status"] == "COMPLETED"
    data = res["data"]
    assert data["authentication_status"] == "UNAUTHENTICATED"
    assert data["connection_status"] == "DISCONNECTED"
    assert data["lifecycle_state"] == "WAITING_FOR_PAIRING"

    # Verify Master DB state
    conn = get_connection()
    try:
        dev = conn.execute("SELECT device_id, authentication_status, status FROM devices WHERE device_id = ?;", (dev_id,)).fetchone()
        assert dev is not None, "Device record must be PRESERVED (never deleted)"
        assert dev["authentication_status"] == "unauthenticated"
        assert dev["status"] == "offline"

        auth_rows = conn.execute("SELECT authentication_status FROM device_auth WHERE device_id = ?;", (dev_id,)).fetchall()
        assert len(auth_rows) > 0
        for r in auth_rows:
            assert r["authentication_status"] == "revoked"
    finally:
        conn.close()


def test_client_command_handler_reauthenticate_agent_security_disconnect():
    """
    Verify that when Linux CommandHandler receives REAUTHENTICATE_AGENT:
    1. Destroys active session
    2. Wipes local stored credentials (_credentials.json)
    3. Clears connection identity (without permanently destroying connection object)
    4. Fires disconnect callback
    5. Returns UNAUTHENTICATED / WAITING_FOR_PAIRING
    """
    mock_conn = MagicMock(spec=MasterConnection)
    mock_auth = MagicMock(spec=ClientAuth)
    mock_auth.device_id = "DEV-LINUX-CMD-REAUTH"

    disconnect_called = False

    def on_disconnect():
        nonlocal disconnect_called
        disconnect_called = True

    handler = LinuxCommandHandler(conn=mock_conn, auth=mock_auth)
    handler.set_disconnect_callback(on_disconnect)

    res = handler.handle_command({
        "command_id": "CMD-REAUTH-001",
        "device_id": "DEV-LINUX-CMD-REAUTH",
        "command_type": "REAUTHENTICATE_AGENT",
    })

    assert res["success"] is True
    assert res["data"]["authentication_status"] == "UNAUTHENTICATED"
    assert res["data"]["connection_status"] == "DISCONNECTED"
    assert res["data"]["lifecycle_state"] == "WAITING_FOR_PAIRING"

    # Local credentials must be cleared
    mock_auth._clear_credentials.assert_called_once()

    # Connection identity must be cleared
    mock_conn.clear_identity.assert_called_once()

    # Disconnect callback must have fired
    assert disconnect_called is True


def test_unauthorized_401_callback_and_re_pairing_cycle():
    """
    Verify that:
    1. 401 Unauthorized triggers the registered callback.
    2. Calling clear_identity() removes auth identity without making connection dead.
    3. Calling set_identity(new_id, new_token) cleanly re-arms the connection object.
    """
    conn = MasterConnection("http://127.0.0.1:9100")
    conn.set_identity("DEV-OLD", "tok-old")
    assert conn.is_authenticated is True

    callback_fired = False

    def on_401(resp):
        nonlocal callback_fired
        callback_fired = True
        conn.clear_identity()

    conn.set_unauthorized_callback(on_401)

    # Simulate 401 response from Master
    with patch.object(conn, "_request", return_value=(401, {"error": "Unauthorized"})):
        status, resp = conn._request_with_retry("POST", "/api/heartbeat", authenticated=True)
        assert status == 401

    assert callback_fired is True
    assert conn.is_authenticated is False
    assert conn._device_id is None
    assert conn._auth_token is None

    # Verify connection object is NOT permanently dead: re-arm with new token
    conn.set_identity("DEV-NEW", "tok-new")
    assert conn.is_authenticated is True
    assert conn._device_id == "DEV-NEW"
    assert conn._auth_token == "tok-new"
