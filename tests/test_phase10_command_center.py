"""
APEXEYE — Phase 10: Secure Command Center & Remote Operations Test Suite

Comprehensive tests verifying:
  1. Strict command allowlist enforcement (5 commands only).
  2. Offline device safety rejection.
  3. Real client command handler execution (RUN_HEALTH_CHECK, REAUTHENTICATE_AGENT,
     SYNCHRONIZE_TIME, CONNECTIVITY_CHECK, UPDATE_MONITORING_POLICY).
  4. Non-breaking agent session renewal & auth retention.
  5. Time synchronization calculation and offset handling.
  6. Connectivity diagnostic & RTT latency calculation.
  7. Policy update safety & frozen presence constant protection.
  8. Unique command IDs & replay protection.
  9. Command audit logging in database.
 10. REST API endpoints & security boundary (@require_admin loopback protection).
 11. Linux client handler parity.
 12. Verification that frozen constants remain 100% untouched.
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from master.app.api import create_app
from master.app.database import get_connection, init_database
from master.app.services.command_service import CommandService, ALLOWED_COMMANDS
from client.app.services.command_handler import CommandHandler as WindowsCommandHandler
from client_linux.app.services.command_handler import CommandHandler as LinuxCommandHandler


@pytest.fixture(autouse=True)
def setup_test_database():
    """Ensure tables are initialized and reset for clean test execution."""
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


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def seed_device(device_id="DEV-001", name="Workstation-A", status="online", auth_status="paired"):
    """Helper to insert a device and paired auth token in DB."""
    conn = get_connection()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn.execute(
            """INSERT INTO devices
               (device_id, device_name, device_type, operating_system, ip_address,
                hostname, status, authentication_status, created_at, updated_at, last_seen)
               VALUES (?, ?, 'WINDOWS_PC', 'Windows 11', '192.168.1.50',
                'DESKTOP-01', ?, ?, ?, ?, ?);""",
            (device_id, name, status, auth_status, now_str, now_str, now_str),
        )
        conn.execute(
            """INSERT INTO device_auth
               (device_id, credential_id, authentication_status, created_at)
               VALUES (?, 'hash_credential_123', ?, ?);""",
            (device_id, auth_status, now_str),
        )
        conn.commit()
    finally:
        conn.close()


# ── 1. Allowlist & Validation Tests ──────────────────────────────────

def test_command_allowlist():
    """Verify exact 5 allowlisted commands."""
    assert ALLOWED_COMMANDS == {
        "RUN_HEALTH_CHECK",
        "REAUTHENTICATE_AGENT",
        "SYNCHRONIZE_TIME",
        "CONNECTIVITY_CHECK",
        "UPDATE_MONITORING_POLICY",
    }


def test_reject_unauthorized_command():
    """Ensure arbitrary shell or unknown commands are rejected immediately."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    with pytest.raises(ValueError, match="unauthorized command type"):
        svc.execute_command("DEV-001", "EXECUTE_SHELL", {"command": "dir"})

    with pytest.raises(ValueError, match="unauthorized command type"):
        svc.execute_command("DEV-001", "DOWNLOAD_FILE", {})


def test_nonexistent_device():
    """Ensure commands against nonexistent devices raise ValueError."""
    svc = CommandService()
    with pytest.raises(ValueError, match="does not exist"):
        svc.execute_command("DEV-NONEXISTENT", "CONNECTIVITY_CHECK")


# ── 2. Offline Device Protection Tests ───────────────────────────────

def test_offline_device_rejection():
    """Ensure commands targeted to offline devices are safely rejected with explicit message."""
    seed_device("DEV-OFFLINE", name="Offline-PC", status="offline")
    svc = CommandService()

    res = svc.execute_command("DEV-OFFLINE", "RUN_HEALTH_CHECK")
    assert res["success"] is False
    assert res["status"] == "REJECTED"
    assert "Device is currently offline" in res["error"]

    # Verify recorded in DB as REJECTED
    history = svc.get_command_history(device_id="DEV-OFFLINE")
    assert len(history) == 1
    assert history[0]["status"] == "REJECTED"
    assert history[0]["error"] == "Device is currently offline. Command cannot be delivered."


# ── 3. Individual Command Execution Tests ────────────────────────────

def test_execute_run_health_check():
    """Verify RUN_HEALTH_CHECK queries live telemetry and computes health score."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    res = svc.execute_command("DEV-001", "RUN_HEALTH_CHECK")
    assert res["success"] is True
    assert res["status"] == "COMPLETED"
    assert "health_score" in res["data"]
    assert res["data"]["health_score"] is not None
    assert res["data"]["health_status"] in ("GOOD", "WARNING", "CRITICAL")
    assert res["rtt_ms"] >= 0


def test_execute_reauthenticate_agent():
    """Verify REAUTHENTICATE_AGENT invalidates session/credential, disconnects client, and preserves device identity."""
    seed_device("DEV-001", status="online", auth_status="paired")
    svc = CommandService()

    res = svc.execute_command("DEV-001", "REAUTHENTICATE_AGENT")
    assert res["success"] is True
    assert res["status"] == "COMPLETED"
    assert res["data"]["authentication_status"] == "UNAUTHENTICATED"
    assert res["data"]["connection_status"] == "DISCONNECTED"
    assert res["data"]["lifecycle_state"] == "WAITING_FOR_PAIRING"

    # Verify device record is still intact (NOT deleted) and marked unauthenticated/offline
    conn = get_connection()
    try:
        dev = conn.execute("SELECT authentication_status, status FROM devices WHERE device_id = 'DEV-001';").fetchone()
        assert dev is not None
        assert dev["authentication_status"] == "unauthenticated"
        assert dev["status"] == "offline"

        # Verify device_auth credentials were revoked
        auth_row = conn.execute("SELECT authentication_status FROM device_auth WHERE device_id = 'DEV-001';").fetchone()
        if auth_row:
            assert auth_row["authentication_status"] == "revoked"
    finally:
        conn.close()


def test_execute_synchronize_time():
    """Verify SYNCHRONIZE_TIME calculates clock delta."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    res = svc.execute_command("DEV-001", "SYNCHRONIZE_TIME")
    assert res["success"] is True
    assert res["status"] == "COMPLETED"
    assert "master_time" in res["data"]
    assert res["data"]["synchronized"] is True


def test_execute_connectivity_check():
    """Verify CONNECTIVITY_CHECK measures RTT latency."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    res = svc.execute_command("DEV-001", "CONNECTIVITY_CHECK")
    assert res["success"] is True
    assert res["status"] == "COMPLETED"
    assert res["data"]["reachable"] is True
    assert res["data"]["authentication_valid"] is True
    assert res["rtt_ms"] >= 0


def test_execute_update_monitoring_policy_valid():
    """Verify UPDATE_MONITORING_POLICY accepts approved telemetry and log parameters."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    params = {
        "telemetry_interval": 15,
        "event_scan_interval": 6,
        "log_severity": "WARNING",
    }
    res = svc.execute_command("DEV-001", "UPDATE_MONITORING_POLICY", parameters=params)
    assert res["success"] is True
    assert res["status"] == "COMPLETED"
    applied = res["data"]["applied_policy"]
    assert applied["telemetry_interval"] == 15
    assert applied["event_scan_interval"] == 6
    assert applied["log_severity"] == "WARNING"


def test_execute_update_monitoring_policy_forbidden_heartbeat():
    """Strictly protect frozen heartbeat/presence constants against mutation."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    params = {
        "heartbeat_interval": 10,
        "presence_check_interval": 5,
    }
    res = svc.execute_command("DEV-001", "UPDATE_MONITORING_POLICY", parameters=params)
    assert res["success"] is False
    assert res["status"] == "FAILED"
    assert "frozen and cannot be modified" in res["error"]


# ── 4. Client-Side Command Handler Tests ─────────────────────────────

def test_windows_client_command_handler_execution():
    """Verify Windows client command handler executes allowlisted commands locally."""
    mock_auth = MagicMock()
    mock_auth.device_id = "DEV-WIN-01"
    mock_auth.pair.return_value = True

    handler = WindowsCommandHandler(auth=mock_auth)

    # 1. Health check
    res_health = handler.handle_command({
        "command_id": "CMD-001",
        "device_id": "DEV-WIN-01",
        "command_type": "RUN_HEALTH_CHECK",
    })
    assert res_health["success"] is True
    assert "telemetry" in res_health["data"]

    # 2. Reauthenticate
    res_auth = handler.handle_command({
        "command_id": "CMD-002",
        "device_id": "DEV-WIN-01",
        "command_type": "REAUTHENTICATE_AGENT",
    })
    assert res_auth["success"] is True
    assert res_auth["data"]["authentication_status"] in ("VALID", "UNAUTHENTICATED")

    # 3. Synchronize time
    res_sync = handler.handle_command({
        "command_id": "CMD-003",
        "device_id": "DEV-WIN-01",
        "command_type": "SYNCHRONIZE_TIME",
        "parameters": {"master_time": "2026-08-29T12:00:00Z"},
    })
    assert res_sync["success"] is True
    assert res_sync["data"]["synchronized"] is True

    # 4. Unknown command rejection
    res_unauth = handler.handle_command({
        "command_id": "CMD-004",
        "device_id": "DEV-WIN-01",
        "command_type": "SYSTEM_SHUTDOWN",
    })
    assert res_unauth["success"] is False
    assert "not recognized" in res_unauth["error"]


def test_linux_client_command_handler_parity():
    """Verify Linux client command handler parity."""
    mock_auth = MagicMock()
    mock_auth.device_id = "DEV-LINUX-01"
    mock_auth.pair.return_value = True

    handler = LinuxCommandHandler(auth=mock_auth)

    res = handler.handle_command({
        "command_id": "CMD-LIN-01",
        "device_id": "DEV-LINUX-01",
        "command_type": "CONNECTIVITY_CHECK",
    })
    assert res["success"] is True
    assert res["data"]["reachable"] is True
    assert res["data"]["packet_acknowledged"] is True


# ── 5. Replay Protection & Audit History Tests ───────────────────────

def test_unique_command_ids_and_replay_protection():
    """Verify every execution receives a unique command_id and is recorded in DB."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    r1 = svc.execute_command("DEV-001", "CONNECTIVITY_CHECK")
    r2 = svc.execute_command("DEV-001", "CONNECTIVITY_CHECK")

    assert r1["command_id"] != r2["command_id"]
    assert r1["command_id"].startswith("CMD-")
    assert r2["command_id"].startswith("CMD-")

    history = svc.get_command_history(device_id="DEV-001")
    assert len(history) == 2
    cmd_ids = [h["command_id"] for h in history]
    assert r1["command_id"] in cmd_ids
    assert r2["command_id"] in cmd_ids


def test_command_audit_logging_no_sensitive_tokens():
    """Verify commands and audit_logs tables record execution without plaintext tokens."""
    seed_device("DEV-001", status="online")
    svc = CommandService()

    svc.execute_command("DEV-001", "REAUTHENTICATE_AGENT", administrator="SuperAdmin")

    conn = get_connection()
    try:
        audit_row = conn.execute(
            "SELECT * FROM audit_logs WHERE target = 'DEV-001' ORDER BY id DESC LIMIT 1;"
        ).fetchone()
        assert audit_row is not None
        assert audit_row["actor"] == "SuperAdmin"
        assert "COMMAND_COMPLETED:REAUTHENTICATE_AGENT" in audit_row["action"]

        # Ensure no token string leaked
        cmd_row = conn.execute("SELECT * FROM commands WHERE device_id = 'DEV-001';").fetchone()
        assert "token" not in (cmd_row["parameters"] or "")
        assert "token" not in (cmd_row["result"] or "")
    finally:
        conn.close()


# ── 6. REST API Endpoints & Security Tests ───────────────────────────

def test_api_execute_command_endpoint(client):
    """Test POST /api/commands/execute endpoint."""
    seed_device("DEV-001", status="online")

    payload = {
        "device_id": "DEV-001",
        "command_type": "CONNECTIVITY_CHECK",
    }
    resp = client.post("/api/commands/execute", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["command_type"] == "CONNECTIVITY_CHECK"
    assert data["status"] == "COMPLETED"


def test_api_command_history_filtering(client):
    """Test GET /api/commands/history with filters."""
    seed_device("DEV-001", status="online")
    seed_device("DEV-002", status="offline")

    svc = CommandService()
    svc.execute_command("DEV-001", "CONNECTIVITY_CHECK")
    svc.execute_command("DEV-002", "CONNECTIVITY_CHECK")

    # All history
    resp = client.get("/api/commands/history")
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 2

    # Filter by device
    resp_dev = client.get("/api/commands/history?device_id=DEV-001")
    assert resp_dev.status_code == 200
    assert resp_dev.get_json()["count"] == 1
    assert resp_dev.get_json()["history"][0]["device_id"] == "DEV-001"

    # Filter by status
    resp_st = client.get("/api/commands/history?status=REJECTED")
    assert resp_st.status_code == 200
    assert resp_st.get_json()["count"] == 1
    assert resp_st.get_json()["history"][0]["status"] == "REJECTED"


def test_api_command_types_metadata(client):
    """Test GET /api/commands/types."""
    resp = client.get("/api/commands/types")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["allowed_commands"]) == 5
    assert "RUN_HEALTH_CHECK" in data["allowed_commands"]


def test_remote_ip_blocked_by_security_boundary(client):
    """Ensure non-loopback remote LAN callers are rejected with 403 Forbidden."""
    seed_device("DEV-001", status="online")

    resp = client.post(
        "/api/commands/execute",
        json={"device_id": "DEV-001", "command_type": "CONNECTIVITY_CHECK"},
        environ_base={"REMOTE_ADDR": "192.168.1.100"},
    )
    assert resp.status_code == 403
    assert "Forbidden" in resp.get_json()["error"]


# ── 7. Frozen Subsystem Verification ─────────────────────────────────

def test_frozen_presence_and_telemetry_constants():
    """Verify that all frozen constants remain strictly untouched."""
    from master.app.config import config as master_cfg
    from client.app.config import config as client_cfg

    assert master_cfg.HEARTBEAT_TIMEOUT_SECONDS == 9
    assert master_cfg.PRESENCE_CHECK_INTERVAL == 1
    assert master_cfg.TELEMETRY_INTERVAL == 10

    assert client_cfg.HEARTBEAT_INTERVAL == 3
    assert client_cfg.TELEMETRY_INTERVAL == 10
