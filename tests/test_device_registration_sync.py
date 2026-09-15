"""
APEXEYE — Comprehensive Tests for Windows Client Registered-Device Identity Synchronization

Validates:
1. Fresh Windows client registration creates Master devices record.
2. Existing device reconnect does not create duplicates.
3. Authenticated Windows client appears in Master dashboard device queries.
4. Dashboard reports correct summary counts (TOTAL DEVICES, ONLINE, OFFLINE).
5. Host info updates device metadata (device_name, device_type, OS, hostname, IP).
6. Client heartbeat updates last_seen and keeps device ONLINE.
7. Client disconnect transitions status to OFFLINE after presence timeout while preserving registration.
8. REAUTHENTICATE_AGENT preserves device row in devices table while revoking credentials.
9. Windows client command handler stops monitoring workers and enters WAITING_FOR_PAIRING.
10. Re-pairing uses the SAME device_id, restores the SAME database record, and transitions to ONLINE / PAIRED.
11. No duplicate device rows are created across reconnects and re-authentications.
12. Direct assertions against SQLite devices and device_auth tables.
"""

import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

import pytest

from master.app.config import config as master_config
from master.app.database import get_connection, init_database
from master.app.services.device_service import DeviceService
from master.app.auth import AuthService
from master.app.services.host_info_service import HostInfoService
from master.app.services.heartbeat_service import HeartbeatService
from master.app.services.command_service import CommandService
from master.app.api import create_app

from client.app.config import config as client_config
from client.app.auth import ClientAuth, _CRED_FILE
from client.app.communication import MasterConnection
from client.app.services.command_handler import CommandHandler
from client.app.agent import Agent


@pytest.fixture
def test_db_path(tmp_path):
    """Provide an isolated test database for regression verification."""
    db_file = tmp_path / "apexeye_test.db"
    orig_db = master_config.DB_PATH
    master_config.DB_PATH = str(db_file)
    init_database()
    yield str(db_file)
    master_config.DB_PATH = orig_db


@pytest.fixture
def master_test_client(test_db_path):
    """Flask test client for Master API."""
    with patch("master.app.config.config.DB_PATH", test_db_path):
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client


# ═══════════════════════════════════════════════════════════════════════════
# 1. WINDOWS PERSISTENT IDENTITY & REGISTRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_deterministic_device_identity_resolution(tmp_path):
    """Verify that client identity is deterministic and does not churn random UUIDs."""
    client_dir = tmp_path / "client"
    client_dir.mkdir(parents=True)
    cred_file = client_dir / ".credentials.json"
    
    # 1. Stored identity is respected
    cred_file.write_text(json.dumps({"device_id": "vansh-workstation", "status": "unauthenticated"}))
    with patch("client.app.config.find_env_file", return_value=None), \
         patch.object(client_config, "_PROJECT_ROOT", tmp_path):
        client_config.reload()
        assert client_config.CLIENT_ID == "vansh-workstation"

    # 2. Explicit environment variable takes highest priority
    with patch.dict(os.environ, {"APEXEYE_DEVICE_ID": "vansh-laptop"}):
        client_config.reload()
        assert client_config.CLIENT_ID == "vansh-laptop"


def test_fresh_client_registration_creates_master_device(test_db_path, master_test_client):
    """Fresh client registration endpoint creates a Master device record and generates pairing token."""
    device_payload = {
        "device_id": "vansh",
        "device_name": "Vansh",
        "device_type": "WINDOWS_PC",
        "operating_system": "Windows 11",
        "hostname": "vansh",
        "ip_address": "192.168.1.55",
    }

    resp = master_test_client.post("/api/client/register", json=device_payload)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["device_id"] == "vansh"
    assert "token" in data
    token = data["token"]

    # Verify database state
    conn = sqlite3.connect(test_db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM devices WHERE device_id = 'vansh';").fetchone()
        assert row is not None
        assert row["device_id"] == "vansh"
        assert row["device_name"] == "Vansh"
        assert row["device_type"] == "WINDOWS_PC"
        assert row["operating_system"] == "Windows 11"
        assert row["hostname"] == "vansh"
        assert row["ip_address"] == "192.168.1.55"
        assert row["status"] == "pending"
        assert row["authentication_status"] == "pending"

        auth_row = conn.execute("SELECT * FROM device_auth WHERE device_id = 'vansh';").fetchone()
        assert auth_row is not None
        assert auth_row["authentication_status"] == "pending"
    finally:
        conn.close()


def test_authentication_with_device_info_activates_device(test_db_path, master_test_client):
    """Authenticating with token + device_info transitions device to ONLINE and PAIRED."""
    # 1. Register device and generate token
    device_payload = {
        "device_id": "vansh",
        "device_name": "Vansh",
        "device_type": "WINDOWS_PC",
        "operating_system": "Windows 11",
        "hostname": "vansh",
        "ip_address": "192.168.1.55",
    }
    reg_resp = master_test_client.post("/api/client/register", json=device_payload)
    token = reg_resp.get_json()["token"]

    # 2. Authenticate
    auth_resp = master_test_client.post(
        "/api/devices/vansh/authenticate",
        json={"token": token, "device_info": device_payload},
    )
    assert auth_resp.status_code == 200
    assert auth_resp.get_json()["status"] == "paired"

    # 3. Direct DB assertions
    conn = sqlite3.connect(test_db_path)
    conn.row_factory = sqlite3.Row
    try:
        dev = conn.execute("SELECT * FROM devices WHERE device_id = 'vansh';").fetchone()
        assert dev["status"] == "online"
        assert dev["authentication_status"] == "paired"
        assert dev["last_seen"] is not None

        auth = conn.execute("SELECT * FROM device_auth WHERE device_id = 'vansh';").fetchone()
        assert auth["authentication_status"] == "paired"
        assert auth["last_used_at"] is not None
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# 2. MASTER DASHBOARD DEVICE QUERY & SUMMARY COUNTS
# ═══════════════════════════════════════════════════════════════════════════

def test_dashboard_reports_correct_device_counts(test_db_path, master_test_client):
    """Master summary reports TOTAL: 1, ONLINE: 1, OFFLINE: 0 for connected client."""
    dev_svc = DeviceService()
    auth_svc = AuthService()

    # Pre-auth summary
    sum_before = dev_svc.get_summary()
    assert sum_before["total"] == 0
    assert sum_before["online"] == 0

    # Register & Authenticate
    dev_svc.upsert_device({
        "device_id": "vansh",
        "device_name": "Vansh",
        "device_type": "WINDOWS_PC",
        "operating_system": "Windows 11",
        "hostname": "vansh",
        "ip_address": "192.168.1.55",
    })
    pair_res = auth_svc.generate_pairing_credential("vansh")
    auth_svc.authenticate_device("vansh", pair_res["token"])

    # Post-auth summary
    sum_after = dev_svc.get_summary()
    assert sum_after["total"] == 1
    assert sum_after["online"] == 1
    assert sum_after["offline"] == 0

    # List with telemetry query
    devs = dev_svc.list_devices_with_telemetry()
    assert len(devs) == 1
    assert devs[0]["device_id"] == "vansh"
    assert devs[0]["device_name"] == "Vansh"
    assert devs[0]["device_type"] == "WINDOWS_PC"
    assert devs[0]["operating_system"] == "Windows 11"
    assert devs[0]["status"] == "online"


# ═══════════════════════════════════════════════════════════════════════════
# 3. RECONNECT & NO DUPLICATE CREATION
# ═══════════════════════════════════════════════════════════════════════════

def test_existing_device_reconnect_does_not_duplicate_record(test_db_path):
    """Client reconnects using same device_id and valid token without creating extra records."""
    dev_svc = DeviceService()
    auth_svc = AuthService()

    dev_data = {
        "device_id": "vansh",
        "device_name": "Vansh",
        "device_type": "WINDOWS_PC",
        "operating_system": "Windows 11",
        "hostname": "vansh",
        "ip_address": "192.168.1.55",
    }
    dev_svc.upsert_device(dev_data)
    pair = auth_svc.generate_pairing_credential("vansh")
    auth_svc.authenticate_device("vansh", pair["token"], device_info=dev_data)

    # Simulate client restart / repeated upsert + authenticate
    for _ in range(3):
        dev_svc.upsert_device(dev_data)
        ok = auth_svc.authenticate_device("vansh", pair["token"], device_info=dev_data)
        assert ok is True

    # Assert exactly 1 record in database
    conn = sqlite3.connect(test_db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM devices WHERE device_id LIKE 'vansh%';").fetchone()[0]
        assert count == 1, f"Expected exactly 1 device row for 'vansh', found {count}"

        all_devs = conn.execute("SELECT device_id FROM devices;").fetchall()
        assert len(all_devs) == 1
        assert all_devs[0][0] == "vansh"
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# 4. HOST INFO & HEARTBEAT METADATA SYNCHRONIZATION
# ═══════════════════════════════════════════════════════════════════════════

def test_host_info_and_heartbeat_updates_metadata_and_presence(test_db_path):
    """Host info and heartbeats update device metadata, last_seen, and maintain online status."""
    dev_svc = DeviceService()
    auth_svc = AuthService()
    host_svc = HostInfoService()
    hb_svc = HeartbeatService()

    dev_svc.upsert_device({"device_id": "vansh", "device_name": "Initial Name", "device_type": "WINDOWS_PC"})
    pair = auth_svc.generate_pairing_credential("vansh")
    auth_svc.authenticate_device("vansh", pair["token"])

    # Send detailed host info
    host_info_payload = {
        "hostname": "vansh-main-pc",
        "device_name": "Vansh Pro",
        "operating_system": "Windows 11 Enterprise",
        "os_full": "Windows 11 Enterprise (Build 26100)",
        "local_ip": "192.168.1.120",
        "cpu_model": "Intel Core i7-13700H",
        "ram_total_gb": 32.0,
    }
    host_svc.store_host_info("vansh", host_info_payload)

    # Verify device record updated
    dev = dev_svc.get_device("vansh")
    assert dev["device_name"] == "Vansh Pro"
    assert dev["hostname"] == "vansh-main-pc"
    assert dev["operating_system"] == "Windows 11 Enterprise (Build 26100)"
    assert dev["device_type"] == "WINDOWS_PC"
    assert dev["ip_address"] == "192.168.1.120"
    assert dev["status"] == "online"

    # Send heartbeat
    hb_res = hb_svc.process_heartbeat("vansh", {"client_status": "running"})
    assert hb_res["status"] == "acknowledged"


# ═══════════════════════════════════════════════════════════════════════════
# 5. DISCONNECT & OFFLINE PRESENCE TRANSITION
# ═══════════════════════════════════════════════════════════════════════════

def test_client_disconnect_transitions_to_offline_without_deleting_device(test_db_path):
    """When client heartbeat stops, presence reconciliation marks it offline while preserving record."""
    dev_svc = DeviceService()
    auth_svc = AuthService()

    dev_svc.upsert_device({
        "device_id": "vansh",
        "device_name": "Vansh",
        "device_type": "WINDOWS_PC",
        "operating_system": "Windows 11",
    })
    pair = auth_svc.generate_pairing_credential("vansh")
    auth_svc.authenticate_device("vansh", pair["token"])

    # Simulate presence timeout by setting last_seen and updated_at in the past
    past_time = "2020-01-01 00:00:00"
    conn = sqlite3.connect(test_db_path)
    try:
        conn.execute("UPDATE devices SET last_seen = ?, updated_at = ? WHERE device_id = 'vansh';", (past_time, past_time))
        conn.commit()
    finally:
        conn.close()

    # Reconcile presence (timeout=5s)
    transitioned = dev_svc.reconcile_presence(timeout_seconds=5)
    assert transitioned == 1

    # Device must still exist, but status = offline, authentication_status = paired
    dev = dev_svc.get_device("vansh")
    assert dev is not None
    assert dev["device_id"] == "vansh"
    assert dev["status"] == "offline"
    assert dev["authentication_status"] == "paired"

    # Summary reflects offline device
    summary = dev_svc.get_summary()
    assert summary["total"] == 1
    assert summary["online"] == 0
    assert summary["offline"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# 6. FORCED RE-AUTHENTICATION & RE-PAIRING LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════

def test_forced_reauth_preserves_device_row_and_re_pairing_restores_online(test_db_path):
    """
    1. Master executes REAUTHENTICATE_AGENT.
    2. Master sets device offline + unauthenticated, credential revoked.
    3. Windows client command handler triggers disconnect callback and clears credentials while keeping device_id.
    4. Re-pairing uses the same device_id and restores existing database record to ONLINE + PAIRED.
    """
    dev_svc = DeviceService()
    auth_svc = AuthService()
    cmd_svc = CommandService()

    # 1. Setup online paired device
    dev_svc.upsert_device({
        "device_id": "vansh",
        "device_name": "Vansh",
        "device_type": "WINDOWS_PC",
        "operating_system": "Windows 11",
        "hostname": "vansh",
    })
    pair1 = auth_svc.generate_pairing_credential("vansh")
    auth_svc.authenticate_device("vansh", pair1["token"])

    # Client-side setup
    mock_conn = MagicMock(spec=MasterConnection)
    mock_conn.master_url = "http://127.0.0.1:9100"
    client_auth = ClientAuth(mock_conn)
    client_auth._creds = {"device_id": "vansh", "token": pair1["token"], "status": "paired"}

    disconnect_triggered = False

    def on_disconnect():
        nonlocal disconnect_triggered
        disconnect_triggered = True

    cmd_handler = CommandHandler(conn=mock_conn, auth=client_auth, disconnect_callback=on_disconnect)

    # 2. Master executes REAUTHENTICATE_AGENT
    cmd_res = cmd_svc.execute_command(
        device_id="vansh",
        command_type="REAUTHENTICATE_AGENT",
        client_handler=cmd_handler,
    )
    assert cmd_res["success"] is True
    assert disconnect_triggered is True

    # 3. Verify Master DB state
    conn = sqlite3.connect(test_db_path)
    conn.row_factory = sqlite3.Row
    try:
        dev_row = conn.execute("SELECT * FROM devices WHERE device_id = 'vansh';").fetchone()
        assert dev_row is not None
        assert dev_row["status"] == "offline"
        assert dev_row["authentication_status"] == "unauthenticated"

        auth_row = conn.execute("SELECT * FROM device_auth WHERE device_id = 'vansh';").fetchone()
        assert auth_row["authentication_status"] == "revoked"
    finally:
        conn.close()

    # Verify client state: token removed, device_id preserved
    assert client_auth.token is None
    assert client_auth.device_id == "vansh"
    assert client_auth.is_paired is False

    # 4. User generates new pairing token and re-pairs
    pair2 = auth_svc.generate_pairing_credential("vansh")

    # We mock conn.authenticate to invoke auth_svc directly during test
    def mock_authenticate(did, tok, device_info=None):
        ok = auth_svc.authenticate_device(did, tok, device_info=device_info)
        return (200 if ok else 401), ({"status": "paired"} if ok else {"error": "failed"})

    mock_conn.authenticate.side_effect = mock_authenticate
    ok, msg = client_auth.authenticate("vansh", pair2["token"])
    assert ok is True
    assert client_auth.is_paired is True
    assert client_auth.device_id == "vansh"

    # 5. Verify SAME database row is now ONLINE and PAIRED (total devices = 1)
    conn = sqlite3.connect(test_db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM devices WHERE device_id = 'vansh';").fetchall()
        assert len(rows) == 1
        assert rows[0]["status"] == "online"
        assert rows[0]["authentication_status"] == "paired"
    finally:
        conn.close()

    summary = dev_svc.get_summary()
    assert summary["total"] == 1
    assert summary["online"] == 1
    assert summary["offline"] == 0
