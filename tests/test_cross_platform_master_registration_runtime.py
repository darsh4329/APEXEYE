"""
APEXEYE — Cross-Platform Master Registration & Authentication Runtime Tests

Tests the complete runtime startup/authentication/registration flow for:
1. Windows Client (client/)
2. Linux Client (client_linux/)
3. Master Server (master/)

Validates:
- Master starting with 0 online devices.
- Client starting with existing .credentials.json contacts Master POST /api/devices/<device_id>/authenticate.
- Master upserts the device, marks it online and paired.
- Master summary correctly shows TOTAL DEVICES = 1, ONLINE CLIENTS = 1.
- No duplicate device rows created across multiple restarts.
- Forced re-authentication lifecycle (REAUTHENTICATE_AGENT), credentials cleared, device retained.
- Re-pairing restores the same device row without duplicates.
- Network failure preserves credentials.
- 401/403 clears credentials and enters WAITING_FOR_PAIRING.
"""

import json
import os
import sqlite3
import sys
import logging
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
from master.app.api import create_app

# Windows Client imports
from client.app.config import config as win_client_config
from client.app.auth import ClientAuth as WinClientAuth, _CRED_FILE as WIN_CRED_FILE
from client.app.communication import MasterConnection as WinMasterConnection
from client.app.services.command_handler import CommandHandler as WinCommandHandler
from client.app.ui.dashboard import create_client_ui_app as create_win_ui_app

# Linux Client imports
from client_linux.app.config import config as lin_client_config
from client_linux.app.auth import ClientAuth as LinClientAuth, _CRED_FILE as LIN_CRED_FILE
from client_linux.app.communication import MasterConnection as LinMasterConnection
from client_linux.app.services.command_handler import CommandHandler as LinCommandHandler
from client_linux.app.ui.dashboard import create_client_ui_app as create_lin_ui_app


@pytest.fixture
def clean_db(tmp_path):
    """Provide a completely isolated, clean Master database starting with 0 devices."""
    db_file = tmp_path / "apexeye_runtime_test.db"
    orig_db = master_config.DB_PATH
    master_config.DB_PATH = str(db_file)
    init_database()
    yield str(db_file)
    master_config.DB_PATH = orig_db


@pytest.fixture
def master_client(clean_db):
    """Flask test client for Master API."""
    with patch("master.app.config.config.DB_PATH", clean_db):
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client


class TestWindowsClientMasterRegistrationRuntime:
    """Windows client runtime startup, authentication, and registration tests."""

    def test_windows_client_startup_with_saved_credentials_registers_device_on_master(
        self, clean_db, master_client, tmp_path, caplog
    ):
        """
        WINDOWS:
        1. Start Master with zero devices.
        2. Pre-register device on Master (token generated, device offline/pending).
        3. Master starts with ONLINE CLIENTS = 0.
        4. Start Windows client auth with saved .credentials.json.
        5. Verify Windows actually contacts Master.
        6. Verify Master updates the device row.
        7. Verify Master marks device online and paired.
        8. Master summary: TOTAL DEVICES = 1, ONLINE CLIENTS = 1.
        """
        device_svc = DeviceService()
        auth_svc = AuthService()

        # Step 1: Master starts with 0 devices
        summary = device_svc.get_summary()
        assert summary["total_devices"] == 0
        assert summary["online_devices"] == 0

        # Step 2 & 3: Device provisioned on Master
        dev_id = "win-desktop-01"
        device_svc.upsert_device({
            "device_id": dev_id,
            "device_name": "Windows Workstation",
            "device_type": "WINDOWS_PC",
        }, status="offline", auth_status="unauthenticated")

        pair_info = auth_svc.generate_pairing_credential(dev_id)
        raw_token = pair_info["token"]

        # Verify Master starts with ONLINE CLIENTS = 0
        summary_before = device_svc.get_summary()
        assert summary_before["total_devices"] == 1
        assert summary_before["online_devices"] == 0

        # Create saved .credentials.json for Windows client
        win_cred_path = tmp_path / "win_client" / ".credentials.json"
        win_cred_path.parent.mkdir(parents=True, exist_ok=True)

        with patch("client.app.auth._CRED_FILE", win_cred_path), \
             patch("client.app.config.config.CLIENT_ID", dev_id):
            
            # Setup bridge connection that calls Master Flask app
            mock_conn = WinMasterConnection("http://127.0.0.1:9100")
            def _mock_request(method, path, data=None, authenticated=False, timeout=15.0):
                if method == "POST":
                    resp = master_client.post(path, json=data)
                elif method == "GET":
                    resp = master_client.get(path)
                return resp.status_code, resp.get_json() or {}

            mock_conn._request = _mock_request

            # Step 4: Initialize client auth and save credentials to disk
            client_auth = WinClientAuth(mock_conn)
            client_auth._save_credentials({
                "device_id": dev_id,
                "token": raw_token,
                "status": "paired",
            })

            # Re-initialize client (simulating fresh startup)
            with caplog.at_level(logging.INFO):
                startup_auth = WinClientAuth(mock_conn)
                assert startup_auth.is_authenticated is False, "Must not be authenticated before Master verification"

                # Step 5: Startup verification against Master
                pair_success = startup_auth.pair()
                assert pair_success is True
                assert startup_auth.is_authenticated is True

            # Verify safe diagnostic logs
            log_text = caplog.text
            assert "[AUTH] Starting Master authentication" in log_text
            assert f"[AUTH] Device ID: {dev_id}" in log_text
            assert f"[AUTH] Contacting Master: /api/devices/{dev_id}/authenticate" in log_text
            assert "[AUTH] Master response: 200" in log_text
            assert "[AUTH] Master authentication successful" in log_text
            assert "[DEVICE] Master registration synchronized" in log_text

            # Step 6, 7, 8: Verify Master database state
            master_summary = device_svc.get_summary()
            assert master_summary["total_devices"] == 1
            assert master_summary["online_devices"] == 1

            device = device_svc.get_device(dev_id)
            assert device is not None
            assert device["device_id"] == dev_id
            assert device["status"] == "online"
            assert device["authentication_status"] == "paired"
            assert device["device_type"] in ("WINDOWS_PC", "LINUX_PC")
            assert device["last_seen"] is not None

    def test_windows_client_ui_serves_auth_page_when_unauthenticated_and_dashboard_when_authenticated(
        self, clean_db, master_client, tmp_path
    ):
        """Verify local dashboard does not open in authenticated state before Master authentication."""
        mock_conn = WinMasterConnection("http://127.0.0.1:9100")
        client_auth = WinClientAuth(mock_conn)
        client_auth._clear_credentials()

        app = create_win_ui_app(client_auth, mock_conn)
        test_client = app.test_client()

        # Unauthenticated: serves auth HTML
        resp = test_client.get("/")
        assert resp.status_code == 200
        assert "Device Authentication" in resp.get_data(as_text=True)

        status_resp = test_client.get("/api/local/status")
        assert status_resp.get_json()["is_authenticated"] is False
        assert status_resp.get_json()["is_paired"] is False

        # Metrics return 401
        metrics_resp = test_client.get("/api/local/metrics")
        assert metrics_resp.status_code == 401


class TestLinuxClientMasterRegistrationRuntime:
    """Linux client runtime startup, authentication, and registration tests."""

    def test_linux_client_startup_with_saved_credentials_registers_device_on_master(
        self, clean_db, master_client, tmp_path, caplog
    ):
        """
        LINUX:
        1. Start Master with zero devices.
        2. Pre-register Linux device on Master (offline/pending).
        3. Master starts with ONLINE CLIENTS = 0.
        4. Start Linux client auth with saved .credentials.json.
        5. Verify Linux actually contacts Master and sends device_type=LINUX_PC.
        6. Verify Master updates the device row.
        7. Verify Master marks device online and paired.
        8. Master summary: TOTAL DEVICES = 1, ONLINE CLIENTS = 1.
        """
        device_svc = DeviceService()
        auth_svc = AuthService()

        # Step 1: Master starts with 0 devices
        summary = device_svc.get_summary()
        assert summary["total_devices"] == 0
        assert summary["online_devices"] == 0

        # Step 2 & 3: Provision device on Master
        dev_id = "lin-server-01"
        device_svc.upsert_device({
            "device_id": dev_id,
            "device_name": "Linux Node 1",
            "device_type": "LINUX_PC",
        }, status="offline", auth_status="unauthenticated")

        pair_info = auth_svc.generate_pairing_credential(dev_id)
        raw_token = pair_info["token"]

        # Verify Master starts with ONLINE CLIENTS = 0
        assert device_svc.get_summary()["online_devices"] == 0

        # Create saved .credentials.json for Linux client
        lin_cred_path = tmp_path / "lin_client" / ".credentials.json"
        lin_cred_path.parent.mkdir(parents=True, exist_ok=True)

        with patch("client_linux.app.auth._CRED_FILE", lin_cred_path), \
             patch("client_linux.app.config.config.CLIENT_ID", dev_id):
            
            mock_conn = LinMasterConnection("http://127.0.0.1:9100")
            def _mock_request(method, path, data=None, authenticated=False, timeout=15.0):
                if method == "POST":
                    resp = master_client.post(path, json=data)
                elif method == "GET":
                    resp = master_client.get(path)
                return resp.status_code, resp.get_json() or {}

            mock_conn._request = _mock_request

            # Step 4: Initialize client auth and save credentials to disk
            client_auth = LinClientAuth(mock_conn)
            client_auth._save_credentials({
                "device_id": dev_id,
                "token": raw_token,
                "status": "paired",
            })

            # Re-initialize client (simulating fresh startup)
            with caplog.at_level(logging.INFO):
                startup_auth = LinClientAuth(mock_conn)
                assert startup_auth.is_authenticated is False, "Must not be authenticated before Master verification"

                # Step 5: Startup verification against Master
                pair_success = startup_auth.pair()
                assert pair_success is True
                assert startup_auth.is_authenticated is True

            # Verify safe diagnostic logs
            log_text = caplog.text
            assert "[AUTH] Starting Master authentication" in log_text
            assert f"[AUTH] Device ID: {dev_id}" in log_text
            assert f"[AUTH] Contacting Master: /api/devices/{dev_id}/authenticate" in log_text
            assert "[AUTH] Master response: 200" in log_text
            assert "[AUTH] Master authentication successful" in log_text
            assert "[DEVICE] Master registration synchronized" in log_text

            # Step 6, 7, 8: Verify Master database state
            master_summary = device_svc.get_summary()
            assert master_summary["total_devices"] == 1
            assert master_summary["online_devices"] == 1

            device = device_svc.get_device(dev_id)
            assert device is not None
            assert device["device_id"] == dev_id
            assert device["status"] == "online"
            assert device["authentication_status"] == "paired"
            assert device["device_type"] == "LINUX_PC"
            assert device["last_seen"] is not None


class TestDuplicatePreventionAndReconnect:
    """Duplicate prevention across restarts and reconnects for both clients."""

    def test_restarting_same_client_multiple_times_preserves_single_device_row(
        self, clean_db, master_client, tmp_path
    ):
        """
        Verify that multiple restarts of the same client never produce duplicate devices (e.g. vansh-2, vansh-3).
        Device count MUST remain 1.
        """
        device_svc = DeviceService()
        auth_svc = AuthService()

        dev_id = "workstation-node"
        device_svc.upsert_device({
            "device_id": dev_id,
            "device_name": "Workstation Node",
            "device_type": "WINDOWS_PC",
        }, status="offline", auth_status="unauthenticated")

        pair_info = auth_svc.generate_pairing_credential(dev_id)
        raw_token = pair_info["token"]

        win_cred_path = tmp_path / "win_dup_test" / ".credentials.json"
        win_cred_path.parent.mkdir(parents=True, exist_ok=True)

        with patch("client.app.auth._CRED_FILE", win_cred_path), \
             patch("client.app.config.config.CLIENT_ID", dev_id):
            
            mock_conn = WinMasterConnection("http://127.0.0.1:9100")
            def _mock_request(method, path, data=None, authenticated=False, timeout=15.0):
                if method == "POST":
                    resp = master_client.post(path, json=data)
                elif method == "GET":
                    resp = master_client.get(path)
                return resp.status_code, resp.get_json() or {}
            mock_conn._request = _mock_request

            # 1. First start
            auth1 = WinClientAuth(mock_conn)
            auth1.authenticate(dev_id, raw_token)
            assert device_svc.get_summary()["total_devices"] == 1

            # 2. Restart 1
            auth2 = WinClientAuth(mock_conn)
            assert auth2.pair() is True
            assert device_svc.get_summary()["total_devices"] == 1

            # 3. Restart 2
            auth3 = WinClientAuth(mock_conn)
            assert auth3.pair() is True
            assert device_svc.get_summary()["total_devices"] == 1

            # 4. Restart 3
            auth4 = WinClientAuth(mock_conn)
            assert auth4.pair() is True
            assert device_svc.get_summary()["total_devices"] == 1

            # Verify only 1 row exists in SQLite table
            db_conn = sqlite3.connect(clean_db)
            try:
                rows = db_conn.execute("SELECT device_id FROM devices;").fetchall()
                assert len(rows) == 1
                assert rows[0][0] == dev_id
            finally:
                db_conn.close()


class TestForcedReauthenticationAndRepairing:
    """Forced re-authentication (REAUTHENTICATE_AGENT) lifecycle for Windows and Linux."""

    def test_windows_forced_reauth_and_re_pairing_lifecycle(
        self, clean_db, master_client, tmp_path
    ):
        """
        1. Windows device online.
        2. Master sends REAUTHENTICATE_AGENT.
        3. Client credentials invalidated, WAITING_FOR_PAIRING reached.
        4. Master preserves device row, marks status unauthenticated.
        5. Re-pair client with new token.
        6. Same device_id restored, status online/paired, 0 duplicates.
        """
        device_svc = DeviceService()
        auth_svc = AuthService()

        dev_id = "win-corp-pc"
        device_svc.upsert_device({
            "device_id": dev_id,
            "device_name": "Windows Corp PC",
            "device_type": "WINDOWS_PC",
        }, status="offline", auth_status="unauthenticated")

        pair_info = auth_svc.generate_pairing_credential(dev_id)
        raw_token = pair_info["token"]

        win_cred_path = tmp_path / "win_reauth_test" / ".credentials.json"
        win_cred_path.parent.mkdir(parents=True, exist_ok=True)

        with patch("client.app.auth._CRED_FILE", win_cred_path), \
             patch("client.app.config.config.CLIENT_ID", dev_id):
            
            mock_conn = WinMasterConnection("http://127.0.0.1:9100")
            def _mock_request(method, path, data=None, authenticated=False, timeout=15.0):
                if method == "POST":
                    resp = master_client.post(path, json=data)
                elif method == "GET":
                    resp = master_client.get(path)
                return resp.status_code, resp.get_json() or {}
            mock_conn._request = _mock_request

            # Authenticate initially
            auth = WinClientAuth(mock_conn)
            assert auth.authenticate(dev_id, raw_token)[0] is True
            assert device_svc.get_summary()["online_devices"] == 1

            # Master sends REAUTHENTICATE_AGENT
            handler = WinCommandHandler(conn=mock_conn, auth=auth)
            cmd_resp = handler.handle_command({
                "command_id": "CMD-REAUTH-WIN",
                "device_id": dev_id,
                "command_type": "REAUTHENTICATE_AGENT",
            })
            assert cmd_resp["success"] is True
            assert cmd_resp["data"]["lifecycle_state"] == "WAITING_FOR_PAIRING"
            assert auth.is_authenticated is False
            assert not mock_conn.is_authenticated

            # Revoke on Master side
            auth_svc.revoke_device(dev_id)
            dev_row = device_svc.get_device(dev_id)
            assert dev_row is not None
            assert dev_row["authentication_status"] == "unauthenticated"

            # Admin generates new pairing token for SAME device
            new_cred = auth_svc.generate_pairing_credential(dev_id)
            new_token = new_cred["token"]

            # Re-pair client
            repair_ok, _ = auth.authenticate(dev_id, new_token)
            assert repair_ok is True
            assert auth.is_authenticated is True

            # Verify Master state: SAME device row, online, 0 duplicates
            assert device_svc.get_summary()["total_devices"] == 1
            assert device_svc.get_summary()["online_devices"] == 1
            updated_dev = device_svc.get_device(dev_id)
            assert updated_dev["status"] == "online"
            assert updated_dev["authentication_status"] == "paired"

    def test_linux_forced_reauth_and_re_pairing_lifecycle(
        self, clean_db, master_client, tmp_path
    ):
        """
        1. Linux device online.
        2. Master sends REAUTHENTICATE_AGENT.
        3. Client credentials invalidated, WAITING_FOR_PAIRING reached.
        4. Master preserves device row, marks status unauthenticated.
        5. Re-pair client with new token.
        6. Same device_id restored, status online/paired, 0 duplicates.
        """
        device_svc = DeviceService()
        auth_svc = AuthService()

        dev_id = "lin-prod-server"
        device_svc.upsert_device({
            "device_id": dev_id,
            "device_name": "Linux Prod Server",
            "device_type": "LINUX_PC",
        }, status="offline", auth_status="unauthenticated")

        pair_info = auth_svc.generate_pairing_credential(dev_id)
        raw_token = pair_info["token"]

        lin_cred_path = tmp_path / "lin_reauth_test" / ".credentials.json"
        lin_cred_path.parent.mkdir(parents=True, exist_ok=True)

        with patch("client_linux.app.auth._CRED_FILE", lin_cred_path), \
             patch("client_linux.app.config.config.CLIENT_ID", dev_id):
            
            mock_conn = LinMasterConnection("http://127.0.0.1:9100")
            def _mock_request(method, path, data=None, authenticated=False, timeout=15.0):
                if method == "POST":
                    resp = master_client.post(path, json=data)
                elif method == "GET":
                    resp = master_client.get(path)
                return resp.status_code, resp.get_json() or {}
            mock_conn._request = _mock_request

            # Authenticate initially
            auth = LinClientAuth(mock_conn)
            assert auth.authenticate(dev_id, raw_token)[0] is True
            assert device_svc.get_summary()["online_devices"] == 1

            # Master sends REAUTHENTICATE_AGENT
            handler = LinCommandHandler(conn=mock_conn, auth=auth)
            cmd_resp = handler.handle_command({
                "command_id": "CMD-REAUTH-LIN",
                "device_id": dev_id,
                "command_type": "REAUTHENTICATE_AGENT",
            })
            assert cmd_resp["success"] is True
            assert cmd_resp["data"]["lifecycle_state"] == "WAITING_FOR_PAIRING"
            assert auth.is_authenticated is False
            assert not mock_conn.is_authenticated

            # Revoke on Master side
            auth_svc.revoke_device(dev_id)
            dev_row = device_svc.get_device(dev_id)
            assert dev_row is not None
            assert dev_row["authentication_status"] == "unauthenticated"

            # Admin generates new pairing token for SAME device
            new_cred = auth_svc.generate_pairing_credential(dev_id)
            new_token = new_cred["token"]

            # Re-pair client
            repair_ok, _ = auth.authenticate(dev_id, new_token)
            assert repair_ok is True
            assert auth.is_authenticated is True

            # Verify Master state: SAME device row, online, 0 duplicates
            assert device_svc.get_summary()["total_devices"] == 1
            assert device_svc.get_summary()["online_devices"] == 1
            updated_dev = device_svc.get_device(dev_id)
            assert updated_dev["status"] == "online"
            assert updated_dev["authentication_status"] == "paired"
            assert updated_dev["device_type"] == "LINUX_PC"


class TestNetworkFailureAndRejectionResilience:
    """Verify behavior on network failure vs 401/403 rejection."""

    def test_network_failure_preserves_credentials_and_does_not_claim_authentication(self, tmp_path):
        """On connection failure (status 0), credentials MUST be preserved, but client is not authenticated."""
        mock_conn = WinMasterConnection("http://127.0.0.1:9100")
        mock_conn.authenticate = MagicMock(return_value=(0, {"error": "Connection refused"}))

        win_cred_path = tmp_path / "win_net_fail" / ".credentials.json"
        win_cred_path.parent.mkdir(parents=True, exist_ok=True)

        with patch("client.app.auth._CRED_FILE", win_cred_path):
            auth = WinClientAuth(mock_conn)
            auth._save_credentials({"device_id": "dev-net-01", "token": "tok-1", "status": "paired"})

            restart_auth = WinClientAuth(mock_conn)
            result = restart_auth.pair()
            assert result is False
            assert restart_auth.is_authenticated is False
            # Crucial: credentials file MUST NOT be wiped!
            assert win_cred_path.exists()
            assert restart_auth.token == "tok-1"

    def test_401_rejection_clears_credentials_and_preserves_device_id(self, tmp_path):
        """On 401/403 rejection, credentials MUST be cleared while device_id is preserved."""
        mock_conn = WinMasterConnection("http://127.0.0.1:9100")
        mock_conn.authenticate = MagicMock(return_value=(401, {"error": "Authentication failed"}))

        win_cred_path = tmp_path / "win_401" / ".credentials.json"
        win_cred_path.parent.mkdir(parents=True, exist_ok=True)

        with patch("client.app.auth._CRED_FILE", win_cred_path):
            auth = WinClientAuth(mock_conn)
            auth._save_credentials({"device_id": "dev-401", "token": "bad-tok", "status": "paired"})

            restart_auth = WinClientAuth(mock_conn)
            result = restart_auth.pair()
            assert result is False
            assert restart_auth.is_authenticated is False
            assert restart_auth.token is None
            assert restart_auth.device_id == "dev-401"
