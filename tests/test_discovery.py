"""
APEXEYE — Master Discovery, .env Precedence & IP Change Recovery Test Suite

Tests:
1. MasterDiscoveryService UDP beacon & probe response (non-sensitive payload).
2. Client UDP discovery probe and response handling.
3. Master candidate endpoint verification (TCP + /api/health).
4. Rejection of invalid / non-Master services.
5. Cached Master endpoint persistence and invalidation.
6. Subnet broadcast enumeration and interface filtering (excluding VirtualBox, APIPA, loopback).
7. Comprehensive .env Resolution Test Cases (TEST 1 - TEST 6):
   - TEST 1: Valid .env with APEXEYE_MASTER_URL
   - TEST 2: No MASTER value in .env (triggers LAN discovery)
   - TEST 3: Process environment override (os.environ wins over .env)
   - TEST 4: Broken / unreachable .env URL (triggers LAN recovery)
   - TEST 5: Master IP changed (cache update, credential preservation, communication resume)
   - TEST 6: No Master available (safe localhost fallback warning)
"""

import json
import os
import socket
import sys
import tempfile
import shutil
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure project root is on sys.path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.services.discovery import MasterDiscoveryService
from master.app.config import config as master_config
from client.app.discovery import (
    MasterDiscoverer,
    verify_master_endpoint,
    load_cached_master,
    save_cached_master,
    get_active_subnet_broadcasts,
    is_virtual_or_link_local_ip,
)
from client.app.communication import MasterConnection
from client.app.config import ClientConfig, _resolve_master_configuration, parse_env_file


class TestMasterDiscoveryService(unittest.TestCase):
    """Test Master UDP discovery service functionality."""

    def test_discovery_payload_contains_no_secrets(self):
        """Discovery payload includes non-sensitive metadata only (no tokens/passwords/db)."""
        svc = MasterDiscoveryService(port=9101, api_port=9100)
        payload = svc.get_discovery_payload()

        self.assertEqual(payload.get("service"), "APEXEYE_MASTER")
        self.assertEqual(payload.get("port"), 9100)
        self.assertEqual(payload.get("protocol"), "http")
        self.assertIn("lan_ip", payload)
        self.assertIn("hostname", payload)
        self.assertIn("version", payload)

        # Ensure no sensitive keys exist
        for sensitive_key in ["token", "secret", "password", "db_path", "credentials", "devices"]:
            self.assertNotIn(sensitive_key, payload)

    def test_discovery_service_listener_and_probe_reply(self):
        """Master discovery service answers UDP probes sent to port 9101."""
        test_port = 19101
        svc = MasterDiscoveryService(port=test_port, api_port=9100)
        svc.start()

        try:
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_sock.settimeout(2.0)
            probe_msg = json.dumps({"query": "APEXEYE_DISCOVERY"}).encode("utf-8")
            client_sock.sendto(probe_msg, ("127.0.0.1", test_port))

            data, addr = client_sock.recvfrom(2048)
            client_sock.close()

            resp = json.loads(data.decode("utf-8"))
            self.assertEqual(resp.get("service"), "APEXEYE_MASTER")
            self.assertEqual(resp.get("port"), 9100)
        finally:
            svc.stop()


class TestClientDiscoveryEngine(unittest.TestCase):
    """Test Client MasterDiscoverer and verification logic."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="apexeye_disc_test_")
        self.cache_file = Path(self.temp_dir) / ".apexeye_master_cache.json"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_verify_master_endpoint_success(self):
        """verify_master_endpoint succeeds when TCP connects and /api/health returns healthy."""
        with patch("socket.create_connection"):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.read.return_value = json.dumps({
                    "status": "healthy",
                    "app": "APEXEYE Master",
                    "version": "0.1.0",
                }).encode("utf-8")
                mock_urlopen.return_value.__enter__.return_value = mock_resp

                ok, data = verify_master_endpoint("http://10.165.255.109:9100")
                self.assertTrue(ok)
                self.assertEqual(data.get("status"), "healthy")

    def test_verify_master_endpoint_rejects_unhealthy(self):
        """verify_master_endpoint rejects endpoints returning non-healthy responses."""
        with patch("socket.create_connection"):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.read.return_value = json.dumps({
                    "status": "unhealthy",
                    "error": "database down",
                }).encode("utf-8")
                mock_urlopen.return_value.__enter__.return_value = mock_resp

                ok, _ = verify_master_endpoint("http://10.165.255.109:9100")
                self.assertFalse(ok)

    def test_verify_master_endpoint_rejects_unreachable_tcp(self):
        """verify_master_endpoint rejects when TCP port connection fails."""
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
            ok, err = verify_master_endpoint("http://10.165.255.109:9100")
            self.assertFalse(ok)
            self.assertIn("unreachable", err.get("error", ""))

    def test_cache_save_and_load(self):
        """Cached endpoint can be persisted and reloaded."""
        save_cached_master(
            "http://10.165.255.109:9100",
            hostname="Master-PC",
            source="LAN discovery (10.165.255.109:9100)",
            cache_path=self.cache_file,
        )

        cached = load_cached_master(self.cache_file)
        self.assertIsNotNone(cached)
        self.assertEqual(cached.get("url"), "http://10.165.255.109:9100")
        self.assertEqual(cached.get("hostname"), "Master-PC")
        self.assertIn("verified_at", cached)

    def test_subnet_broadcast_calculation_and_filtering(self):
        """get_active_subnet_broadcasts includes 255.255.255.255 and excludes virtual adapters."""
        bcasts = get_active_subnet_broadcasts()
        self.assertIn("255.255.255.255", bcasts)
        self.assertTrue(is_virtual_or_link_local_ip("192.168.56.1"))
        self.assertTrue(is_virtual_or_link_local_ip("169.254.12.34"))
        self.assertTrue(is_virtual_or_link_local_ip("127.0.0.1"))
        self.assertFalse(is_virtual_or_link_local_ip("10.165.255.109"))

    def test_discover_via_udp_lan(self):
        """Client UDP probe finds Master and verifies endpoint."""
        discoverer = MasterDiscoverer(discovery_port=19102)

        fake_response = json.dumps({
            "service": "APEXEYE_MASTER",
            "version": "0.1.0",
            "port": 9100,
            "lan_ip": "10.165.255.109",
            "hostname": "Vansh_pc",
        }).encode("utf-8")

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (fake_response, ("10.165.255.109", 19102))
            mock_sock_cls.return_value = mock_sock

            with patch("client.app.discovery.verify_master_endpoint", return_value=(True, {"status": "healthy"})):
                with patch("client.app.discovery.save_cached_master"):
                    result = discoverer.discover_via_udp_lan(timeout=0.5)
                    self.assertIsNotNone(result)
                    url, src = result
                    self.assertEqual(url, "http://10.165.255.109:9100")
                    self.assertIn("LAN discovery", src)


class TestRequiredEnvAndPrecedenceCases(unittest.TestCase):
    """
    Test the 6 specific required .env resolution and precedence test cases.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="apexeye_env_req_test_")
        self.env_file = Path(self.temp_dir) / ".env"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_valid_env(self):
        """TEST 1 — Valid .env containing APEXEYE_MASTER_URL."""
        self.env_file.write_text("APEXEYE_MASTER_URL=http://10.165.255.109:9100\n", encoding="utf-8")

        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env["APEXEYE_ENV_FILE"] = str(self.env_file)

        with patch.dict(os.environ, clean_env, clear=True):
            with patch("client.app.discovery.verify_master_endpoint", return_value=(True, {"status": "healthy"})):
                cfg = ClientConfig()
                self.assertEqual(cfg.master_url, "http://10.165.255.109:9100")
                self.assertIn(".env", cfg.source)
                self.assertFalse(cfg.is_localhost_target)

    def test_02_no_master_value_in_env_triggers_lan_discovery(self):
        """TEST 2 — No MASTER value in .env triggers automatic LAN discovery."""
        self.env_file.write_text("# Optional explicit Master override\nAPEXEYE_MASTER_URL=\nAPEXEYE_CLIENT_UI_PORT=9200\n", encoding="utf-8")

        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env["APEXEYE_ENV_FILE"] = str(self.env_file)

        with patch.dict(os.environ, clean_env, clear=True):
            with patch("client.app.discovery.master_discoverer.discover_via_udp_lan", return_value=("http://10.165.255.109:9100", "LAN discovery (10.165.255.109:9100)")):
                cfg = ClientConfig()
                self.assertEqual(cfg.master_url, "http://10.165.255.109:9100")
                self.assertIn("LAN discovery", cfg.source)
                self.assertFalse(cfg.is_localhost_target)
                self.assertTrue(cfg.lan_discovery_attempted)

    def test_03_process_environment_override_wins_over_env(self):
        """TEST 3 — Process environment variable APEXEYE_MASTER_URL takes precedence over .env."""
        self.env_file.write_text("APEXEYE_MASTER_URL=http://10.165.255.109:9100\n", encoding="utf-8")

        with patch.dict(os.environ, {
            "APEXEYE_MASTER_URL": "http://10.165.255.121:9100",
            "APEXEYE_ENV_FILE": str(self.env_file),
        }):
            with patch("client.app.discovery.verify_master_endpoint", return_value=(True, {"status": "healthy"})):
                cfg = ClientConfig()
                self.assertEqual(cfg.master_url, "http://10.165.255.121:9100")
                self.assertIn("environment (APEXEYE_MASTER_URL)", cfg.source)
                self.assertFalse(cfg.is_localhost_target)

    def test_04_broken_env_url_triggers_lan_recovery(self):
        """TEST 4 — Broken/unreachable .env URL triggers automatic LAN discovery recovery."""
        self.env_file.write_text("APEXEYE_MASTER_URL=http://10.0.0.123:9100\n", encoding="utf-8")

        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env["APEXEYE_ENV_FILE"] = str(self.env_file)

        # Mock: 10.0.0.123 is unreachable, but LAN discovery finds 10.165.255.109
        def mock_verify(url, timeout=2.0):
            if "10.0.0.123" in url:
                return False, {"error": "TCP unreachable"}
            return True, {"status": "healthy"}

        with patch.dict(os.environ, clean_env, clear=True):
            with patch("client.app.discovery.verify_master_endpoint", side_effect=mock_verify):
                with patch("client.app.discovery.master_discoverer.discover_via_udp_lan", return_value=("http://10.165.255.109:9100", "LAN discovery (10.165.255.109:9100)")):
                    cfg = ClientConfig()
                    self.assertEqual(cfg.master_url, "http://10.165.255.109:9100")
                    self.assertIn("LAN discovery", cfg.source)
                    self.assertFalse(cfg.is_localhost_target)

    def test_05_master_ip_changed_recovery_and_credential_preservation(self):
        """TEST 5 — Master IP changed: recovers new IP, updates cache, preserves credentials."""
        old_ip = "10.165.255.109"
        new_ip = "10.165.255.121"

        conn = MasterConnection(f"http://{old_ip}:9100")
        conn.set_identity("device-pc-01", "tok-xyz-999")
        self.assertTrue(conn.is_authenticated)

        with patch("client.app.discovery.master_discoverer.discover_via_udp_lan", return_value=(f"http://{new_ip}:9100", f"LAN discovery ({new_ip}:9100)")):
            ok = conn.attempt_rediscovery()
            self.assertTrue(ok)
            self.assertEqual(conn.master_url, f"http://{new_ip}:9100")
            # Credentials must remain preserved
            self.assertTrue(conn.is_authenticated)
            self.assertEqual(conn._device_id, "device-pc-01")
            self.assertEqual(conn._auth_token, "tok-xyz-999")

    def test_06_no_master_available_falls_back_to_localhost(self):
        """TEST 6 — No Master available across all discovery methods falls back to localhost."""
        clean_env = dict(os.environ)
        clean_env.pop("APEXEYE_MASTER_URL", None)
        clean_env.pop("APEXEYE_MASTER_ADDRESS", None)
        clean_env.pop("APEXEYE_ENV_FILE", None)

        with patch("client.app.config.find_env_file", return_value=None):
            with patch.dict(os.environ, clean_env, clear=True):
                with patch("client.app.discovery.master_discoverer.discover_via_udp_lan", return_value=None):
                    with patch("client.app.discovery.master_discoverer.discover_via_hostnames", return_value=None):
                        with patch("client.app.discovery.master_discoverer.discover_via_cache", return_value=None):
                            cfg = ClientConfig()
                            self.assertEqual(cfg.master_url, "http://127.0.0.1:9100")
                            self.assertIn("default (localhost fallback)", cfg.source)
                            self.assertTrue(cfg.is_localhost_target)


if __name__ == "__main__":
    unittest.main()
