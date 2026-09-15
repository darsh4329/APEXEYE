"""
APEXEYE — Linux Agent Test Suite (Phase 3)

Tests:
1. Linux Client Configuration loading
2. Linux Client Logger
3. Linux Client Module Imports
4. Linux Telemetry Collectors (CPU, Memory, Disk, Network, OS Info, Events)
5. Linux MasterConnection (Health check, diagnostics, buffering)
6. Linux Client Authentication / Pairing Flow
7. Linux Agent Lifecycle Orchestrator
8. Linux Client Main entry point
9. Master Integration with LINUX_PC device type
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.api import create_app
from master.app.services.device_service import DeviceService
from client_linux.app.config import config, LinuxClientConfig
from client_linux.app.utils.logger import get_logger
from client_linux.app.communication import MasterConnection
from client_linux.app.auth import ClientAuth
from client_linux.app.collectors import (
    CPUCollector,
    MemoryCollector,
    DiskCollector,
    NetworkCollector,
    OSInfoCollector,
    EventCollector,
)
from client_linux.app.agent import Agent


class TestLinuxClientConfig(unittest.TestCase):
    """Test Linux client configuration."""

    def test_app_name(self):
        self.assertEqual(config.APP_NAME, "APEXEYE Linux Client")

    def test_device_type(self):
        self.assertEqual(config.DEVICE_TYPE, "LINUX_PC")

    def test_version(self):
        self.assertEqual(config.VERSION, "0.3.0")

    def test_client_id_present(self):
        self.assertTrue(len(config.CLIENT_ID) > 0)

    def test_master_url_resolution(self):
        self.assertTrue(config.master_url.startswith("http://"))

    def test_intervals_are_positive_ints(self):
        self.assertGreater(config.HEARTBEAT_INTERVAL, 0)
        self.assertGreater(config.TELEMETRY_INTERVAL, 0)
        self.assertGreater(config.EVENT_SCAN_INTERVAL, 0)
        self.assertGreater(config.HOST_INFO_INTERVAL, 0)


class TestLinuxClientLogging(unittest.TestCase):
    """Test Linux client logging utility."""

    def test_get_logger(self):
        log = get_logger("test.linux.logger")
        self.assertIsNotNone(log)

    def test_logger_can_log(self):
        log = get_logger("test.linux.logger2")
        log.info("Phase 3 Linux test log message")


class TestLinuxCollectors(unittest.TestCase):
    """Test Linux-specific telemetry collectors."""

    def test_cpu_collector(self):
        collector = CPUCollector()
        data = collector.collect()
        self.assertIn("timestamp", data)
        self.assertIn("cpu_usage", data)
        self.assertIn("cpu_cores", data)
        self.assertIn("load_average", data)
        self.assertIsInstance(data["cpu_usage"], (int, float))

    def test_memory_collector(self):
        collector = MemoryCollector()
        data = collector.collect()
        self.assertIn("timestamp", data)
        self.assertIn("memory_total_gb", data)
        self.assertIn("memory_used_gb", data)
        self.assertIn("memory_usage_percent", data)
        self.assertIsInstance(data["memory_usage_percent"], (int, float))

    def test_disk_collector(self):
        collector = DiskCollector()
        data = collector.collect()
        self.assertIn("timestamp", data)
        self.assertIn("disk_usage_percent", data)
        self.assertIn("disk_total_gb", data)
        self.assertIn("drives", data)
        self.assertIsInstance(data["drives"], list)

    def test_network_collector(self):
        collector = NetworkCollector()
        data = collector.collect()
        self.assertIn("timestamp", data)
        self.assertIn("network_bytes_sent_mb", data)
        self.assertIn("network_bytes_recv_mb", data)
        self.assertIn("interfaces", data)
        self.assertIsInstance(data["interfaces"], list)

    def test_os_info_collector(self):
        collector = OSInfoCollector()
        data = collector.collect()
        self.assertIn("timestamp", data)
        self.assertIn("hostname", data)
        self.assertIn("operating_system", data)
        self.assertIn("architecture", data)
        self.assertIn("local_ip", data)

    def test_event_collector(self):
        collector = EventCollector()
        events = collector.collect()
        self.assertIsInstance(events, list)


class TestLinuxCommunication(unittest.TestCase):
    """Test MasterConnection in Linux client."""

    def test_format_diagnostics_safe(self):
        conn = MasterConnection("http://192.168.1.150:9100")
        diag = conn.format_diagnostics("Connection refused")
        self.assertIn("192.168.1.150:9100", diag)
        self.assertIn("APEXEYE LINUX AGENT CONNECTIVITY DIAGNOSTIC", diag)
        self.assertIn("Possible Causes:", diag)
        self.assertIn("Troubleshooting Steps:", diag)

    def test_offline_buffer(self):
        conn = MasterConnection("http://127.0.0.1:9999")
        conn.set_identity("test-dev", "test-token")
        with patch.object(config, "MAX_RETRY_ATTEMPTS", 0), patch.object(config, "RETRY_BASE_DELAY", 0):
            success = conn.send_telemetry({"cpu": {"usage": 10}})
            self.assertFalse(success)
            self.assertGreater(len(conn._offline_buffer), 0)


class TestLinuxAuthAndMasterIntegration(unittest.TestCase):
    """Test Linux agent registration and authentication against Master."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.flask_app = create_app()
        cls.flask_app.config["TESTING"] = True
        cls.test_client = cls.flask_app.test_client()

    def test_linux_device_registration_and_auth(self):
        device_id = "test-linux-node-01"

        # 1. Register as LINUX_PC
        reg_resp = self.test_client.post("/api/client/register", json={
            "device_id": device_id,
            "device_name": "Ubuntu-Server-01",
            "device_type": "LINUX_PC",
            "operating_system": "Ubuntu 24.04 LTS",
            "hostname": "ubuntu-srv-01",
            "ip_address": "192.168.1.80",
        })
        self.assertEqual(reg_resp.status_code, 201)
        data = reg_resp.get_json()
        token = data["token"]
        self.assertEqual(data["device_id"], device_id)

        # 2. Authenticate
        auth_resp = self.test_client.post(
            f"/api/devices/{device_id}/authenticate",
            json={"token": token}
        )
        self.assertEqual(auth_resp.status_code, 200)

        # 3. Verify Master recorded device_type = LINUX_PC
        conn = get_connection()
        device_row = conn.execute(
            "SELECT device_id, device_type, authentication_status FROM devices WHERE device_id = ?;",
            (device_id,)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(device_row)
        self.assertEqual(device_row["device_type"], "LINUX_PC")
        self.assertEqual(device_row["authentication_status"], "paired")

        # 4. Transmit authenticated Linux telemetry (Master returns 201 Created)
        tel_resp = self.test_client.post(
            "/api/telemetry",
            json={
                "device_id": device_id,
                "cpu": {"cpu_usage": 15.5},
                "memory": {"memory_usage_percent": 42.0},
                "disk": {"disk_usage_percent": 30.0},
                "network": {"network_bytes_sent_mb": 5.0, "network_bytes_recv_mb": 12.0},
            },
            headers={"X-Device-ID": device_id, "X-Auth-Token": token}
        )
        self.assertIn(tel_resp.status_code, (200, 201))

        # 5. Transmit Linux heartbeat
        hb_resp = self.test_client.post(
            "/api/heartbeat",
            json={"device_id": device_id, "client_status": "running"},
            headers={"X-Device-ID": device_id, "X-Auth-Token": token}
        )
        self.assertEqual(hb_resp.status_code, 200)


class TestLinuxAgentOrchestrator(unittest.TestCase):
    """Test Linux Agent lifecycle."""

    def test_agent_init_and_workers(self):
        conn = MasterConnection("http://127.0.0.1:9100")
        conn.set_identity("test-dev", "test-token")
        agent = Agent(conn)
        self.assertTrue(agent.is_running)
        agent.stop()
        self.assertFalse(agent.is_running)


class TestLinuxClientMain(unittest.TestCase):
    """Test client_linux.main entry point with mocks."""

    @patch("client_linux.app.communication.MasterConnection.check_master_health")
    @patch("client_linux.app.auth.ClientAuth.pair")
    @patch("client_linux.app.agent.Agent.start")
    @patch("client_linux.app.agent.Agent.wait")
    def test_linux_main_runs(self, mock_wait, mock_start, mock_pair, mock_health):
        mock_health.return_value = (True, {"status": "healthy", "version": "0.3.0"})
        mock_pair.return_value = True
        from client_linux.main import main
        main()
        mock_health.assert_called_once()
        mock_pair.assert_called_once()
        mock_start.assert_called_once()
        mock_wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()
