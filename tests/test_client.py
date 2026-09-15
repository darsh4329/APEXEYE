"""
APEXEYE — Client Test Suite (Phase 0)

Validates:
  - Client starts successfully
  - Configuration loads
  - Client logging works
  - Client module structure imports successfully
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.config import config
from client.app.utils.logger import get_logger


class TestClientConfig(unittest.TestCase):
    """Client configuration loads correctly."""

    def test_app_name(self):
        self.assertEqual(config.APP_NAME, "APEXEYE Client")

    def test_version(self):
        self.assertIsNotNone(config.VERSION)

    def test_client_id_generated(self):
        self.assertTrue(len(config.CLIENT_ID) > 0)

    def test_master_address(self):
        self.assertTrue(len(config.MASTER_ADDRESS) > 0)

    def test_master_port(self):
        self.assertIsInstance(config.MASTER_PORT, int)

    def test_master_url(self):
        self.assertTrue(config.master_url.startswith("http://"))


class TestClientLogging(unittest.TestCase):
    """Client logging works."""

    def test_logger_returns_logger(self):
        logger = get_logger("test.client")
        self.assertIsNotNone(logger)

    def test_logger_can_log(self):
        logger = get_logger("test.client.canlog")
        logger.info("Phase 0 client test log message")


class TestClientModuleImports(unittest.TestCase):
    """All Client placeholder modules import without error."""

    def test_import_auth(self):
        from client.app.auth import ClientAuth
        self.assertIsNotNone(ClientAuth)

    def test_import_communication(self):
        from client.app.communication import MasterConnection
        self.assertIsNotNone(MasterConnection)

    def test_import_collectors(self):
        from client.app.collectors.cpu import CPUCollector
        from client.app.collectors.memory import MemoryCollector
        from client.app.collectors.disk import DiskCollector
        from client.app.collectors.network import NetworkCollector
        from client.app.collectors.os_info import OSInfoCollector
        from client.app.collectors.events import EventCollector
        self.assertIsNotNone(CPUCollector)
        self.assertIsNotNone(MemoryCollector)
        self.assertIsNotNone(DiskCollector)
        self.assertIsNotNone(NetworkCollector)
        self.assertIsNotNone(OSInfoCollector)
        self.assertIsNotNone(EventCollector)


class TestClientMain(unittest.TestCase):
    """Client entry point runs without error when Master is reachable."""

    @patch("client.app.communication.MasterConnection.check_master_health")
    @patch("client.app.auth.ClientAuth.pair")
    @patch("client.app.agent.Agent.start")
    @patch("client.app.agent.Agent.wait")
    def test_main_runs(self, mock_wait, mock_start, mock_pair, mock_health):
        mock_health.return_value = (True, {"status": "healthy", "version": "0.2.0"})
        mock_pair.return_value = True
        from client.main import main
        main()
        mock_health.assert_called_once()
        mock_pair.assert_called_once()
        mock_start.assert_called_once()
        mock_wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()

