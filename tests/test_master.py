"""
APEXEYE — Master Test Suite (Phase 0)

Validates:
  - Master starts successfully
  - Configuration loads
  - SQLite database initializes (idempotently)
  - Database connection works
  - All required tables exist
  - Re-running init does not destroy data
  - Logging works
"""

import os
import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path

# Ensure project root is on path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.config import config
from master.app.database import init_database, get_connection, check_database_health
from master.app.utils.logger import get_logger

EXPECTED_TABLES = {
    "devices",
    "device_auth",
    "telemetry",
    "logs",
    "alerts",
    "audit_logs",
    "reports",
}


class TestMasterConfig(unittest.TestCase):
    """Master configuration loads correctly."""

    def test_app_name(self):
        self.assertEqual(config.APP_NAME, "APEXEYE Master")

    def test_version(self):
        self.assertIsNotNone(config.VERSION)

    def test_port_is_int(self):
        self.assertIsInstance(config.PORT, int)

    def test_db_path_set(self):
        self.assertTrue(len(config.DB_PATH) > 0)


class TestMasterDatabase(unittest.TestCase):
    """Database initialization and connection tests."""

    def setUp(self):
        # Use a temporary database for tests
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_init_creates_database(self):
        init_database(self.db_path)
        self.assertTrue(Path(self.db_path).exists())

    def test_all_tables_created(self):
        init_database(self.db_path)
        conn = get_connection(self.db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table';"
        )
        tables = {row["name"] for row in cursor.fetchall()}
        conn.close()
        self.assertTrue(EXPECTED_TABLES.issubset(tables), f"Missing: {EXPECTED_TABLES - tables}")

    def test_foreign_keys_enabled(self):
        init_database(self.db_path)
        conn = get_connection(self.db_path)
        result = conn.execute("PRAGMA foreign_keys;").fetchone()
        conn.close()
        self.assertEqual(result[0], 1)

    def test_idempotent_init(self):
        """Re-running init should not destroy existing data."""
        init_database(self.db_path)
        conn = get_connection(self.db_path)
        conn.execute(
            "INSERT INTO devices (device_id, device_name, device_type) "
            "VALUES ('test-001', 'TestPC', 'WINDOWS_PC');"
        )
        conn.commit()
        conn.close()

        # Run init again
        init_database(self.db_path)

        conn = get_connection(self.db_path)
        row = conn.execute(
            "SELECT device_id FROM devices WHERE device_id='test-001';"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["device_id"], "test-001")

    def test_health_check_ok(self):
        init_database(self.db_path)
        health = check_database_health(self.db_path)
        self.assertTrue(health["ok"])
        self.assertIsNone(health["error"])
        self.assertTrue(EXPECTED_TABLES.issubset(set(health["tables"])))

    def test_health_check_missing_db(self):
        health = check_database_health("/nonexistent/path.db")
        self.assertFalse(health["ok"])

    def test_device_type_constraint(self):
        """Device type must be one of the allowed values."""
        init_database(self.db_path)
        conn = get_connection(self.db_path)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO devices (device_id, device_name, device_type) "
                "VALUES ('bad-001', 'Bad', 'INVALID_TYPE');"
            )
        conn.close()


class TestMasterLogging(unittest.TestCase):
    """Logging infrastructure works."""

    def test_logger_returns_logger(self):
        logger = get_logger("test.master")
        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, "test.master")

    def test_logger_can_log(self):
        logger = get_logger("test.master.canlog")
        # Should not raise
        logger.info("Phase 0 test log message")


class TestMasterMain(unittest.TestCase):
    """Master application can be created without error."""

    def test_app_creates(self):
        """Flask app factory creates a working application."""
        from master.app.api import create_app
        app = create_app()
        self.assertIsNotNone(app)

    def test_db_initializes_on_startup(self):
        """Database is initialized when app is created."""
        from master.app.database import check_database_health
        health = check_database_health()
        self.assertTrue(health["ok"])


if __name__ == "__main__":
    unittest.main()
