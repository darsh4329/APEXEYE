"""
APEXEYE — Phase 5.1 Test Suite
Activity Monitoring Hardening & Real-World Activity Semantics

Tests:
  - Word, Chrome, PowerPoint foreground detection (APPLICATION_ACTIVE)
  - Game/Entertainment launcher & game executable categorization
  - Duplicate active event suppression across identical polling cycles
  - Application focus switching (previous_application tracking)
  - Background process vs foreground active distinction
  - Ignored system processes filtering
  - Unknown foreground application handling
  - Privacy boundary: Zero window title/URL/keystroke collection
  - Master current active application query & REST API
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.api import create_app
from master.app.services.device_service import DeviceService
from master.app.services.log_service import LogService
from master.app.auth import AuthService
from client.app.collectors.events import (
    EventCollector,
    APPLICATION_TAXONOMY,
    IGNORED_SYSTEM_PROCESSES,
)


class TestPhase51ActivitySemantics(unittest.TestCase):
    """Test EventCollector activity monitoring semantics and zero-spam lifecycle."""

    def setUp(self):
        self.collector = EventCollector()
        self.collector._previous.processes = {}
        self.collector._previous.app_groups = {}
        self.collector._last_active_app = None

    def test_01_word_foreground_detection(self):
        """Word foreground -> get_current_foreground_activity (PRODUCTIVITY)."""
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="winword.exe"):
            act = self.collector.get_current_foreground_activity()
            self.assertIsNotNone(act)
            self.assertEqual(act["event_type"], "APPLICATION_ACTIVE")
            self.assertEqual(act["application_name"], "Microsoft Word")
            self.assertEqual(act["category"], "PRODUCTIVITY")
            self.assertEqual(act["message"], "Foreground application: Microsoft Word")

    def test_02_chrome_foreground_detection(self):
        """Chrome foreground -> get_current_foreground_activity (BROWSER)."""
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="chrome.exe"):
            act = self.collector.get_current_foreground_activity()
            self.assertIsNotNone(act)
            self.assertEqual(act["event_type"], "APPLICATION_ACTIVE")
            self.assertEqual(act["application_name"], "Google Chrome")
            self.assertEqual(act["category"], "BROWSER")

    def test_03_powerpoint_foreground_detection(self):
        """PowerPoint foreground -> get_current_foreground_activity (PRODUCTIVITY)."""
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="powerpnt.exe"):
            act = self.collector.get_current_foreground_activity()
            self.assertIsNotNone(act)
            self.assertEqual(act["event_type"], "APPLICATION_ACTIVE")
            self.assertEqual(act["application_name"], "Microsoft PowerPoint")
            self.assertEqual(act["category"], "PRODUCTIVITY")

    def test_04_steam_and_game_foreground_detection(self):
        """Steam & games foreground -> GAME/ENTERTAINMENT."""
        # Steam launcher
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="steam.exe"):
            act = self.collector.get_current_foreground_activity()
            self.assertIsNotNone(act)
            self.assertEqual(act["application_name"], "Steam")
            self.assertEqual(act["category"], "GAME/ENTERTAINMENT")

        # Game executable
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="cs2.exe"):
            act = self.collector.get_current_foreground_activity()
            self.assertIsNotNone(act)
            self.assertEqual(act["application_name"], "Counter-Strike 2")
            self.assertEqual(act["category"], "GAME/ENTERTAINMENT")

    def test_05_collect_emits_zero_active_or_unknown_spam(self):
        """Standard lifecycle collect() MUST NEVER emit APPLICATION_ACTIVE or UNKNOWN_APPLICATION spam."""
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="excel.exe"):
            events = self.collector.collect()
            active_events = [e for e in events if e.get("event_type") == "APPLICATION_ACTIVE"]
            unknown_events = [e for e in events if e.get("category") == "UNKNOWN_APPLICATION"]
            self.assertEqual(len(active_events), 0)
            self.assertEqual(len(unknown_events), 0)

    def test_06_lifecycle_tracking_preserves_clean_events(self):
        """Opening code.exe emits clean APPLICATION_STARTED without window polling spam."""
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 501, "name": "code.exe"}
        with patch("psutil.process_iter", return_value=[mock_proc]):
            events = self.collector.collect()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "APPLICATION_STARTED")
            self.assertEqual(events[0]["application_name"], "Visual Studio Code")

    def test_07_background_process_lifecycle_distinction(self):
        """Background process running emits APPLICATION_STARTED only, zero ACTIVE events."""
        mock_bg_proc = MagicMock()
        mock_bg_proc.info = {"pid": 9999, "name": "steam.exe"}

        with patch("psutil.process_iter", return_value=[mock_bg_proc]), \
             patch("client.app.collectors.events._get_active_window_process_name", return_value="winword.exe"):
            events = self.collector.collect()

            # Process started event for steam
            started = [e for e in events if e["event_type"] == "APPLICATION_STARTED"]
            self.assertEqual(len(started), 1)
            self.assertEqual(started[0]["application_name"], "Steam")

            # ZERO active events in event stream
            active = [e for e in events if e["event_type"] == "APPLICATION_ACTIVE"]
            self.assertEqual(len(active), 0)

    def test_08_ignored_system_process(self):
        """Focused on taskbar/desktop/explorer -> None."""
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="explorer.exe"):
            act = self.collector.get_current_foreground_activity()
            self.assertIsNone(act)

    def test_09_unknown_foreground_application_handling(self):
        """Unknown foreground app -> None (no UNKNOWN_APPLICATION spam)."""
        with patch("client.app.collectors.events._get_active_window_process_name", return_value="customaccountingtool.exe"):
            act = self.collector.get_current_foreground_activity()
            self.assertIsNone(act)

    def test_10_privacy_boundary_strict_verification(self):
        """Verify no sensitive fields (keystrokes, URLs, clipboard, doc contents) exist."""
        forbidden_keys = {"keystrokes", "typed_text", "clipboard", "document_content", "url", "browser_history", "password", "window_title"}
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1234, "name": "winword.exe"}
        with patch("psutil.process_iter", return_value=[mock_proc]), \
             patch("client.app.collectors.events._get_active_window_process_name", return_value="winword.exe"):
            events = self.collector.collect()
            for evt in events:
                for fk in forbidden_keys:
                    self.assertNotIn(fk, evt)
                    if isinstance(evt.get("details"), dict):
                        self.assertNotIn(fk, evt["details"])

    def test_11_antigravity_lifecycle_detection(self):
        """Antigravity running as 'Antigravity IDE.exe' is recognized as Antigravity (DEVELOPMENT)."""
        self.assertIn("antigravity ide.exe", APPLICATION_TAXONOMY)
        self.assertNotIn("antigravity.exe", IGNORED_SYSTEM_PROCESSES)

        mock_proc = MagicMock()
        mock_proc.info = {"pid": 3084, "name": "Antigravity IDE.exe"}
        with patch("psutil.process_iter", return_value=[mock_proc]):
            events = self.collector.collect()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "APPLICATION_STARTED")
            self.assertEqual(events[0]["application_name"], "Antigravity")
            self.assertEqual(events[0]["category"], "DEVELOPMENT")
            self.assertEqual(events[0]["message"], "Antigravity opened")

        # Closing Antigravity
        with patch("psutil.process_iter", return_value=[]):
            events = self.collector.collect()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "APPLICATION_STOPPED")
            self.assertEqual(events[0]["application_name"], "Antigravity")
            self.assertEqual(events[0]["message"], "Antigravity closed")

    def test_12_chatgpt_lifecycle_detection(self):
        """ChatGPT running as 'ChatGPT Classic.exe' is recognized as ChatGPT (PRODUCTIVITY)."""
        self.assertIn("chatgpt classic.exe", APPLICATION_TAXONOMY)

        mock_proc = MagicMock()
        mock_proc.info = {"pid": 8960, "name": "ChatGPT Classic.exe"}
        with patch("psutil.process_iter", return_value=[mock_proc]):
            events = self.collector.collect()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "APPLICATION_STARTED")
            self.assertEqual(events[0]["application_name"], "ChatGPT")
            self.assertEqual(events[0]["category"], "PRODUCTIVITY")
            self.assertEqual(events[0]["message"], "ChatGPT opened")

        # Closing ChatGPT
        with patch("psutil.process_iter", return_value=[]):
            events = self.collector.collect()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "APPLICATION_STOPPED")
            self.assertEqual(events[0]["application_name"], "ChatGPT")
            self.assertEqual(events[0]["message"], "ChatGPT closed")

    def test_13_edge_subprocess_lifecycle_grouping(self):
        """
        Verify complete lifecycle state machine for Edge (0 -> 1 -> 5 -> 2 -> 0 -> 1):
        - 0 -> 1: exactly ONE APPLICATION_STARTED ('Microsoft Edge opened')
        - 1 -> 5: ZERO events (subprocesses grouped)
        - 5 -> 2: ZERO events
        - 2 -> 0: exactly ONE APPLICATION_STOPPED ('Microsoft Edge closed')
        - 0 -> 1: exactly ONE new APPLICATION_STARTED ('Microsoft Edge opened')
        """
        def make_proc(pid, name="msedge.exe"):
            p = MagicMock()
            p.info = {"pid": pid, "name": name}
            return p

        # 0 -> 1
        with patch("psutil.process_iter", return_value=[make_proc(101)]):
            e1 = self.collector.collect()
            self.assertEqual(len(e1), 1)
            self.assertEqual(e1[0]["event_type"], "APPLICATION_STARTED")
            self.assertEqual(e1[0]["message"], "Microsoft Edge opened")

        # 1 -> 5
        with patch("psutil.process_iter", return_value=[make_proc(pid) for pid in [101, 102, 103, 104, 105]]):
            e2 = self.collector.collect()
            self.assertEqual(len(e2), 0)

        # 5 -> 2
        with patch("psutil.process_iter", return_value=[make_proc(pid) for pid in [101, 102]]):
            e3 = self.collector.collect()
            self.assertEqual(len(e3), 0)

        # 2 -> 0
        with patch("psutil.process_iter", return_value=[]):
            e4 = self.collector.collect()
            self.assertEqual(len(e4), 1)
            self.assertEqual(e4[0]["event_type"], "APPLICATION_STOPPED")
            self.assertEqual(e4[0]["message"], "Microsoft Edge closed")

        # 0 -> 1 (Reopen)
        with patch("psutil.process_iter", return_value=[make_proc(201)]):
            e5 = self.collector.collect()
            self.assertEqual(len(e5), 1)
            self.assertEqual(e5[0]["event_type"], "APPLICATION_STARTED")
            self.assertEqual(e5[0]["message"], "Microsoft Edge opened")

    def test_14_youtube_represented_by_browser_process(self):
        """YouTube opened in Edge is represented by Microsoft Edge, not a nonexistent process."""
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 401, "name": "msedge.exe"}
        with patch("psutil.process_iter", return_value=[mock_proc]):
            events = self.collector.collect()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["application_name"], "Microsoft Edge")
            self.assertEqual(events[0]["category"], "BROWSER")

    def test_15_telemetry_interval_and_heartbeat_defaults(self):
        """Verify telemetry interval is 10s and heartbeat is 3s."""
        from client.app.config import config as win_cfg
        self.assertEqual(win_cfg.TELEMETRY_INTERVAL, 10)
        self.assertEqual(win_cfg.HEARTBEAT_INTERVAL, 3)


class TestPhase51MasterCurrentActivity(unittest.TestCase):
    """Test Master current active application tracking & REST API."""

    @classmethod
    def setUpClass(cls):
        init_database()
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        self.device_svc = DeviceService()
        self.auth_svc = AuthService()
        self.log_svc = LogService()

        conn = get_connection()
        conn.execute("DELETE FROM logs;")
        conn.execute("DELETE FROM device_auth;")
        conn.execute("DELETE FROM devices;")
        conn.commit()
        conn.close()

        # Register device
        self.device_svc.register({
            "device_id": "ACT-PC-01",
            "device_name": "Executive Laptop",
            "device_type": "WINDOWS_PC",
        })

    def test_11_current_active_application_service_and_api(self):
        """Verify get_device_current_activity and REST API endpoints."""
        # 1. Initially no activity recorded
        initial = self.log_svc.get_device_current_activity("ACT-PC-01")
        self.assertFalse(initial["has_activity"])

        # 2. Ingest APPLICATION_ACTIVE logs
        self.log_svc.ingest_logs("ACT-PC-01", [
            {
                "timestamp": "2026-08-25 10:00:00",
                "severity": "INFO",
                "category": "PRODUCTIVITY",
                "event_type": "APPLICATION_ACTIVE",
                "application_name": "Microsoft Word",
                "message": "Foreground application: Microsoft Word",
            },
            {
                "timestamp": "2026-08-25 10:30:00",
                "severity": "INFO",
                "category": "GAME/ENTERTAINMENT",
                "event_type": "APPLICATION_ACTIVE",
                "application_name": "Steam",
                "message": "Foreground application: Steam",
            },
        ])

        # 3. Query current activity (should return Steam)
        current = self.log_svc.get_device_current_activity("ACT-PC-01")
        self.assertTrue(current["has_activity"])
        self.assertEqual(current["foreground_application"], "Steam")
        self.assertEqual(current["category"], "GAME/ENTERTAINMENT")
        self.assertEqual(current["last_changed"], "2026-08-25 10:30:00")
        self.assertEqual(current["status_text"], "Foreground application: Steam (GAME/ENTERTAINMENT)")

        # 4. Query via REST API GET /api/logs/activity/ACT-PC-01
        resp = self.client.get("/api/logs/activity/ACT-PC-01")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["foreground_application"], "Steam")
        self.assertEqual(data["category"], "GAME/ENTERTAINMENT")

        # 5. Query all activities GET /api/logs/activity
        resp_all = self.client.get("/api/logs/activity")
        self.assertEqual(resp_all.status_code, 200)
        data_all = resp_all.get_json()
        self.assertEqual(data_all["count"], 1)
        self.assertEqual(data_all["activities"][0]["foreground_application"], "Steam")


if __name__ == "__main__":
    unittest.main()
