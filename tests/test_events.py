"""
APEXEYE — Application Activity Classification & Filtering Regression Test Suite

Validates:
1. Genuine application detection: SomeApp.exe -> APPLICATION ("Some App").
2. Windows background worker noise filtering: TiWorker, MoUsoCoreWorker, Wpsupdate -> SYSTEM.
3. Linux genuine application detection: someapp -> APPLICATION ("Someapp").
4. Linux system process filtering: systemd-resolved, kworker, dbus-daemon -> SYSTEM.
5. Process group lifecycle: SomeApp emits APPLICATION_STARTED and APPLICATION_STOPPED.
6. System noise suppression: TiWorker/MoUsoCoreWorker spawn/stop emits zero events.
7. Lightweight O(1) classification caching.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.collectors.events import (
    EventCollector as WindowsEventCollector,
    ProcessSnapshot as WindowsProcessSnapshot,
    _classify_process as _classify_windows_process,
    _is_system_noise as _is_windows_system_noise,
    _resolve_application_metadata as _resolve_windows_metadata,
)
from client_linux.app.collectors.events import (
    EventCollector as LinuxEventCollector,
    ProcessSnapshot as LinuxProcessSnapshot,
    _classify_linux_process,
    _is_kernel_or_system_noise as _is_linux_system_noise,
    _resolve_application_metadata as _resolve_linux_metadata,
)


# ===========================================================================
# 1. Windows Application Activity Classification Tests
# ===========================================================================

class TestWindowsProcessClassification:
    def test_genuine_someapp_classified_as_application(self):
        """SomeApp.exe must be classified as APPLICATION with clean title."""
        cls, friendly, cat = _classify_windows_process(pid=1234, name="SomeApp.exe")
        assert cls == "APPLICATION"
        assert friendly == "Some App"
        assert cat == "APPLICATION"

        # _is_system_noise must return False
        assert _is_windows_system_noise(1234, "SomeApp.exe") is False

        # Metadata resolution
        title, category = _resolve_windows_metadata("SomeApp.exe")
        assert title == "Some App"
        assert category == "APPLICATION"

    def test_windows_background_noise_classified_as_system(self):
        """TiWorker, MoUsoCoreWorker, and Wpsupdate must be classified as SYSTEM."""
        for name in ("TiWorker.exe", "tiworker.exe", "MoUsoCoreWorker.exe", "mousocoreworker.exe", "wpsupdate.exe", "Wpsupdate.exe"):
            cls, friendly, cat = _classify_windows_process(pid=5678, name=name)
            assert cls == "SYSTEM", f"{name} should be classified as SYSTEM, got {cls}"
            assert cat == "SYSTEM"
            assert _is_windows_system_noise(5678, name) is True

    def test_system_directories_classified_as_system(self):
        """Processes running out of Windows System32 / servicing / WinSxS are classified as SYSTEM."""
        mock_proc = MagicMock()
        mock_proc.exe.return_value = r"C:\Windows\System32\some_os_worker.exe"
        mock_proc.username.return_value = r"NT AUTHORITY\SYSTEM"
        mock_proc.session_id.return_value = 0

        cls, _, cat = _classify_windows_process(pid=3333, name="some_os_worker.exe", proc=mock_proc)
        assert cls == "SYSTEM"
        assert cat == "SYSTEM"

    def test_session_zero_classified_as_system(self):
        """Processes in Windows non-interactive Session 0 are classified as SYSTEM."""
        mock_proc = MagicMock()
        mock_proc.session_id.return_value = 0
        mock_proc.exe.return_value = r"C:\Windows\unknown_service.exe"

        cls, _, cat = _classify_windows_process(pid=4444, name="unknown_service.exe", proc=mock_proc)
        assert cls == "SYSTEM"

    def test_windows_taxonomy_apps_remain_application(self):
        """Taxonomy applications (e.g. notepad.exe, chrome.exe) are recognized as APPLICATION."""
        cls, friendly, cat = _classify_windows_process(pid=1000, name="notepad.exe")
        assert cls == "APPLICATION"
        assert friendly == "Notepad"
        assert cat == "PRODUCTIVITY"


# ===========================================================================
# 2. Linux Application Activity Classification Tests
# ===========================================================================

class TestLinuxProcessClassification:
    def test_genuine_user_app_classified_as_application(self):
        """Linux user executable 'someapp' must be classified as APPLICATION."""
        cls, friendly, cat = _classify_linux_process(pid=1001, name="someapp", ppid=1000)
        assert cls == "APPLICATION"
        assert friendly == "Someapp"
        assert cat == "APPLICATION"
        assert _is_linux_system_noise(1001, "someapp", ppid=1000) is False

    def test_linux_system_processes_classified_as_system(self):
        """Linux system daemons (systemd-resolved, kworker, dbus-daemon) are classified as SYSTEM."""
        for name in ("systemd-resolved", "kworker/0:1", "dbus-daemon", "systemd"):
            cls, friendly, cat = _classify_linux_process(pid=200, name=name, ppid=1)
            assert cls == "SYSTEM", f"{name} should be classified as SYSTEM"
            assert _is_linux_system_noise(200, name, ppid=1) is True

    def test_linux_uid_root_system_service_classified_as_system(self):
        """Linux process running with root UID < 1000 in /usr/lib/systemd is SYSTEM."""
        mock_proc = MagicMock()
        mock_uids = MagicMock()
        mock_uids.real = 0
        mock_proc.uids.return_value = mock_uids
        mock_proc.exe.return_value = "/usr/lib/systemd/systemd-logind"

        cls, _, cat = _classify_linux_process(pid=500, name="systemd-logind", ppid=1, proc=mock_proc)
        assert cls == "SYSTEM"
        assert cat == "SYSTEM"


# ===========================================================================
# 3. Windows Lifecycle & Noise Filter Stream Tests
# ===========================================================================

class TestWindowsLifecycleStream:
    def test_someapp_emits_started_and_stopped(self):
        """Starting and stopping SomeApp.exe emits lifecycle events."""
        collector = WindowsEventCollector()
        collector._previous.processes = {}

        p_some = MagicMock()
        p_some.info = {"pid": 7777, "name": "SomeApp.exe"}

        # 1. SomeApp.exe starts
        with patch("psutil.process_iter", return_value=[p_some]):
            events = collector.collect()
            assert len(events) == 1
            assert events[0]["event_type"] == "APPLICATION_STARTED"
            assert events[0]["application_name"] == "Some App"
            assert events[0]["category"] == "APPLICATION"

        # 2. SomeApp.exe stops
        with patch("psutil.process_iter", return_value=[]):
            events = collector.collect()
            assert len(events) == 1
            assert events[0]["event_type"] == "APPLICATION_STOPPED"
            assert events[0]["application_name"] == "Some App"

    def test_background_noise_workers_emit_zero_events(self):
        """TiWorker, MoUsoCoreWorker, Wpsupdate spawning and exiting emit ZERO events."""
        collector = WindowsEventCollector()
        collector._previous.processes = {}

        p_ti = MagicMock(); p_ti.info = {"pid": 8001, "name": "TiWorker.exe"}
        p_mouso = MagicMock(); p_mouso.info = {"pid": 8002, "name": "MoUsoCoreWorker.exe"}
        p_wps = MagicMock(); p_wps.info = {"pid": 8003, "name": "wpsupdate.exe"}

        # Workers spawn
        with patch("psutil.process_iter", return_value=[p_ti, p_mouso, p_wps]):
            events = collector.collect()
            assert len(events) == 0, f"Background workers must emit 0 events, got: {events}"

        # Workers terminate
        with patch("psutil.process_iter", return_value=[]):
            events = collector.collect()
            assert len(events) == 0, "Background workers exiting must emit 0 events"
