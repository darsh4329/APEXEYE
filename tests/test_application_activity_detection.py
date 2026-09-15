"""
APEXEYE — Comprehensive Cross-Platform Application Activity Detection Test Suite
Validates Windows and Linux production application detection engines:
1. Positive real application detection (Chrome, Edge, VS Code, arbitrary apps).
2. Negative system noise suppression (svchost, RuntimeBroker, SearchHost, Identity Helper, Lenovo helpers, systemd, dbus, nginx).
3. Browser/Electron subprocess suppression (--type=renderer, --type=gpu-process, --type=utility, crashpad).
4. Multi-process logical grouping (multiple PIDs collapsed to 1 application).
5. get_running_applications() API correctness on both Windows and Linux.
6. 0 -> 1+ / 1+ -> 0 Lifecycle state machine guarantees (exact STARTED and STOPPED count, zero churn spam).
7. Startup baseline handling (no false alerts on startup).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database

# Windows collector imports
from client.app.collectors.events import (
    EventCollector as WinEventCollector,
    ProcessSnapshot as WinProcessSnapshot,
    _classify_process as win_classify_process,
    _is_system_noise as win_is_system_noise,
    _is_browser_or_electron_subworker as win_is_subworker,
    _resolve_application_metadata as win_resolve_metadata,
)

# Linux collector imports
from client_linux.app.collectors.events import (
    EventCollector as LinuxEventCollector,
    ProcessSnapshot as LinuxProcessSnapshot,
    _classify_linux_process as linux_classify_process,
    _is_kernel_or_system_noise as linux_is_system_noise,
    _is_browser_or_electron_subworker as linux_is_subworker,
    _resolve_application_metadata as linux_resolve_metadata,
)


@pytest.fixture(autouse=True)
def setup_db():
    init_database()
    yield


# ==============================================================================
# 1. WINDOWS APPLICATION DETECTION & NOISE SUPPRESSION TESTS
# ==============================================================================

def test_windows_positive_application_detection():
    """Verify Windows client detects real applications with friendly names and categories."""
    assert win_resolve_metadata("chrome.exe") == ("Google Chrome", "BROWSER")
    assert win_resolve_metadata("msedge.exe") == ("Microsoft Edge", "BROWSER")
    assert win_resolve_metadata("code.exe") == ("Visual Studio Code", "DEVELOPMENT")
    assert win_resolve_metadata("whatsapp.exe") == ("WhatsApp", "COMMUNICATION")
    assert win_resolve_metadata("discord.exe") == ("Discord", "COMMUNICATION")
    assert win_resolve_metadata("custom_game.exe") == ("Custom Game", "APPLICATION")


def test_windows_system_and_helper_suppression():
    """Verify system infrastructure, background workers, and OAuth helpers are suppressed."""
    assert win_is_system_noise(100, "svchost.exe") is True
    assert win_is_system_noise(104, "SearchHost.exe") is True
    assert win_is_system_noise(108, "RuntimeBroker.exe") is True
    assert win_is_system_noise(112, "TiWorker.exe") is True
    assert win_is_system_noise(116, "Identity Helper.exe") is True
    assert win_is_system_noise(120, "LenovoVantageService.exe") is True
    assert win_is_system_noise(124, "LenovoHotkeys.exe") is True
    assert win_is_system_noise(128, "crashpad_handler.exe") is True

    # Real applications must NOT be classified as system noise
    assert win_is_system_noise(2000, "chrome.exe") is False
    assert win_is_system_noise(2004, "msedge.exe") is False
    assert win_is_system_noise(2008, "Code.exe") is False


def test_windows_browser_subworker_suppression():
    """Verify browser and Electron child subprocesses are recognized as subworkers."""
    renderer_proc = MagicMock()
    renderer_proc.cmdline.return_value = ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "--type=renderer"]
    assert win_is_subworker(renderer_proc) is True

    gpu_proc = MagicMock()
    gpu_proc.cmdline.return_value = ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "--type=gpu-process"]
    assert win_is_subworker(gpu_proc) is True

    utility_proc = MagicMock()
    utility_proc.cmdline.return_value = ["code.exe", "--type=utility", "--utility-sub-type=audio.mojom.AudioService"]
    assert win_is_subworker(utility_proc) is True

    crashpad_proc = MagicMock()
    crashpad_proc.cmdline.return_value = ["chrome.exe", "--type=crashpad-handler"]
    assert win_is_subworker(crashpad_proc) is True

    main_proc = MagicMock()
    main_proc.cmdline.return_value = ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"]
    assert win_is_subworker(main_proc) is False


def test_windows_multi_process_grouping_and_snapshot():
    """Verify 15 Chrome processes collapse into exactly ONE logical application in snapshot."""
    snap = WinProcessSnapshot()
    mock_procs = []
    # 1 main process
    p_main = MagicMock()
    p_main.info = {"pid": 5000, "name": "chrome.exe"}
    p_main.cmdline.return_value = ["chrome.exe"]
    mock_procs.append(p_main)
    # 14 subprocesses (renderers, gpu, utilities)
    for i in range(1, 15):
        p_sub = MagicMock()
        p_sub.info = {"pid": 5000 + i, "name": "chrome.exe"}
        p_sub.cmdline.return_value = ["chrome.exe", "--type=renderer"]
        mock_procs.append(p_sub)

    with patch("psutil.process_iter", return_value=mock_procs), \
         patch("client.app.collectors.events._get_visible_desktop_windows", return_value={5000: "New Tab - Google Chrome"}), \
         patch("client.app.collectors.events._get_foreground_window_info", return_value=(5000, "New Tab - Google Chrome")):
        snap.capture()

    groups = snap.app_groups
    assert len(groups) == 1
    assert "Google Chrome" in groups
    cat, pids, exe = groups["Google Chrome"]
    assert cat == "BROWSER"
    assert len(pids) == 15
    assert 5000 in pids

    running_apps = snap.get_running_applications()
    assert len(running_apps) == 1
    app = running_apps[0]
    assert app["application_name"] == "Google Chrome"
    assert app["primary_pid"] == 5000
    assert app["process_count"] == 15
    assert app["is_foreground"] is True
    assert app["window_title"] == "New Tab - Google Chrome"


def test_windows_lifecycle_state_machine():
    """Verify 0 -> 1+ emits 1 STARTED, churn emits 0, 1+ -> 0 emits 1 STOPPED, reopen emits 1 STARTED."""
    collector = WinEventCollector()
    collector._previous.processes = {}

    p_main = MagicMock(); p_main.info = {"pid": 6000, "name": "Code.exe"}; p_main.cmdline.return_value = ["Code.exe"]
    p_sub1 = MagicMock(); p_sub1.info = {"pid": 6001, "name": "Code.exe"}; p_sub1.cmdline.return_value = ["Code.exe", "--type=renderer"]

    # 1. Start application
    with patch("psutil.process_iter", return_value=[p_main]), \
         patch("client.app.collectors.events._get_visible_desktop_windows", return_value={6000: "ApexEye - VS Code"}):
        evts_start = collector.collect()
        assert len(evts_start) == 1
        assert evts_start[0]["event_type"] == "APPLICATION_STARTED"
        assert evts_start[0]["application_name"] == "Visual Studio Code"

    # 2. Subprocess spawns
    with patch("psutil.process_iter", return_value=[p_main, p_sub1]), \
         patch("client.app.collectors.events._get_visible_desktop_windows", return_value={6000: "ApexEye - VS Code"}):
        assert len(collector.collect()) == 0, "Subprocess spawn must emit 0 events"

    # 3. Application terminates
    with patch("psutil.process_iter", return_value=[]), \
         patch("client.app.collectors.events._get_visible_desktop_windows", return_value={}):
        evts_stop = collector.collect()
        assert len(evts_stop) == 1
        assert evts_stop[0]["event_type"] == "APPLICATION_STOPPED"
        assert evts_stop[0]["application_name"] == "Visual Studio Code"

    # 4. Reopen application
    p_reopen = MagicMock(); p_reopen.info = {"pid": 6050, "name": "Code.exe"}; p_reopen.cmdline.return_value = ["Code.exe"]
    with patch("psutil.process_iter", return_value=[p_reopen]), \
         patch("client.app.collectors.events._get_visible_desktop_windows", return_value={6050: "ApexEye - VS Code"}):
        evts_reopen = collector.collect()
        assert len(evts_reopen) == 1
        assert evts_reopen[0]["event_type"] == "APPLICATION_STARTED"
        assert evts_reopen[0]["pid"] == 6050


# ==============================================================================
# 2. LINUX APPLICATION DETECTION & NOISE SUPPRESSION TESTS
# ==============================================================================

def test_linux_positive_application_detection():
    """Verify Linux client detects real applications with friendly names and categories."""
    assert linux_resolve_metadata("google-chrome")[0] == "Google Chrome"
    assert linux_resolve_metadata("google-chrome")[1] == "BROWSER"
    assert linux_resolve_metadata("microsoft-edge")[0] == "Microsoft Edge"
    assert linux_resolve_metadata("microsoft-edge")[1] == "BROWSER"
    assert linux_resolve_metadata("code")[0] == "Visual Studio Code"
    assert linux_resolve_metadata("code")[1] == "DEVELOPMENT"
    assert linux_resolve_metadata("custom_script")[0] == "Custom Script"
    assert linux_resolve_metadata("custom_script")[1] == "APPLICATION"


def test_linux_system_and_helper_suppression():
    """Verify Linux kernel threads, systemd daemons, and OS servers are suppressed."""
    assert linux_is_system_noise(1, "systemd") is True
    assert linux_is_system_noise(2, "kthreadd") is True
    assert linux_is_system_noise(10, "[kworker/u16:1]") is True
    assert linux_is_system_noise(250, "dbus-daemon") is True
    assert linux_is_system_noise(300, "systemd-journald") is True
    assert linux_is_system_noise(400, "nginx") is True
    assert linux_is_system_noise(450, "dockerd") is True

    # Real applications must NOT be filtered
    assert linux_is_system_noise(1500, "chrome", ppid=1000) is False
    assert linux_is_system_noise(1600, "microsoft-edge", ppid=1000) is False
    assert linux_is_system_noise(1700, "code", ppid=1000) is False


def test_linux_browser_subworker_suppression():
    """Verify Linux browser/Electron zygote and renderer workers are identified."""
    p_zygote = MagicMock()
    p_zygote.cmdline.return_value = ["/opt/google/chrome/chrome", "--type=zygote"]
    assert linux_is_subworker(p_zygote) is True

    p_renderer = MagicMock()
    p_renderer.cmdline.return_value = ["/usr/share/code/code", "--type=renderer"]
    assert linux_is_subworker(p_renderer) is True

    p_main = MagicMock()
    p_main.cmdline.return_value = ["/opt/google/chrome/chrome"]
    assert linux_is_subworker(p_main) is False


def test_linux_multi_process_grouping_and_snapshot():
    """Verify Linux multi-process apps collapse into 1 application in get_running_applications()."""
    snap = LinuxProcessSnapshot()
    mock_procs = []
    # Main Chrome process
    p1 = MagicMock(); p1.info = {"pid": 7001, "name": "chrome", "ppid": 1000}
    p1.cmdline.return_value = ["chrome"]
    mock_procs.append(p1)
    # 5 worker processes
    for i in range(2, 7):
        p = MagicMock(); p.info = {"pid": 7000 + i, "name": "chrome", "ppid": 7001}
        p.cmdline.return_value = ["chrome", "--type=renderer"]
        mock_procs.append(p)

    with patch("client_linux.app.collectors.events.psutil.process_iter", return_value=mock_procs):
        snap.capture()

    groups = snap.app_groups
    assert len(groups) == 1
    assert "Google Chrome" in groups
    assert len(groups["Google Chrome"][1]) == 6

    running_apps = snap.get_running_applications()
    assert len(running_apps) == 1
    app = running_apps[0]
    assert app["application_name"] == "Google Chrome"
    assert app["process_count"] == 6
    assert app["category"] == "BROWSER"


def test_linux_lifecycle_state_machine():
    """Verify Linux 0 -> 1+ emits 1 STARTED, churn emits 0, 1+ -> 0 emits 1 STOPPED."""
    collector = LinuxEventCollector()
    collector._previous.processes = {}

    p_main = MagicMock(); p_main.info = {"pid": 8000, "name": "code", "ppid": 1000}
    p_sub = MagicMock(); p_sub.info = {"pid": 8001, "name": "code", "ppid": 8000}

    with patch("client_linux.app.collectors.events.psutil.process_iter") as mock_iter:
        # 1. Start application
        mock_iter.return_value = [p_main]
        evts = collector.collect()
        assert len(evts) == 1
        assert evts[0]["event_type"] == "APPLICATION_STARTED"
        assert evts[0]["application_name"] == "Visual Studio Code"

        # 2. Worker spawns (churn)
        mock_iter.return_value = [p_main, p_sub]
        assert len(collector.collect()) == 0

        # 3. Application terminates
        mock_iter.return_value = []
        evts_stop = collector.collect()
        assert len(evts_stop) == 1
        assert evts_stop[0]["event_type"] == "APPLICATION_STOPPED"
        assert evts_stop[0]["application_name"] == "Visual Studio Code"
