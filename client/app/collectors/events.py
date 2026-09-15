"""
APEXEYE CLIENT — Application & Process Activity Monitor (Direct Running Application Detector)

Monitors real user-facing application lifecycle events (APPLICATION_STARTED, APPLICATION_STOPPED)
based directly on running user application executables with multi-process grouping,
conservative background service filtering, and zero GUI/window heuristics.

Guarantees:
  - Detects real user applications directly from running executables.
  - Multi-process grouping: Chrome, Edge, VS Code, Antigravity, ChatGPT, etc. running multiple
    PIDs emit exactly ONE started event on open and ONE stopped event on close.
  - Subprocess churn (tabs opening/closing, renderers spawning/exiting) emits ZERO duplicate events.
  - Discards OS system infrastructure and background services (svchost, dwm, RuntimeBroker,
    SearchHost, Windows Defender services, Lenovo background services, etc.).
  - Does NOT depend on visible windows, window titles, foreground window, WinSta0, or desktop enumeration.
  - Strictly preserves user privacy: NEVER collects keystrokes, passwords, or document contents.
"""

import os
import re
import sys
from datetime import datetime, timezone
from typing import Optional

import psutil

from client.app.utils.logger import get_logger

logger = get_logger("apexeye.client.collectors.events")

# Configurable application taxonomy: process_exe_lower -> (Friendly Name, Category)
APPLICATION_TAXONOMY = {
    # Productivity & Office
    "winword.exe": ("Microsoft Word", "PRODUCTIVITY"),
    "excel.exe": ("Microsoft Excel", "PRODUCTIVITY"),
    "powerpnt.exe": ("Microsoft PowerPoint", "PRODUCTIVITY"),
    "outlook.exe": ("Microsoft Outlook", "PRODUCTIVITY"),
    "onenote.exe": ("Microsoft OneNote", "PRODUCTIVITY"),
    "notepad.exe": ("Notepad", "PRODUCTIVITY"),
    "notepad++.exe": ("Notepad++", "PRODUCTIVITY"),
    # Browsers
    "chrome.exe": ("Google Chrome", "BROWSER"),
    "msedge.exe": ("Microsoft Edge", "BROWSER"),
    "firefox.exe": ("Mozilla Firefox", "BROWSER"),
    "brave.exe": ("Brave Browser", "BROWSER"),
    "opera.exe": ("Opera Browser", "BROWSER"),
    "vivaldi.exe": ("Vivaldi Browser", "BROWSER"),
    # Communication
    "teams.exe": ("Microsoft Teams", "COMMUNICATION"),
    "ms-teams.exe": ("Microsoft Teams", "COMMUNICATION"),
    "slack.exe": ("Slack", "COMMUNICATION"),
    "zoom.exe": ("Zoom", "COMMUNICATION"),
    "discord.exe": ("Discord", "COMMUNICATION"),
    "skype.exe": ("Skype", "COMMUNICATION"),
    "whatsapp.exe": ("WhatsApp", "COMMUNICATION"),
    "whatsapp.root.exe": ("WhatsApp", "COMMUNICATION"),
    "whatsapproot.exe": ("WhatsApp", "COMMUNICATION"),
    "telegram.exe": ("Telegram", "COMMUNICATION"),
    # Development
    "code.exe": ("Visual Studio Code", "DEVELOPMENT"),
    "devenv.exe": ("Visual Studio", "DEVELOPMENT"),
    "pycharm64.exe": ("PyCharm", "DEVELOPMENT"),
    "pycharm.exe": ("PyCharm", "DEVELOPMENT"),
    "idea64.exe": ("IntelliJ IDEA", "DEVELOPMENT"),
    "idea.exe": ("IntelliJ IDEA", "DEVELOPMENT"),
    "windowsterminal.exe": ("Windows Terminal", "DEVELOPMENT"),
    "wt.exe": ("Windows Terminal", "DEVELOPMENT"),
    "openconsole.exe": ("Windows Terminal", "DEVELOPMENT"),
    "terminal.exe": ("Windows Terminal", "DEVELOPMENT"),
    "cmd.exe": ("Command Prompt", "DEVELOPMENT"),
    "powershell.exe": ("PowerShell", "DEVELOPMENT"),
    "pwsh.exe": ("PowerShell", "DEVELOPMENT"),
    "git-bash.exe": ("Git Bash", "DEVELOPMENT"),
    # Media
    "spotify.exe": ("Spotify", "MEDIA"),
    "vlc.exe": ("VLC Media Player", "MEDIA"),
    # AI & Modern Tools
    "chatgpt classic.exe": ("ChatGPT", "PRODUCTIVITY"),
    "chatgpt.exe": ("ChatGPT", "PRODUCTIVITY"),
    "chatgpt desktop.exe": ("ChatGPT", "PRODUCTIVITY"),
    "chatgptclassic.exe": ("ChatGPT", "PRODUCTIVITY"),
    "antigravity ide.exe": ("Antigravity", "DEVELOPMENT"),
    "antigravity.exe": ("Antigravity", "DEVELOPMENT"),
    "antigravity-ide.exe": ("Antigravity", "DEVELOPMENT"),
    "antigravityide.exe": ("Antigravity", "DEVELOPMENT"),
    # Adobe & Design
    "photoshop.exe": ("Adobe Photoshop", "PRODUCTIVITY"),
    "acrobat.exe": ("Adobe Acrobat", "PRODUCTIVITY"),
    "acrord32.exe": ("Adobe Reader", "PRODUCTIVITY"),
    # Games & Entertainment Launchers & Platforms
    "steam.exe": ("Steam", "GAME/ENTERTAINMENT"),
    "epicgameslauncher.exe": ("Epic Games Launcher", "GAME/ENTERTAINMENT"),
    "riotclientservices.exe": ("Riot Client", "GAME/ENTERTAINMENT"),
    "battle.net.exe": ("Battle.net", "GAME/ENTERTAINMENT"),
    "upc.exe": ("Ubisoft Connect", "GAME/ENTERTAINMENT"),
    "ubisoftconnect.exe": ("Ubisoft Connect", "GAME/ENTERTAINMENT"),
    "eadesktop.exe": ("EA app", "GAME/ENTERTAINMENT"),
    "origin.exe": ("Origin", "GAME/ENTERTAINMENT"),
    "gamebar.exe": ("Xbox Game Bar", "GAME/ENTERTAINMENT"),
    "xboxapp.exe": ("Xbox App", "GAME/ENTERTAINMENT"),
    "xboxpcapp.exe": ("Xbox App", "GAME/ENTERTAINMENT"),
    # Games & Entertainment Confident Executables
    "minecraft.exe": ("Minecraft", "GAME/ENTERTAINMENT"),
    "minecraftlauncher.exe": ("Minecraft Launcher", "GAME/ENTERTAINMENT"),
    "robloxplayerbeta.exe": ("Roblox", "GAME/ENTERTAINMENT"),
    "robloxplayerlauncher.exe": ("Roblox Launcher", "GAME/ENTERTAINMENT"),
    "leagueclient.exe": ("League of Legends", "GAME/ENTERTAINMENT"),
    "leagueclientux.exe": ("League of Legends", "GAME/ENTERTAINMENT"),
    "valorant.exe": ("VALORANT", "GAME/ENTERTAINMENT"),
    "cs2.exe": ("Counter-Strike 2", "GAME/ENTERTAINMENT"),
    "csgo.exe": ("Counter-Strike: Global Offensive", "GAME/ENTERTAINMENT"),
    "dota2.exe": ("Dota 2", "GAME/ENTERTAINMENT"),
    "gta5.exe": ("Grand Theft Auto V", "GAME/ENTERTAINMENT"),
    "fortniteclient-win64-shipping.exe": ("Fortnite", "GAME/ENTERTAINMENT"),
    "genshinimpact.exe": ("Genshin Impact", "GAME/ENTERTAINMENT"),
}

# Standard OS and background services to completely ignore
IGNORED_SYSTEM_PROCESSES = {
    "svchost.exe", "dwm.exe", "explorer.exe", "runtimebroker.exe",
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "taskhostw.exe", "spoolsv.exe", "ctfmon.exe", "sihost.exe",
    "conhost.exe", "wudfhost.exe", "dashost.exe", "audiodg.exe",
    "mpcmdrun.exe", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "defendersessionhelper.exe",
    "lockapp.exe", "logonui.exe", "smartscreen.exe", "applicationframehost.exe",
    "shellhost.exe", "textinputhost.exe", "searchindexer.exe",
    "backgroundtaskhost.exe", "wmiapsrv.exe", "wmiprvse.exe",
    "identity helper.exe", "identity_helper.exe", "identityhelper.exe",
    "crashpad_handler.exe", "crashpad.exe",
    "lenovovantageservice.exe", "lenovohotkeys.exe", "lenovovantage.exe",
    "widgetservice.exe", "widgets.exe", "wslservice.exe",
    "onedrive.sync.service.exe", "onedrive.exe", "msedgewebview2.exe",
    "crossdeviceresume.exe", "appactions.exe", "srtasks.exe",
    "compattelrunner.exe", "vssvc.exe", "msiexec.exe", "pyrefly.exe",
    "language_server_windows_x64.exe", "filecoauth.exe",
    "ccleaner_service.exe", "wavesaudioservice.exe", "wavessvc64.exe",
    "rtkauduservice64.exe", "atieclxx.exe", "appvshnotify.exe",
}

# Windows system directory paths containing OS infrastructure binaries
_WINDOWS_SYSTEM_DIRS = (
    r"\windows\system32",
    r"\windows\syswow64",
    r"\windows\winsxs",
    r"\windows\servicing",
    r"\windows\systemapps",
    r"\windows\diagnostics",
    r"\windows\microsoft.net",
    r"\windows\softwaredistribution",
    r"\windows\uuso",
    r"\windows\wcos",
    r"\windows\driverstore",
    r"\programdata\microsoft\windows defender",
)

# Conservative pattern matching for background maintenance, service, daemon, worker, and updater processes
_SERVICE_WORKER_PATTERN = re.compile(
    r"^(tiworker|mousocoreworker|wpsupdate|compattelrunner|trustedinstaller|sedlauncher|"
    r"waasmedic.*|usoclient|devicecensus|dismhost|vssvc|werfault|wermgr|"
    r"lenovo.*|.*vantage.*|.*hotkey.*|.*defender.*|"
    r".*service.*|.*svc.*|.*daemon.*|"
    r".*worker|.*updater|.*telemetry.*|.*crashreporter.*|.*crashpad.*|identity.*helper.*|.*notify.*|.*clicktorun.*)$",
    re.IGNORECASE,
)

# Process classification cache for performance
# Process classification cache for performance (strictly bounded to prevent memory growth)
_CACHE_MAX_ENTRIES = 512
_CLASSIFICATION_CACHE: dict[str, tuple[str, str, str]] = {}
_PE_METADATA_CACHE: dict[str, Optional[str]] = {}


def _bounded_cache_set(cache: dict, key: str, val: object, max_size: int = _CACHE_MAX_ENTRIES) -> None:
    """Store in cache, safely evicting the oldest key if limit reached."""
    if len(cache) >= max_size and key not in cache:
        try:
            oldest_key = next(iter(cache))
            del cache[oldest_key]
        except Exception:
            cache.clear()
    cache[key] = val


def _get_pe_version_info(exe_path: str) -> Optional[str]:
    """
    Extract application friendly name from Windows PE VersionInfo resources.
    Inspects FileDescription and ProductName across standard translations.
    """
    if not exe_path or sys.platform != "win32":
        return None
    clean_path = str(exe_path).strip()
    if clean_path in _PE_METADATA_CACHE:
        return _PE_METADATA_CACHE[clean_path]
    try:
        import ctypes
        if not os.path.isfile(clean_path):
            _bounded_cache_set(_PE_METADATA_CACHE, clean_path, None)
            return None
        size = ctypes.windll.version.GetFileVersionInfoSizeW(clean_path, None)
        if not size:
            _bounded_cache_set(_PE_METADATA_CACHE, clean_path, None)
            return None
        res = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(clean_path, 0, size, res):
            _bounded_cache_set(_PE_METADATA_CACHE, clean_path, None)
            return None

        trans_ptr = ctypes.c_void_p()
        trans_len = ctypes.c_uint()
        translations = []
        if ctypes.windll.version.VerQueryValueW(
            res, '\\VarFileInfo\\Translation', ctypes.byref(trans_ptr), ctypes.byref(trans_len)
        ) and trans_len.value >= 4:
            count = trans_len.value // 4
            trans_arr = (ctypes.c_ushort * (count * 2)).from_address(trans_ptr.value)
            for i in range(count):
                translations.append(f'{trans_arr[i*2]:04x}{trans_arr[i*2+1]:04x}')
        translations.extend(['040904b0', '040904e4', '000004b0', '04090000'])

        for field in ['FileDescription', 'ProductName']:
            for trans in translations:
                sub_block = f'\\StringFileInfo\\{trans}\\{field}'
                ptr = ctypes.c_void_p()
                length = ctypes.c_uint()
                if ctypes.windll.version.VerQueryValueW(
                    res, sub_block, ctypes.byref(ptr), ctypes.byref(length)
                ) and length.value > 0:
                    val = ctypes.wstring_at(ptr.value, length.value).rstrip('\x00').strip()
                    if val and not val.lower().startswith("microsoft® windows"):
                        _bounded_cache_set(_PE_METADATA_CACHE, clean_path, val)
                        return val
    except Exception:
        pass
    _bounded_cache_set(_PE_METADATA_CACHE, clean_path, None)
    return None


def _is_browser_or_electron_subworker(proc: object) -> bool:
    """
    Detect browser or electron helper subprocesses:
    renderers, GPU processes, utility workers, crashpad handlers, etc.
    """
    try:
        cmd = proc.cmdline() if hasattr(proc, "cmdline") and callable(proc.cmdline) else []
        if isinstance(cmd, list):
            cmd_str = " ".join(str(arg).lower() for arg in cmd)
            subworker_flags = (
                "--type=renderer",
                "--type=gpu-process",
                "--type=utility",
                "--type=crashpad-handler",
                "--type=service-worker",
                "--type=watcher",
            )
            if any(flag in cmd_str for flag in subworker_flags):
                return True
    except Exception:
        pass
    return False


_SERVICES_EXE_PIDS_CACHE: set[int] = set()
_SERVICES_EXE_CACHE_TIME: float = 0.0
_SERVICES_CACHE_TTL: float = 60.0


def _get_services_exe_pids() -> set[int]:
    """
    Cache/discover the PID of Windows services.exe (Service Control Manager).
    Revalidates cached PIDs with a 60s TTL and pid_exists check to avoid repeated O(N) process iterations.
    """
    global _SERVICES_EXE_PIDS_CACHE, _SERVICES_EXE_CACHE_TIME
    import time
    now = time.time()
    if _SERVICES_EXE_PIDS_CACHE and (now - _SERVICES_EXE_CACHE_TIME) < _SERVICES_CACHE_TTL:
        if all(psutil.pid_exists(p) for p in _SERVICES_EXE_PIDS_CACHE):
            return _SERVICES_EXE_PIDS_CACHE

    pids = set()
    try:
        for p in psutil.process_iter(["pid", "name"]):
            try:
                name = p.info.get("name") if hasattr(p, "info") and isinstance(p.info, dict) else (p.name() if callable(p.name) else p.name)
                if name and name.lower() == "services.exe":
                    pid = p.info.get("pid") if hasattr(p, "info") and isinstance(p.info, dict) else (p.pid() if callable(p.pid) else p.pid)
                    if isinstance(pid, int):
                        pids.add(pid)
            except Exception:
                continue
    except Exception:
        pass

    if pids:
        _SERVICES_EXE_PIDS_CACHE = pids
        _SERVICES_EXE_CACHE_TIME = now
    return pids or _SERVICES_EXE_PIDS_CACHE



def _is_user_application_process(proc: object) -> bool:
    """
    Direct inspection to determine if a running process is a legitimate user application
    or a subprocess of a user application, excluding OS/system and background services.

    Checks:
      1. PID validity (ignore system/idle PIDs <= 4).
      2. Ignored system process list.
      3. Service Control Manager parentage (PPID == services.exe).
      4. Session ID (Session 0 is reserved for Windows background services).
      5. Process ownership / account (exclude NT AUTHORITY, SYSTEM, LOCAL/NETWORK SERVICE).
      6. Executable location (exclude Windows system directories unless in APPLICATION_TAXONOMY).
      7. Background service and daemon naming patterns.
    """
    try:
        pid = None
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "pid" in proc.info:
            pid = proc.info.get("pid")
        elif hasattr(proc, "pid") and not callable(proc.pid):
            pid = proc.pid
        elif hasattr(proc, "pid") and callable(proc.pid):
            try:
                pid = proc.pid()
            except Exception:
                pid = None

        if isinstance(pid, int) and pid <= 4:
            return False

        # Safe process name check
        raw_name = ""
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "name" in proc.info:
            raw_name = proc.info.get("name") or ""
        elif hasattr(proc, "name") and callable(proc.name):
            try:
                ret = proc.name()
                if isinstance(ret, str):
                    raw_name = ret
            except Exception:
                raw_name = ""
        elif hasattr(proc, "name") and isinstance(proc.name, str):
            raw_name = proc.name

        if not raw_name or not isinstance(raw_name, str):
            return False

        name_lower = raw_name.lower().strip()
        if name_lower.startswith("unknown_") or name_lower in IGNORED_SYSTEM_PROCESSES:
            return False

        clean_no_ext = name_lower[:-4] if name_lower.endswith(".exe") else name_lower
        if clean_no_ext in IGNORED_SYSTEM_PROCESSES:
            return False

        # Fast path: known user applications in taxonomy
        is_in_taxonomy = (name_lower in APPLICATION_TAXONOMY or clean_no_ext in APPLICATION_TAXONOMY)

        # Check PPID: services.exe parentage means it is a registered Windows background service
        ppid = None
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "ppid" in proc.info:
            ppid = proc.info.get("ppid")
        elif hasattr(proc, "ppid") and callable(proc.ppid):
            try:
                ppid = proc.ppid()
            except Exception:
                pass
        if isinstance(ppid, int) and ppid in _get_services_exe_pids() and not is_in_taxonomy:
            return False

        # Check session ID: Session 0 is reserved for background services/daemons
        if hasattr(proc, "session_id") and callable(proc.session_id):
            try:
                sess_id = proc.session_id()
                if isinstance(sess_id, int) and sess_id == 0 and not is_in_taxonomy:
                    return False
            except Exception:
                pass

        # Check account ownership: System/service accounts
        raw_uname = None
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "username" in proc.info:
            raw_uname = proc.info.get("username")
        elif hasattr(proc, "username") and callable(proc.username):
            try:
                raw_uname = proc.username()
            except psutil.AccessDenied:
                # System/elevated processes that deny user access are OS/service infrastructure
                if not is_in_taxonomy:
                    return False
            except Exception:
                pass

        if isinstance(raw_uname, str) and raw_uname:
            uname = raw_uname.lower()
            if any(s in uname for s in ("nt authority", "system", "local service", "network service")):
                return False

        # Check executable binary location
        exe_path = ""
        raw_exe = None
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "exe" in proc.info:
            raw_exe = proc.info.get("exe")
        elif hasattr(proc, "exe") and callable(proc.exe):
            try:
                raw_exe = proc.exe()
            except psutil.AccessDenied:
                if not is_in_taxonomy:
                    return False
            except Exception:
                pass

        if isinstance(raw_exe, str) and raw_exe:
            exe_path = raw_exe.lower()

        if isinstance(exe_path, str) and exe_path:
            for sys_dir in _WINDOWS_SYSTEM_DIRS:
                if sys_dir in exe_path:
                    # System directories are excluded unless explicitly declared in taxonomy (e.g. notepad.exe)
                    if not is_in_taxonomy:
                        return False

        # If it is in taxonomy, it's a verified user application
        if is_in_taxonomy:
            return True

        # Conservative third-party background/service pattern filter
        if _SERVICE_WORKER_PATTERN.search(clean_no_ext) or _SERVICE_WORKER_PATTERN.search(name_lower):
            return False

        return True

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False
    except Exception:
        return False


def _classify_process(pid: Optional[int], name: str, proc: Optional[object] = None) -> tuple[str, str, str]:
    """
    Classify a process into ('APPLICATION' | 'SYSTEM', friendly_name, category).
    Maintains compatibility with tests and callers.
    """
    if isinstance(pid, int) and pid <= 4:
        return ("SYSTEM", name, "SYSTEM")

    clean = str(name).lower().strip()
    clean_no_ext = clean[:-4] if clean.endswith(".exe") else clean

    if clean in IGNORED_SYSTEM_PROCESSES or clean_no_ext in IGNORED_SYSTEM_PROCESSES:
        return ("SYSTEM", clean_no_ext, "SYSTEM")

    # Fast path: Defined in Application Taxonomy -> APPLICATION
    if clean in APPLICATION_TAXONOMY:
        friendly, cat = APPLICATION_TAXONOMY[clean]
        return ("APPLICATION", friendly, cat)
    if clean_no_ext in APPLICATION_TAXONOMY:
        friendly, cat = APPLICATION_TAXONOMY[clean_no_ext]
        return ("APPLICATION", friendly, cat)

    # Check cache
    if clean in _CLASSIFICATION_CACHE:
        return _CLASSIFICATION_CACHE[clean]

    # Process inspection when proc is provided
    if proc is not None:
        if not _is_user_application_process(proc):
            res = ("SYSTEM", clean_no_ext, "SYSTEM")
            _bounded_cache_set(_CLASSIFICATION_CACHE, clean, res)
            return res

        # Try PE VersionInfo for dynamic applications
        exe_path = None
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "exe" in proc.info:
            exe_path = proc.info.get("exe")
        elif hasattr(proc, "exe") and callable(proc.exe):
            try:
                raw_exe = proc.exe()
                if isinstance(raw_exe, str) and raw_exe:
                    exe_path = raw_exe
            except Exception:
                pass
        if exe_path:
            pe_name = _get_pe_version_info(exe_path)
            if pe_name:
                res = ("APPLICATION", pe_name, "APPLICATION")
                _bounded_cache_set(_CLASSIFICATION_CACHE, clean, res)
                return res

    # Heuristic background service filter check
    if _SERVICE_WORKER_PATTERN.search(clean_no_ext) or _SERVICE_WORKER_PATTERN.search(clean):
        res = ("SYSTEM", clean_no_ext, "SYSTEM")
        _bounded_cache_set(_CLASSIFICATION_CACHE, clean, res)
        return res

    # Derive clean title from executable filename
    base = name[:-4] if str(name).lower().endswith(".exe") else str(name)
    s1 = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", base)
    words = re.split(r"[-_.\s]+", s1)
    title = " ".join(w.capitalize() for w in words if w)
    res = ("APPLICATION", title or clean_no_ext, "APPLICATION")
    _bounded_cache_set(_CLASSIFICATION_CACHE, clean, res)
    return res


def _resolve_application_metadata(exe_name: str, proc: Optional[object] = None) -> tuple[str, str]:
    """
    Map raw executable name to readable application name and category.
    Returns (friendly_name, category). If classified as SYSTEM, category is 'SYSTEM'.
    """
    _, friendly_name, category = _classify_process(None, exe_name, proc=proc)
    return friendly_name, category


def _is_system_noise(pid: Optional[int], name: str, proc: Optional[object] = None) -> bool:
    """Check if process is low-level Windows OS noise or background service."""
    classification, _, _ = _classify_process(pid, name, proc)
    return classification == "SYSTEM"


# Optional Win32 foreground inspection helper (non-blocking, never suppresses app detection)
def _get_foreground_window_info() -> tuple[Optional[int], Optional[str]]:
    """Determine PID and executable name owning focused window if available."""
    if sys.platform != "win32":
        return None, None
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None, None
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return None, None
        try:
            proc = psutil.Process(pid.value)
            return pid.value, proc.name().lower()
        except Exception:
            return pid.value, None
    except Exception:
        return None, None


def _get_visible_desktop_windows() -> dict[int, str]:
    """Optional backward compatibility stub for window enumeration."""
    return {}


class ProcessSnapshot:
    """
    Snapshot of running user applications grouped by logical application identity.
    Direct running executable detection without window/GUI dependencies.
    """

    def __init__(self):
        self._processes: dict[int, str] = {}  # pid -> exe_name_lower
        self._logical_apps: dict[str, dict] = {}  # app_name -> dict

    @property
    def processes(self) -> dict[int, str]:
        return self._processes

    @processes.setter
    def processes(self, value: dict[int, str]):
        self._processes = dict(value) if value else {}
        if not self._processes:
            self._logical_apps.clear()

    @property
    def app_groups(self) -> dict[str, tuple[str, list[int], str]]:
        """
        Group running processes by application name for backward compatibility.
        Returns: {app_name: (category, [pids], exe_name)}
        """
        groups: dict[str, tuple[str, list[int], str]] = {}
        if self._logical_apps:
            for app_name, app_info in self._logical_apps.items():
                active_pids = [p for p in app_info.get("pids", []) if p in self._processes]
                if not active_pids:
                    continue
                category = app_info.get("category", "APPLICATION")
                if category == "SYSTEM":
                    continue
                groups[app_name] = (
                    category,
                    active_pids,
                    app_info.get("executable", ""),
                )
            if groups:
                return groups

        # Fallback if _processes was populated manually (e.g. In unit tests)
        if self._processes:
            for pid, name_lower in self._processes.items():
                if _is_system_noise(pid, name_lower):
                    continue
                app_name, category = _resolve_application_metadata(name_lower)
                if category == "SYSTEM":
                    continue
                if app_name not in groups:
                    groups[app_name] = (category, [pid], name_lower)
                else:
                    groups[app_name][1].append(pid)

        return groups

    @app_groups.setter
    def app_groups(self, value):
        if not value:
            self._processes.clear()
            self._logical_apps.clear()

    def get_running_applications(self) -> list[dict]:
        """
        Return a clean snapshot of logical user applications currently running.
        Collapses multi-process applications and excludes system/background services.
        """
        running: list[dict] = []
        for app_name, (category, pids, exe_name) in sorted(self.app_groups.items()):
            primary_pid = pids[0] if pids else 0
            is_fg = False
            win_title = ""
            if app_name in self._logical_apps:
                primary_pid = self._logical_apps[app_name].get("primary_pid", primary_pid)
                is_fg = self._logical_apps[app_name].get("is_foreground", False)
                win_title = self._logical_apps[app_name].get("window_title", "")
            running.append({
                "application_name": app_name,
                "executable": exe_name,
                "category": category,
                "primary_pid": primary_pid,
                "process_count": len(pids),
                "pids": sorted(pids),
                "is_foreground": is_fg,
                "window_title": win_title,
            })
        return running

    def capture(self) -> None:
        """
        Enumerate running processes using psutil and group user applications.
        Directly driven by currently running user executables without window dependency.
        Window information is optionally attached if available.
        """
        self._processes = {}
        self._logical_apps = {}

        visible_windows = _get_visible_desktop_windows()
        fg_pid, _ = _get_foreground_window_info()

        for proc in psutil.process_iter(["pid", "name", "ppid", "username", "exe"]):
            try:
                info = proc.info if hasattr(proc, "info") and isinstance(proc.info, dict) else {}
                pid = info.get("pid")
                if not pid:
                    pid = getattr(proc, "pid", None)
                    if callable(pid):
                        try:
                            pid = pid()
                        except Exception:
                            pid = None

                name = info.get("name")
                if not name and hasattr(proc, "name"):
                    name = proc.name() if callable(proc.name) else proc.name

                if not pid or not name:
                    continue

                name_lower = str(name).lower().strip()

                # Filter out system and background service processes
                if not _is_user_application_process(proc):
                    continue

                app_name, category = _resolve_application_metadata(name_lower, proc=proc)
                if category == "SYSTEM":
                    continue

                self._processes[pid] = name_lower
                is_sub = _is_browser_or_electron_subworker(proc)
                has_window = pid in visible_windows
                is_fg = (pid == fg_pid)
                win_title = visible_windows.get(pid, "")

                if app_name not in self._logical_apps:
                    self._logical_apps[app_name] = {
                        "application_name": app_name,
                        "executable": name_lower,
                        "category": category,
                        "primary_pid": pid,
                        "pids": [pid],
                        "has_main_proc": not is_sub,
                        "is_foreground": is_fg,
                        "window_title": win_title,
                    }
                else:
                    self._logical_apps[app_name]["pids"].append(pid)
                    if has_window:
                        self._logical_apps[app_name]["window_title"] = win_title
                    if is_fg:
                        self._logical_apps[app_name]["is_foreground"] = True
                    # If this process is the main process and previous was a subworker, set as primary
                    if not is_sub and not self._logical_apps[app_name].get("has_main_proc", False):
                        self._logical_apps[app_name]["primary_pid"] = pid
                        self._logical_apps[app_name]["has_main_proc"] = True
                        if has_window:
                            self._logical_apps[app_name]["window_title"] = win_title

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue


class EventCollector:
    """
    Monitors categorized application lifecycle events (Started, Stopped)
    using direct running executable detection.

    Guarantees:
      - 0 processes -> 1+ processes: emits exactly ONE APPLICATION_STARTED
      - Subprocesses spawn: emits ZERO additional started events
      - Subprocesses exit: emits ZERO stopped events while application is running
      - Entire application group reaches 0: emits exactly ONE APPLICATION_STOPPED
      - Later re-open: emits exactly ONE new APPLICATION_STARTED event
      - Background services & system workers are completely filtered out
    """

    def __init__(self):
        self._previous = ProcessSnapshot()
        self._previous.capture()
        self._previous_applications: dict[str, tuple[str, list[int], str]] = dict(self._previous.app_groups)
        self._last_active_app: Optional[str] = None
        self._initialized = True
        logger.info(
            "EventCollector initialized. Baseline: %d running application group(s).",
            len(self._previous_applications),
        )

    def get_running_applications(self) -> list[dict]:
        """Return snapshot of logical applications currently running."""
        return self._previous.get_running_applications()

    def collect(self) -> list[dict]:
        """
        Compare current logical application snapshot with previous snapshot.
        Emits APPLICATION_STARTED for new applications and APPLICATION_STOPPED for terminated applications.
        """
        try:
            current = ProcessSnapshot()
            current.capture()

            events = []
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            current_groups = current.app_groups
            # Sync with _previous in case external code modified _previous.processes
            prev_groups = self._previous.app_groups

            # 1. Detect Started Applications (0 instances -> 1+ instances)
            for app_name, (category, pids, exe_name) in current_groups.items():
                if app_name not in prev_groups:
                    primary_pid = pids[0]
                    events.append({
                        "timestamp": now,
                        "event_type": "APPLICATION_STARTED",
                        "category": category,
                        "application_name": app_name,
                        "process_name": exe_name,
                        "pid": primary_pid,
                        "severity": "INFO",
                        "message": f"{app_name} opened",
                        "source": "process_monitor",
                        "details": {
                            "application_name": app_name,
                            "category": category,
                            "executable_name": exe_name,
                            "pid": primary_pid,
                            "pids": pids,
                        },
                    })
                    logger.info("Application started: %s (PID %d)", app_name, primary_pid)

            # 2. Detect Stopped Applications (1+ instances -> 0 instances)
            for app_name, (category, pids, exe_name) in prev_groups.items():
                if app_name not in current_groups:
                    primary_pid = pids[0] if pids else 0
                    events.append({
                        "timestamp": now,
                        "event_type": "APPLICATION_STOPPED",
                        "category": category,
                        "application_name": app_name,
                        "process_name": exe_name,
                        "pid": primary_pid,
                        "severity": "INFO",
                        "message": f"{app_name} closed",
                        "source": "process_monitor",
                        "details": {
                            "application_name": app_name,
                            "category": category,
                            "executable_name": exe_name,
                            "pid": primary_pid,
                            "pids": pids,
                        },
                    })
                    logger.info("Application stopped: %s (PID %d)", app_name, primary_pid)

            self._previous = current
            self._previous_applications = dict(current_groups)
            return events

        except Exception as exc:
            logger.error("Failed to collect application events: %s", exc)
            return []

    def get_current_foreground_activity(self) -> Optional[dict]:
        """Optional foreground window inspector. Never emits duplicate spam into event stream."""
        fg_pid, active_exe = _get_foreground_window_info()
        if not active_exe or active_exe in IGNORED_SYSTEM_PROCESSES:
            return None

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        app_name, category = _resolve_application_metadata(active_exe)
        if category == "SYSTEM":
            return None

        return {
            "timestamp": now,
            "event_type": "APPLICATION_ACTIVE",
            "category": category,
            "application_name": app_name,
            "process_name": active_exe,
            "executable_name": active_exe,
            "pid": fg_pid,
            "severity": "INFO",
            "message": f"Foreground application: {app_name}",
        }
