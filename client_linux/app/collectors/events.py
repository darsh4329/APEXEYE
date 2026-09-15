"""
APEXEYE LINUX CLIENT — Process & Application Lifecycle Monitor

Monitors real Linux process and application lifecycle events (Started, Stopped)
with reliable process-group state machine, human-readable naming, categorization,
and strict noise filtering.

Guarantees:
  - Detects real process lifecycle changes (APPLICATION_STARTED, APPLICATION_STOPPED).
  - Works for arbitrary applications (browsers, editors, terminals, tools, custom binaries).
  - Multi-process grouping: Chrome/Edge/VS Code running multiple PIDs emits exactly
    ONE started event on open and ONE stopped event when the final process terminates.
  - Zero duplicate spam across polling cycles.
  - Initial baseline established at startup (no false starts for already-running apps).
  - Kernel threads ([...], kworker, ksoftirqd, etc.) and OS internal daemons filtered.
  - Native fallback to /proc when psutil is not available.
  - Strictly preserves user privacy: NEVER collects keystrokes, URLs, or window contents.
"""

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None

from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.collectors.events")

# Configurable application taxonomy: process_name_lower -> (Friendly Name, Category)
LINUX_PROCESS_TAXONOMY = {
    # Web Browsers
    "chrome": ("Google Chrome", "BROWSER"),
    "google-chrome": ("Google Chrome", "BROWSER"),
    "google-chrome-stable": ("Google Chrome", "BROWSER"),
    "chromium": ("Chromium", "BROWSER"),
    "chromium-browser": ("Chromium", "BROWSER"),
    "firefox": ("Mozilla Firefox", "BROWSER"),
    "firefox-bin": ("Mozilla Firefox", "BROWSER"),
    "microsoft-edge": ("Microsoft Edge", "BROWSER"),
    "microsoft-edge-stable": ("Microsoft Edge", "BROWSER"),
    "msedge": ("Microsoft Edge", "BROWSER"),
    "edge": ("Microsoft Edge", "BROWSER"),
    "brave": ("Brave Browser", "BROWSER"),
    "brave-browser": ("Brave Browser", "BROWSER"),
    "opera": ("Opera Browser", "BROWSER"),
    "vivaldi": ("Vivaldi Browser", "BROWSER"),

    # Productivity & Office
    "libreoffice": ("LibreOffice", "PRODUCTIVITY"),
    "soffice.bin": ("LibreOffice", "PRODUCTIVITY"),
    "gedit": ("gedit Text Editor", "PRODUCTIVITY"),
    "kate": ("Kate Editor", "PRODUCTIVITY"),
    "mousepad": ("Mousepad", "PRODUCTIVITY"),
    "xed": ("xed Text Editor", "PRODUCTIVITY"),
    "thunderbird": ("Mozilla Thunderbird", "COMMUNICATION"),
    "thunderbird-bin": ("Mozilla Thunderbird", "COMMUNICATION"),

    # Communication & Collaboration
    "slack": ("Slack", "COMMUNICATION"),
    "discord": ("Discord", "COMMUNICATION"),
    "zoom": ("Zoom", "COMMUNICATION"),
    "teams": ("Microsoft Teams", "COMMUNICATION"),
    "ms-teams": ("Microsoft Teams", "COMMUNICATION"),
    "skype": ("Skype", "COMMUNICATION"),
    "telegram-desktop": ("Telegram", "COMMUNICATION"),
    "element-desktop": ("Element", "COMMUNICATION"),

    # Development Tools & Shells
    "code": ("Visual Studio Code", "DEVELOPMENT"),
    "vscode": ("Visual Studio Code", "DEVELOPMENT"),
    "codium": ("VSCodium", "DEVELOPMENT"),
    "pycharm": ("PyCharm", "DEVELOPMENT"),
    "idea": ("IntelliJ IDEA", "DEVELOPMENT"),
    "sublime_text": ("Sublime Text", "DEVELOPMENT"),
    "atom": ("Atom", "DEVELOPMENT"),
    "gnome-terminal": ("GNOME Terminal", "DEVELOPMENT"),
    "konsole": ("Konsole Terminal", "DEVELOPMENT"),
    "xfce4-terminal": ("XFCE Terminal", "DEVELOPMENT"),
    "alacritty": ("Alacritty Terminal", "DEVELOPMENT"),
    "kitty": ("Kitty Terminal", "DEVELOPMENT"),
    "wezterm-gui": ("WezTerm", "DEVELOPMENT"),
    "xterm": ("XTerm", "DEVELOPMENT"),
    "bash": ("Bash Shell", "DEVELOPMENT"),
    "zsh": ("Zsh Shell", "DEVELOPMENT"),
    "fish": ("Fish Shell", "DEVELOPMENT"),
    "tmux": ("Tmux Multiplexer", "DEVELOPMENT"),
    "screen": ("Screen Multiplexer", "DEVELOPMENT"),
    "git": ("Git VCS", "DEVELOPMENT"),
    "vim": ("Vim Editor", "DEVELOPMENT"),
    "nvim": ("Neovim", "DEVELOPMENT"),
    "nano": ("Nano Editor", "DEVELOPMENT"),
    "python": ("Python Runtime", "DEVELOPMENT"),
    "python3": ("Python 3 Runtime", "DEVELOPMENT"),
    "node": ("Node.js Runtime", "DEVELOPMENT"),
    "java": ("Java JVM Runtime", "DEVELOPMENT"),
    "ruby": ("Ruby Runtime", "DEVELOPMENT"),
    "go": ("Go Toolchain", "DEVELOPMENT"),
    "php": ("PHP Runtime", "DEVELOPMENT"),
    "docker": ("Docker CLI", "DEVELOPMENT"),

    # Media & Creativity
    "spotify": ("Spotify", "MEDIA"),
    "vlc": ("VLC Media Player", "MEDIA"),
    "mpv": ("MPV Player", "MEDIA"),
    "rhythmbox": ("Rhythmbox", "MEDIA"),
    "gimp": ("GIMP", "MEDIA"),
    "inkscape": ("Inkscape", "MEDIA"),
    "blender": ("Blender", "MEDIA"),
    "obs": ("OBS Studio", "MEDIA"),
    "audacity": ("Audacity", "MEDIA"),

    # Games & Entertainment
    "steam": ("Steam", "GAME/ENTERTAINMENT"),
    "lutris": ("Lutris", "GAME/ENTERTAINMENT"),
    "heroic": ("Heroic Games Launcher", "GAME/ENTERTAINMENT"),
    "minecraft": ("Minecraft", "GAME/ENTERTAINMENT"),

    # System Daemons & Network Services
    "nginx": ("NGINX Web Server", "SYSTEM"),
    "apache2": ("Apache Web Server", "SYSTEM"),
    "httpd": ("HTTPD Web Server", "SYSTEM"),
    "gunicorn": ("Gunicorn WSGI Server", "SYSTEM"),
    "uvicorn": ("Uvicorn ASGI Server", "SYSTEM"),
    "caddy": ("Caddy Web Server", "SYSTEM"),
    "redis-server": ("Redis Server", "SYSTEM"),
    "postgres": ("PostgreSQL Database", "SYSTEM"),
    "mysqld": ("MySQL Database", "SYSTEM"),
    "mariadbd": ("MariaDB Database", "SYSTEM"),
    "mongod": ("MongoDB Database", "SYSTEM"),
    "dockerd": ("Docker Daemon", "SYSTEM"),
    "containerd": ("Containerd Runtime", "SYSTEM"),
    "podman": ("Podman Container", "SYSTEM"),
    "k3s": ("K3s Kubernetes", "SYSTEM"),
    "kubelet": ("Kubernetes Kubelet", "SYSTEM"),
    "sshd": ("OpenSSH Daemon", "SECURITY"),
    "curl": ("cURL Utility", "NETWORK"),
    "wget": ("Wget Utility", "NETWORK"),
    "rsync": ("Rsync File Sync", "NETWORK"),
    "htop": ("Htop Process Viewer", "SYSTEM"),
    "top": ("Top Process Viewer", "SYSTEM"),
}

# Substring patterns representing Linux kernel threads
IGNORED_KERNEL_PATTERNS = (
    "kworker", "ksoftirqd", "migration", "rcu", "idle", "kthreadd",
    "kdevtmpfs", "netns", "khungtaskd", "oom_reaper", "writeback",
    "kcompactd", "crypto", "kintegrityd", "kblockd", "edac-poller",
    "devfreq_wq", "watchdogd", "ksmd", "khugepaged", "scsi_eh",
    "scsi_tmf", "ext4-rsv-conver", "jbd2", "loop", "cpuhp",
)

# Standard Linux background system daemons and low-level helpers to ignore
IGNORED_SYSTEM_PROCESSES = {
    "systemd", "systemd-journald", "systemd-udevd", "systemd-timesyncd",
    "systemd-resolved", "systemd-logind", "systemd-networkd", "dbus-daemon",
    "dbus-broker", "polkitd", "accounts-daemon", "irqbalance", "chronyd",
    "atd", "sleep", "agetty", "login", "rtkit-daemon", "pipewire",
    "pipewire-pulse", "wireplumber", "pulseaudio", "dconf-service",
    "gvfsd", "gvfsd-fuse", "gvfs-udisks2-volume-monitor", "gvfs-gphoto2-volume-monitor",
    "gvfs-afc-volume-monitor", "gvfs-mtp-volume-monitor", "udisksd", "upowerd",
    # Windows/WINE helpers when running in cross-platform/test environments
    "svchost", "dwm", "explorer", "smss", "csrss", "wininit", "services",
    "lsass", "winlogon", "fontdrvhost", "taskhostw", "sihost", "conhost",
    "wudfhost", "mpcmdrun", "msmpeng", "nissrv", "securityhealthservice",
    "smartscreen", "searchhost", "searchindexer", "runtimebroker",
    # Self / testing runners
    "pytest", "apexeye",
}


# Substring patterns representing Linux kernel threads
_LINUX_SYSTEM_PATTERN = re.compile(
    r"^(kworker.*|systemd-.*|dbus-.*|gvfs.*|polkit.*|accounts-.*|rtkit-.*|pipewire.*|wireplumber|"
    r".*worker|.*daemon|.*updater|.*broker)$",
    re.IGNORECASE,
)

_LINUX_SYSTEM_DIRS = (
    "/lib/systemd",
    "/usr/lib/systemd",
    "/sbin",
    "/usr/sbin",
    "/usr/libexec",
)

_CACHE_MAX_ENTRIES = 512
_LINUX_CLASSIFICATION_CACHE: dict[str, tuple[str, str, str]] = {}
_DESKTOP_ENTRY_CACHE: dict[str, tuple[str, str]] = {}


def _bounded_cache_set(cache: dict, key: str, val: object, max_size: int = _CACHE_MAX_ENTRIES) -> None:
    """Store in cache, safely evicting the oldest key if limit reached."""
    if len(cache) >= max_size and key not in cache:
        try:
            oldest_key = next(iter(cache))
            del cache[oldest_key]
        except Exception:
            cache.clear()
    cache[key] = val
_DESKTOP_SEARCH_DIRS = (
    Path("/usr/share/applications"),
    Path("/usr/local/share/applications"),
    Path.home() / ".local" / "share" / "applications",
    Path("/var/lib/flatpak/exports/share/applications"),
    Path("/var/lib/snapd/desktop/applications"),
)


def _scan_desktop_entries() -> None:
    """Scan standard Linux desktop entry directories to extract metadata."""
    for sdir in _DESKTOP_SEARCH_DIRS:
        if not sdir.exists():
            continue
        try:
            for dfile in sdir.glob("*.desktop"):
                try:
                    name = None
                    exec_cmd = None
                    categories = ""
                    for line in dfile.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if line.startswith("Name=") and not name:
                            name = line.split("=", 1)[1].strip()
                        elif line.startswith("Exec=") and not exec_cmd:
                            raw_cmd = line.split("=", 1)[1].strip()
                            exec_cmd = raw_cmd.split()[0]
                        elif line.startswith("Categories="):
                            categories = line.split("=", 1)[1].strip()
                    if name and exec_cmd:
                        exe_base = Path(exec_cmd).name.lower()
                        cat = "APPLICATION"
                        cat_upper = categories.upper()
                        if any(b in cat_upper for b in ("WEB", "BROWSER", "NETWORK;WEB")):
                            cat = "BROWSER"
                        elif any(d in cat_upper for d in ("DEVELOPMENT", "IDE", "PROGRAMMING")):
                            cat = "DEVELOPMENT"
                        elif any(m in cat_upper for m in ("AUDIO", "VIDEO", "PLAYER", "MEDIA")):
                            cat = "MEDIA"
                        elif any(p in cat_upper for p in ("OFFICE", "TEXTEDITOR", "EDITOR")):
                            cat = "PRODUCTIVITY"
                        elif any(c in cat_upper for c in ("CHAT", "COMMUNICATION", "INSTANTMESSAGING")):
                            cat = "COMMUNICATION"
                        _DESKTOP_ENTRY_CACHE[exe_base] = (name, cat)
                except Exception:
                    continue
        except Exception:
            continue


def _get_desktop_entry_metadata(clean_name: str) -> Optional[tuple[str, str]]:
    """Resolve binary name to desktop application name and category via .desktop files."""
    if not _DESKTOP_ENTRY_CACHE:
        _scan_desktop_entries()
    return _DESKTOP_ENTRY_CACHE.get(clean_name)


def _is_browser_or_electron_subworker(proc: Optional[object]) -> bool:
    """
    Detect if a Linux process is an internal browser/Electron worker process
    (--type=renderer, --type=gpu-process, --type=utility, --type=zygote, --type=crashpad-handler).
    """
    if proc is None:
        return False
    try:
        cmdline = None
        if hasattr(proc, "cmdline") and callable(proc.cmdline):
            cmdline = proc.cmdline()
        elif hasattr(proc, "info") and isinstance(proc.info, dict):
            cmdline = proc.info.get("cmdline")
        if not cmdline:
            return False
        cmd_str = " ".join(cmdline)
        return any(
            flag in cmd_str
            for flag in (
                "--type=renderer",
                "--type=gpu-process",
                "--type=utility",
                "--type=zygote",
                "--type=crashpad-handler",
            )
        )
    except Exception:
        return False


def _is_user_application_process(proc: object) -> bool:
    """
    Determine if a Linux process is a legitimate user application or user subworker,
    excluding kernel threads, system daemons, root-only infrastructure, and OS services.
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

        if isinstance(pid, int) and pid <= 2:
            return False

        ppid = None
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "ppid" in proc.info:
            ppid = proc.info.get("ppid")
        elif hasattr(proc, "ppid") and callable(proc.ppid):
            try:
                ppid = proc.ppid()
            except Exception:
                pass
        if isinstance(ppid, int) and ppid == 2:  # Linux kernel thread parent is kthreadd (PID 2)
            return False

        name = ""
        if hasattr(proc, "info") and isinstance(proc.info, dict) and "name" in proc.info:
            name = proc.info.get("name") or ""
        elif hasattr(proc, "name") and callable(proc.name):
            try:
                ret = proc.name()
                if isinstance(ret, str):
                    name = ret
            except Exception:
                name = ""
        elif hasattr(proc, "name") and isinstance(proc.name, str):
            name = proc.name

        if not name or not isinstance(name, str):
            return False

        # Bracketed names are kernel threads e.g. [kworker/0:0]
        if name.startswith("[") and name.endswith("]"):
            return False

        clean = name.lower().strip()
        if clean.endswith(".exe"):
            clean = clean[:-4]

        if any(k in clean for k in IGNORED_KERNEL_PATTERNS):
            return False

        if clean in IGNORED_SYSTEM_PROCESSES:
            return False

        if clean in LINUX_PROCESS_TAXONOMY:
            _, cat = LINUX_PROCESS_TAXONOMY[clean]
            if cat == "SYSTEM":
                return False
            return True

        # Check UID: system services running under UID < 1000
        uids = proc.info.get("uids") if hasattr(proc, "info") and isinstance(proc.info, dict) else None
        if uids is None and hasattr(proc, "uids") and callable(proc.uids):
            try:
                uids = proc.uids()
            except Exception:
                pass
        if uids is not None:
            real_uid = getattr(uids, "real", None)
            if isinstance(real_uid, int) and real_uid < 1000:
                return False

        # Check exe location
        raw_exe = proc.info.get("exe") if hasattr(proc, "info") and isinstance(proc.info, dict) else None
        if raw_exe is None and hasattr(proc, "exe") and callable(proc.exe):
            try:
                raw_exe = proc.exe()
            except psutil.AccessDenied:
                return False
            except Exception:
                pass
        if isinstance(raw_exe, str) and raw_exe:
            exe_lower = raw_exe.lower()
            for sdir in _LINUX_SYSTEM_DIRS:
                if exe_lower.startswith(sdir):
                    return False

        if _LINUX_SYSTEM_PATTERN.match(clean):
            return False

        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False
    except Exception:
        return False


def _classify_linux_process(
    pid: int,
    name: str,
    ppid: Optional[int] = None,
    proc: Optional[object] = None,
) -> tuple[str, str, str]:
    """
    Classify Linux process into ('APPLICATION' | 'SYSTEM', friendly_name, category).
    Uses Linux taxonomy, kernel thread detection, systemd paths, UIDs, and pattern heuristics.
    """
    if isinstance(pid, int) and pid <= 2:
        return ("SYSTEM", name, "SYSTEM")
    if isinstance(ppid, int) and ppid == 2:  # Linux kernel thread parent is kthreadd (PID 2)
        return ("SYSTEM", name, "SYSTEM")

    # Bracketed names are kernel threads in Linux ps/top e.g. [kworker/0:0]
    if name.startswith("[") and name.endswith("]"):
        return ("SYSTEM", name, "SYSTEM")

    clean = name.lower().strip()
    if clean.endswith(".exe"):
        clean = clean[:-4]

    if any(k in clean for k in IGNORED_KERNEL_PATTERNS):
        return ("SYSTEM", clean, "SYSTEM")

    if clean in IGNORED_SYSTEM_PROCESSES:
        return ("SYSTEM", clean, "SYSTEM")

    # Fast path: Taxonomy entries are tracked
    if clean in LINUX_PROCESS_TAXONOMY:
        friendly, cat = LINUX_PROCESS_TAXONOMY[clean]
        if cat == "SYSTEM":
            return ("SYSTEM", friendly, "SYSTEM")
        return ("APPLICATION", friendly, cat)

    if clean in _LINUX_CLASSIFICATION_CACHE:
        return _LINUX_CLASSIFICATION_CACHE[clean]

    # Process inspection if proc object is available
    if proc is not None:
        if not _is_user_application_process(proc):
            res = ("SYSTEM", clean, "SYSTEM")
            _bounded_cache_set(_LINUX_CLASSIFICATION_CACHE, clean, res)
            return res

        # Check Linux UID: UIDs < 1000 are reserved for system services/daemons
        if hasattr(proc, "uids") and callable(proc.uids):
            try:
                uids = proc.uids()
                real_uid = getattr(uids, "real", None)
                if isinstance(real_uid, int) and real_uid < 1000:
                    res = ("SYSTEM", clean, "SYSTEM")
                    _bounded_cache_set(_LINUX_CLASSIFICATION_CACHE, clean, res)
                    return res
            except Exception:
                pass

        # Check binary executable location
        if hasattr(proc, "exe") and callable(proc.exe):
            try:
                raw_exe = proc.exe()
                if isinstance(raw_exe, str) and raw_exe:
                    exe = raw_exe.lower()
                    for sdir in _LINUX_SYSTEM_DIRS:
                        if exe.startswith(sdir):
                            res = ("SYSTEM", clean, "SYSTEM")
                            _bounded_cache_set(_LINUX_CLASSIFICATION_CACHE, clean, res)
                            return res
            except psutil.AccessDenied:
                res = ("SYSTEM", clean, "SYSTEM")
                _bounded_cache_set(_LINUX_CLASSIFICATION_CACHE, clean, res)
                return res
            except Exception:
                pass

    # Dynamic Linux .desktop file metadata resolution
    meta = _get_desktop_entry_metadata(clean)
    if meta:
        res = ("APPLICATION", meta[0], meta[1])
        _bounded_cache_set(_LINUX_CLASSIFICATION_CACHE, clean, res)
        return res

    # Generic Linux system daemon pattern matching
    if _LINUX_SYSTEM_PATTERN.match(clean):
        res = ("SYSTEM", clean, "SYSTEM")
        _bounded_cache_set(_LINUX_CLASSIFICATION_CACHE, clean, res)
        return res

    # Genuine user application (e.g. SomeApp, custom-billing-tool)
    base = name[:-4] if name.lower().endswith(".exe") else name
    s1 = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", base)
    words = re.split(r"[-_.\s]+", s1)
    title = " ".join(w.capitalize() for w in words if w)
    res = ("APPLICATION", title or clean, "APPLICATION")
    _bounded_cache_set(_LINUX_CLASSIFICATION_CACHE, clean, res)
    return res


def _is_kernel_or_system_noise(
    pid: int,
    name: str,
    ppid: Optional[int] = None,
    proc: Optional[object] = None,
) -> bool:
    """Check if process is an OS kernel worker thread or system daemon noise."""
    classification, _, _ = _classify_linux_process(pid, name, ppid, proc)
    return classification == "SYSTEM"


def _resolve_application_metadata(clean_name: str, proc: Optional[object] = None) -> tuple[str, str]:
    """
    Map a raw process name to a readable application name and category.
    Supports taxonomy entries, .desktop metadata, and arbitrary dynamic processes.
    """
    clean = clean_name.lower().strip()
    if clean.endswith(".exe"):
        clean = clean[:-4]
    if clean in LINUX_PROCESS_TAXONOMY:
        friendly, cat = LINUX_PROCESS_TAXONOMY[clean]
        return friendly, cat

    meta = _get_desktop_entry_metadata(clean)
    if meta:
        return meta[0], meta[1]

    _, friendly, category = _classify_linux_process(1000, clean, ppid=1000, proc=proc)
    return friendly, category


class ProcessSnapshot:
    """Represents the set of running tracked processes at a point in time."""

    def __init__(self):
        # pid -> (app_name, category, exe_name)
        self._processes: dict[int, tuple[str, str, str]] = {}

    @property
    def processes(self) -> dict[int, tuple[str, str, str]]:
        return self._processes

    @processes.setter
    def processes(self, value: dict[int, tuple[str, str, str]]):
        self._processes = dict(value) if value else {}

    @property
    def app_groups(self) -> dict[str, tuple[str, list[int], str]]:
        """
        Group running processes by application name.
        Returns: {app_name: (category, [pids], primary_exe_name)}
        """
        groups: dict[str, tuple[str, list[int], str]] = {}
        for pid, (app_name, category, exe_name) in self._processes.items():
            if category == "SYSTEM":
                continue
            if app_name not in groups:
                groups[app_name] = (category, [pid], exe_name)
            else:
                groups[app_name][1].append(pid)
        return groups

    @app_groups.setter
    def app_groups(self, value):
        if not value:
            self._processes.clear()

    def get_running_applications(self) -> list[dict]:
        """
        Return a clean snapshot of logical user-facing applications currently active on Linux.
        Excludes raw subprocesses, system daemons, and headless workers.
        """
        running: list[dict] = []
        for app_name, (category, pids, exe_name) in sorted(self.app_groups.items()):
            running.append({
                "application_name": app_name,
                "executable": exe_name,
                "category": category,
                "primary_pid": pids[0] if pids else 0,
                "process_count": len(pids),
                "pids": sorted(pids),
                "is_foreground": False,
                "window_title": "",
            })
        return running

    def capture(self) -> None:
        """Take a snapshot of currently running tracked processes."""
        self._processes = {}

        if psutil:
            for proc in psutil.process_iter(["pid", "name", "ppid", "exe"]):
                try:
                    info = proc.info if hasattr(proc, "info") and proc.info else {}
                    pid = info.get("pid") or getattr(proc, "pid", None)
                    name = info.get("name") or (proc.name() if hasattr(proc, "name") and callable(proc.name) else None)
                    ppid = info.get("ppid") or (proc.ppid() if hasattr(proc, "ppid") and callable(proc.ppid) else None)

                    if not pid or not name:
                        continue

                    if _is_kernel_or_system_noise(pid, name, ppid, proc=proc):
                        continue

                    clean_name = str(name).lower().strip()
                    if clean_name.endswith(".exe"):
                        clean_name = clean_name[:-4]

                    app_name, category = _resolve_application_metadata(clean_name, proc=proc)
                    if category == "SYSTEM":
                        continue
                    self._processes[pid] = (app_name, category, clean_name)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception:
                    continue
        else:
            # Native Linux fallback: inspect /proc/[0-9]+/comm and stat
            proc_root = Path("/proc")
            if proc_root.exists():
                for p_dir in proc_root.iterdir():
                    if p_dir.is_dir() and p_dir.name.isdigit():
                        pid = int(p_dir.name)
                        comm_file = p_dir / "comm"
                        stat_file = p_dir / "stat"

                        name = None
                        ppid = None

                        if comm_file.exists():
                            try:
                                name = comm_file.read_text(encoding="utf-8", errors="replace").strip()
                            except Exception:
                                continue

                        if stat_file.exists():
                            try:
                                stat_text = stat_file.read_text(encoding="utf-8", errors="replace").strip()
                                # /proc/[pid]/stat format: pid (comm) state ppid ...
                                parts = stat_text.rsplit(")", 1)
                                if len(parts) > 1:
                                    after_comm = parts[1].split()
                                    if len(after_comm) >= 2:
                                        ppid = int(after_comm[1])
                            except Exception:
                                pass

                        if not name:
                            continue

                        if _is_kernel_or_system_noise(pid, name, ppid):
                            continue

                        clean_name = name.lower().strip()
                        if clean_name.endswith(".exe"):
                            clean_name = clean_name[:-4]

                        app_name, category = _resolve_application_metadata(clean_name)
                        if category == "SYSTEM":
                            continue
                        self._processes[pid] = (app_name, category, clean_name)


class EventCollector:
    """
    Monitors categorized application lifecycle events (Started, Stopped)
    using a reliable process-group state machine.

    Guarantees:
      - 0 processes -> 1+ processes: emits exactly ONE APPLICATION_STARTED
      - Subprocesses spawn: emits ZERO duplicate started events
      - Subprocesses exit: emits ZERO stopped events while application is still running
      - Entire process group reaches 0: emits exactly ONE APPLICATION_STOPPED
      - Later re-open: emits exactly ONE new APPLICATION_STARTED event
      - Uncataloged / arbitrary user applications are automatically categorized and monitored
      - Initial startup baseline prevents false start events for already-running apps
      - Kernel threads and system daemon noise are filtered out
    """

    def __init__(self):
        self._previous = ProcessSnapshot()
        self._previous.capture()
        self._previous_applications: dict[str, tuple[str, list[int], str]] = dict(self._previous.app_groups)
        logger.info(
            "Linux EventCollector initialized. %d applications recognized in taxonomy. "
            "Baseline: %d active application group(s).",
            len(LINUX_PROCESS_TAXONOMY),
            len(self._previous_applications),
        )

    def get_running_applications(self) -> list[dict]:
        """Return snapshot of logical applications currently running."""
        return self._previous.get_running_applications()

    def collect(self) -> list[dict]:
        """
        Compare current process group snapshot with previous snapshot.
        Returns a list of structured lifecycle event dicts for application start/stop transitions.
        """
        try:
            current = ProcessSnapshot()
            current.capture()

            events = []
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            current_groups = current.app_groups
            prev_groups = self._previous.app_groups

            # Detect newly started application groups (0 -> 1+ processes)
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
                        "source": "linux_process_monitor",
                        "severity": "INFO",
                        "message": f"Application started: {app_name} (PID {primary_pid}, process: {exe_name})",
                    })
                    logger.info("Linux application started: %s (PID %d, process: %s)", app_name, primary_pid, exe_name)

            # Detect stopped application groups (1+ -> 0 processes)
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
                        "source": "linux_process_monitor",
                        "severity": "INFO",
                        "message": f"Application stopped: {app_name} (PID {primary_pid}, process: {exe_name})",
                    })
                    logger.info("Linux application stopped: %s (PID %d, process: %s)", app_name, primary_pid, exe_name)

            self._previous = current
            self._previous_applications = dict(current_groups)
            return events

        except Exception as exc:
            logger.error("Failed to collect Linux process events: %s", exc)
            return []
