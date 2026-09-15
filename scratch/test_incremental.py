"""
Test incremental PID diffing:
Benchmark capture() when 0-2 processes change between cycles (normal steady state).
"""

import sys
import time
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.collectors.events import (
    APPLICATION_TAXONOMY,
    IGNORED_SYSTEM_PROCESSES,
    _SERVICE_WORKER_PATTERN,
    _WINDOWS_SYSTEM_DIRS,
    _resolve_application_metadata,
    _get_foreground_window_info,
    _is_browser_or_electron_subworker,
)

class IncrementalSnapshot:
    def __init__(self):
        self._processes = {}          # pid -> exe_lower
        self._pid_metadata = {}       # pid -> (app_name, category, is_sub)
        self._logical_apps = {}
        self._services_pids = None
        self._services_pids_time = 0

    @property
    def app_groups(self):
        groups = {}
        for app_name, info in self._logical_apps.items():
            active_pids = [p for p in info["pids"] if p in self._processes]
            if active_pids and info["category"] != "SYSTEM":
                groups[app_name] = (info["category"], active_pids, info["executable"])
        return groups

    def _get_services_pids(self):
        now = time.time()
        if self._services_pids is not None and (now - self._services_pids_time) < 60:
            return self._services_pids
        pids = set()
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if p.info["name"] and p.info["name"].lower() == "services.exe":
                    pids.add(p.info["pid"])
            except Exception:
                continue
        self._services_pids = pids
        self._services_pids_time = now
        return pids

    def capture(self):
        current_pids = set(psutil.pids())
        existing_pids = set(self._processes.keys())

        # Purge dead PIDs
        dead_pids = existing_pids - current_pids
        for p in dead_pids:
            self._processes.pop(p, None)
            self._pid_metadata.pop(p, None)

        services_pids = self._get_services_pids()
        fg_pid, _ = _get_foreground_window_info()

        # Only inspect new PIDs that spawned since last cycle!
        new_pids = current_pids - existing_pids
        # If first run (existing_pids is empty), inspect all current_pids
        pids_to_inspect = new_pids if existing_pids else current_pids

        for proc in psutil.process_iter(["pid", "name", "ppid", "username", "exe"]):
            try:
                pid = proc.info["pid"]
                if pid not in pids_to_inspect:
                    continue

                if not pid or pid <= 4:
                    continue

                raw_name = proc.info.get("name")
                if not raw_name:
                    continue

                name_lower = raw_name.lower().strip()
                if name_lower.startswith("unknown_") or name_lower in IGNORED_SYSTEM_PROCESSES:
                    continue

                clean_no_ext = name_lower[:-4] if name_lower.endswith(".exe") else name_lower
                if clean_no_ext in IGNORED_SYSTEM_PROCESSES:
                    continue

                is_in_taxonomy = (name_lower in APPLICATION_TAXONOMY or clean_no_ext in APPLICATION_TAXONOMY)

                ppid = proc.info.get("ppid")
                if ppid in services_pids and not is_in_taxonomy:
                    continue

                uname = proc.info.get("username")
                if uname and any(s in uname.lower() for s in ("nt authority", "system", "local service", "network service")):
                    continue

                exe = proc.info.get("exe")
                if exe:
                    exe_lower = exe.lower()
                    if any(s in exe_lower for s in _WINDOWS_SYSTEM_DIRS) and not is_in_taxonomy:
                        continue

                if not is_in_taxonomy:
                    if _SERVICE_WORKER_PATTERN.search(clean_no_ext) or _SERVICE_WORKER_PATTERN.search(name_lower):
                        continue

                app_name, category = _resolve_application_metadata(name_lower, proc=proc)
                if category == "SYSTEM":
                    continue

                is_sub = _is_browser_or_electron_subworker(proc)
                self._processes[pid] = name_lower
                self._pid_metadata[pid] = (app_name, category, is_sub)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        # Rebuild logical app groups from cached pid metadata
        self._logical_apps = {}
        for pid, name_lower in self._processes.items():
            if pid not in self._pid_metadata:
                continue
            app_name, category, is_sub = self._pid_metadata[pid]
            is_fg = (pid == fg_pid)
            if app_name not in self._logical_apps:
                self._logical_apps[app_name] = {
                    "application_name": app_name,
                    "executable": name_lower,
                    "category": category,
                    "primary_pid": pid,
                    "pids": [pid],
                    "has_main_proc": not is_sub,
                    "is_foreground": is_fg,
                    "window_title": "",
                }
            else:
                self._logical_apps[app_name]["pids"].append(pid)
                if is_fg:
                    self._logical_apps[app_name]["is_foreground"] = True
                if not is_sub and not self._logical_apps[app_name].get("has_main_proc", False):
                    self._logical_apps[app_name]["primary_pid"] = pid
                    self._logical_apps[app_name]["has_main_proc"] = True

def test_incremental():
    snap = IncrementalSnapshot()
    t0 = time.perf_counter()
    snap.capture()
    cold_ms = (time.perf_counter() - t0) * 1000
    print(f"Cold initial capture: {cold_ms:.2f} ms ({len(snap.app_groups)} apps detected)")

    steady_times = []
    for _ in range(10):
        time.sleep(0.1)
        t0 = time.perf_counter()
        snap.capture()
        steady_times.append((time.perf_counter() - t0) * 1000)

    avg_steady = sum(steady_times) / len(steady_times)
    print(f"Steady-state capture (incremental diff): avg={avg_steady:.2f} ms | min={min(steady_times):.2f} ms | max={max(steady_times):.2f} ms")
    print(f"Speedup vs cold: {cold_ms / avg_steady:.1f}x faster!")

if __name__ == "__main__":
    test_incremental()
