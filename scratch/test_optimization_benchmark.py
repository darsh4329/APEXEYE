"""
Benchmark test to compare current ProcessSnapshot.capture()
vs optimized ProcessSnapshot.capture() without touching production code.
"""

import sys
import time
import cProfile
import pstats
import io
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.collectors.events import ProcessSnapshot as OriginalSnapshot, _is_user_application_process, _resolve_application_metadata, _get_foreground_window_info, _is_browser_or_electron_subworker, APPLICATION_TAXONOMY, IGNORED_SYSTEM_PROCESSES, _SERVICE_WORKER_PATTERN, _WINDOWS_SYSTEM_DIRS

# Prototype optimized capture implementation
class OptimizedSnapshot:
    def __init__(self):
        self._processes = {}
        self._logical_apps = {}
        self._services_pids = None
        self._services_pids_time = 0

    @property
    def app_groups(self):
        groups = {}
        if self._logical_apps:
            for app_name, app_info in self._logical_apps.items():
                active_pids = [p for p in app_info.get("pids", []) if p in self._processes]
                if not active_pids:
                    continue
                category = app_info.get("category", "APPLICATION")
                if category == "SYSTEM":
                    continue
                groups[app_name] = (category, active_pids, app_info.get("executable", ""))
        return groups

    def _get_services_pids_cached(self):
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

    def _fast_is_user_app(self, p_info, proc, services_pids):
        pid = p_info.get("pid")
        if not pid or pid <= 4:
            return False

        name = p_info.get("name")
        if not name:
            return False

        name_lower = name.lower().strip()
        if name_lower.startswith("unknown_") or name_lower in IGNORED_SYSTEM_PROCESSES:
            return False

        clean_no_ext = name_lower[:-4] if name_lower.endswith(".exe") else name_lower
        if clean_no_ext in IGNORED_SYSTEM_PROCESSES:
            return False

        is_in_taxonomy = (name_lower in APPLICATION_TAXONOMY or clean_no_ext in APPLICATION_TAXONOMY)

        ppid = p_info.get("ppid")
        if ppid is not None and ppid in services_pids and not is_in_taxonomy:
            return False

        username = p_info.get("username")
        if username:
            uname = username.lower()
            if any(s in uname for s in ("nt authority", "system", "local service", "network service")):
                return False

        exe = p_info.get("exe")
        if exe:
            exe_lower = exe.lower()
            for sys_dir in _WINDOWS_SYSTEM_DIRS:
                if sys_dir in exe_lower and not is_in_taxonomy:
                    return False

        if is_in_taxonomy:
            return True

        if _SERVICE_WORKER_PATTERN.search(clean_no_ext) or _SERVICE_WORKER_PATTERN.search(name_lower):
            return False

        return True

    def capture(self):
        self._processes = {}
        self._logical_apps = {}
        services_pids = self._get_services_pids_cached()
        fg_pid, _ = _get_foreground_window_info()

        # Query required attributes in ONE shot via process_iter
        for proc in psutil.process_iter(["pid", "name", "ppid", "username", "exe"]):
            try:
                info = proc.info
                if not self._fast_is_user_app(info, proc, services_pids):
                    continue

                name_lower = info["name"].lower().strip()
                app_name, category = _resolve_application_metadata(name_lower, proc=proc)
                if category == "SYSTEM":
                    continue

                pid = info["pid"]
                self._processes[pid] = name_lower
                is_sub = _is_browser_or_electron_subworker(proc)
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
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

def compare_runs():
    print("=" * 70)
    print("COMPARATIVE BENCHMARK: ORIGINAL vs OPTIMIZED PROCESS CAPTURE")
    print("=" * 70)

    orig = OriginalSnapshot()
    opt = OptimizedSnapshot()

    # Warm up caches
    orig.capture()
    opt.capture()

    # Measure 5 runs each
    orig_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        orig.capture()
        orig_times.append((time.perf_counter() - t0) * 1000)

    opt_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        opt.capture()
        opt_times.append((time.perf_counter() - t0) * 1000)

    avg_orig = sum(orig_times) / len(orig_times)
    avg_opt = sum(opt_times) / len(opt_times)

    print(f"Original capture() avg time : {avg_orig:8.2f} ms (min={min(orig_times):.2f}, max={max(orig_times):.2f})")
    print(f"Optimized capture() avg time: {avg_opt:8.2f} ms (min={min(opt_times):.2f}, max={max(opt_times):.2f})")
    print(f"Speedup factor              : {avg_orig / avg_opt:8.1f}x faster!")
    print(f"Time saved per 5s cycle     : {avg_orig - avg_opt:8.2f} ms")

    # Verify identical application detection results
    orig_apps = set(orig.app_groups.keys())
    opt_apps = set(opt.app_groups.keys())
    print("\n--- Accuracy Verification ---")
    print(f"Original detected apps count : {len(orig_apps)}")
    print(f"Optimized detected apps count: {len(opt_apps)}")
    print(f"Exact match between sets    : {orig_apps == opt_apps}")
    if orig_apps != opt_apps:
        print(f"  Missing in optimized: {orig_apps - opt_apps}")
        print(f"  Extra in optimized  : {opt_apps - orig_apps}")
    else:
        print("  ALL 100% OF IDENTIFIED APPLICATIONS MATCH EXACTLY!")

if __name__ == "__main__":
    compare_runs()
