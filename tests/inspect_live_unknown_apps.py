"""
APEXEYE — Live Unknown Application Detection & Diagnostic Script
Inspects real processes and EventCollector detection against the host laptop.
"""

import os
import re
import sys
import psutil
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.collectors.events import (
    EventCollector,
    ProcessSnapshot,
    APPLICATION_TAXONOMY,
    IGNORED_SYSTEM_PROCESSES,
    _WINDOWS_SYSTEM_DIRS,
    _SERVICE_WORKER_PATTERN,
    _is_user_application_process,
    _classify_process,
    _resolve_application_metadata,
    _get_pe_version_info,
)

def inspect_all():
    print("=" * 80)
    print("APEXEYE — PRODUCTION LIVE RUNNING APPLICATION DIAGNOSTIC REPORT")
    print("=" * 80)

    # 1. RUN PRODUCTION EventCollector.get_running_applications()
    collector = EventCollector()
    running = collector.get_running_applications()
    
    print(f"\n1. CURRENT RUNNING LOGICAL APPLICATIONS DETECTED ({len(running)} total):")
    print("-" * 80)
    for app in running:
        pids_str = ", ".join(str(p) for p in app["pids"])
        print(f"Application:   {app['application_name']}")
        print(f"  Executable:  {app['executable']}")
        print(f"  Category:    {app['category']}")
        print(f"  Primary PID: {app['primary_pid']}")
        print(f"  Total PIDs:  {app['process_count']} (PIDs: [{pids_str}])")
        print("-" * 40)

    # 2. VIRTUALBOX INSPECTION
    print("\n2. VIRTUALBOX DETECTION ANALYSIS:")
    print("-" * 80)
    vbox_procs = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            n = (p.info.get("name") or "").lower()
            if "virtualbox" in n or "vbox" in n:
                try:
                    exe = p.exe()
                except Exception:
                    exe = "N/A"
                try:
                    uname = p.username()
                except Exception:
                    uname = "N/A"
                try:
                    sess = p.session_id() if hasattr(p, "session_id") else -1
                except Exception:
                    sess = -1
                vbox_procs.append((p.pid, p.info.get("name"), exe, uname, sess, p))
        except Exception:
            pass

    print(f"Real VirtualBox processes found in OS ({len(vbox_procs)}):")
    for pid, name, exe, uname, sess, proc in vbox_procs:
        is_user = _is_user_application_process(proc)
        meta_name, meta_cat = _resolve_application_metadata(name.lower(), proc=proc)
        pe_name = _get_pe_version_info(exe) if exe != "N/A" else None
        in_tax = name.lower() in APPLICATION_TAXONOMY
        print(f"  PID: {pid} | Name: {name} | Exe: {exe}")
        print(f"    User: {uname} | Session: {sess}")
        print(f"    In Taxonomy: {in_tax}")
        print(f"    PE VersionInfo Name: {pe_name}")
        print(f"    _is_user_application_process: {is_user}")
        print(f"    _resolve_application_metadata: ('{meta_name}', '{meta_cat}')")
        print()

    # 3. CHATGPT INSPECTION
    print("\n3. CHATGPT DETECTION ANALYSIS:")
    print("-" * 80)
    chatgpt_procs = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            n = (p.info.get("name") or "").lower()
            if "chatgpt" in n:
                try:
                    exe = p.exe()
                except Exception:
                    exe = "N/A"
                try:
                    uname = p.username()
                except Exception:
                    uname = "N/A"
                try:
                    sess = p.session_id() if hasattr(p, "session_id") else -1
                except Exception:
                    sess = -1
                chatgpt_procs.append((p.pid, p.info.get("name"), exe, uname, sess, p))
        except Exception:
            pass

    print(f"Real ChatGPT processes found in OS ({len(chatgpt_procs)}):")
    for pid, name, exe, uname, sess, proc in chatgpt_procs:
        is_user = _is_user_application_process(proc)
        meta_name, meta_cat = _resolve_application_metadata(name.lower(), proc=proc)
        pe_name = _get_pe_version_info(exe) if exe != "N/A" else None
        in_tax = name.lower() in APPLICATION_TAXONOMY
        print(f"  PID: {pid} | Name: {name} | Exe: {exe}")
        print(f"    User: {uname} | Session: {sess}")
        print(f"    In Taxonomy: {in_tax}")
        print(f"    PE VersionInfo Name: {pe_name}")
        print(f"    _is_user_application_process: {is_user}")
        print(f"    _resolve_application_metadata: ('{meta_name}', '{meta_cat}')")
        print()

    # 4. CANDIDATE PROCESS FILTERING REASON CLASSIFICATION TABLE
    print("\n4. PROCESS FILTERING CLASSIFICATION TABLE (USER DIRECTORIES & CANDIDATES):")
    print("-" * 80)
    print(f"{'Executable':<28} | {'PID':<6} | {'Accepted/Rejected':<17} | {'Reason / Dynamic Source'}")
    print("-" * 80)

    seen_exes = set()
    for p in psutil.process_iter(["pid", "name"]):
        try:
            pid = p.pid
            raw_name = p.name()
            if not raw_name:
                continue
            name_lower = raw_name.lower().strip()
            
            try:
                exe = p.exe()
            except Exception:
                exe = ""

            # Check if this process is in user directories (Program Files, AppData, etc.)
            is_user_dir = False
            if exe:
                exe_l = exe.lower()
                if any(pfx in exe_l for pfx in [r"\program files", r"\users\\", r"\appdata"]):
                    is_user_dir = True

            if not is_user_dir:
                continue

            # Only print unique executables to avoid 200 duplicate rows
            if name_lower in seen_exes:
                continue
            seen_exes.add(name_lower)

            is_accepted = _is_user_application_process(p)
            status = "ACCEPTED" if is_accepted else "REJECTED"

            reason = ""
            if is_accepted:
                if name_lower in APPLICATION_TAXONOMY:
                    reason = f"Taxonomy ({APPLICATION_TAXONOMY[name_lower][0]})"
                else:
                    pe = _get_pe_version_info(exe) if exe else None
                    if pe:
                        reason = f"Dynamic PE metadata ('{pe}')"
                    else:
                        reason = "Dynamic Normalized Exe Name"
            else:
                clean_no_ext = name_lower[:-4] if name_lower.endswith(".exe") else name_lower
                if name_lower in IGNORED_SYSTEM_PROCESSES or clean_no_ext in IGNORED_SYSTEM_PROCESSES:
                    reason = "In IGNORED_SYSTEM_PROCESSES"
                elif any(s in exe.lower() for s in _WINDOWS_SYSTEM_DIRS):
                    reason = "In Windows System Directory"
                elif _SERVICE_WORKER_PATTERN.search(clean_no_ext) or _SERVICE_WORKER_PATTERN.search(name_lower):
                    reason = "Matched _SERVICE_WORKER_PATTERN"
                else:
                    try:
                        uname = p.username().lower()
                        if any(s in uname for s in ("nt authority", "system", "local service", "network service")):
                            reason = f"System/Service Account ({uname})"
                    except Exception:
                        pass
                if not reason:
                    reason = "Rejected by process filter"

            print(f"{raw_name:<28} | {pid:<6} | {status:<17} | {reason}")

        except Exception:
            continue

if __name__ == "__main__":
    inspect_all()
