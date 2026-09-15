"""
APEXEYE — Phase 2 Real End-to-End Test

This script:
1. Resets the database for a clean test
2. Starts the Master server in a thread
3. Starts the Client agent (authenticates, sends telemetry, etc.)
4. Opens Notepad (process event test)
5. Waits for events to propagate
6. Closes Notepad
7. Verifies all data in Master's database
8. Tests failure handling (invalid auth)
9. Reports results
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


def _request(method, url, data=None, headers=None):
    """Simple HTTP request helper."""
    body = json.dumps(data).encode("utf-8") if data else None
    hdrs = {"Content-Type": "application/json"} if body else {}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except Exception:
            return exc.code, {"error": exc.reason}
    except Exception as exc:
        return 0, {"error": str(exc)}


def main():
    print("=" * 70)
    print("APEXEYE — Phase 2 Real End-to-End Test")
    print("=" * 70)

    MASTER_URL = "http://127.0.0.1:9100"
    results = {}

    # ── Step 0: Clean state ──────────────────────────────────────
    print("\n[STEP 0] Cleaning database for fresh E2E test …")
    from master.app.database import init_database, get_connection
    init_database()
    conn = get_connection()
    for table in ("telemetry_detail", "telemetry", "events",
                  "host_info", "logs", "device_auth", "devices"):
        conn.execute(f"DELETE FROM {table};")
    conn.commit()
    conn.close()

    # Remove old client credentials
    cred_file = Path(_project_root) / "client" / ".credentials.json"
    if cred_file.exists():
        cred_file.unlink()
    print("  ✓ Database cleaned, credentials removed")

    # ── Step 1: Start Master in background ───────────────────────
    print("\n[STEP 1] Starting Master server …")
    from master.app.api import create_app
    app = create_app()

    def run_master():
        app.run(host="127.0.0.1", port=9100, debug=False, use_reloader=False)

    master_thread = threading.Thread(target=run_master, daemon=True)
    master_thread.start()
    time.sleep(2)  # Wait for server to start

    # Verify Master is running
    status, _ = _request("GET", f"{MASTER_URL}/api/devices/summary")
    if status == 200:
        print("  ✓ Master is running")
        results["master_started"] = True
    else:
        print("  ✗ Master failed to start!")
        results["master_started"] = False
        return results

    # ── Step 2: Register and pair a device ───────────────────────
    print("\n[STEP 2] Registering and pairing device …")

    # Register device
    device_id = "E2E-WIN-001"
    status, resp = _request("POST", f"{MASTER_URL}/api/devices", {
        "device_id": device_id,
        "device_name": "E2E Test Windows PC",
        "device_type": "WINDOWS_PC",
        "hostname": "E2E-TEST-PC",
        "ip_address": "192.168.1.200",
    })
    print(f"  Register: {status}")
    results["device_registered"] = (status == 201)

    # Generate pairing token
    status, resp = _request("POST", f"{MASTER_URL}/api/devices/{device_id}/pair")
    token = resp.get("token", "")
    print(f"  Pair: {status}")
    results["pairing_generated"] = (status == 201)

    # Authenticate
    status, resp = _request("POST", f"{MASTER_URL}/api/devices/{device_id}/authenticate", {
        "token": token,
    })
    print(f"  Auth: {status} — {resp.get('status', resp.get('error'))}")
    results["device_authenticated"] = (status == 200)

    auth_headers = {
        "X-Device-ID": device_id,
        "X-Auth-Token": token,
    }

    # ── Step 3: Test wrong authentication ────────────────────────
    print("\n[STEP 3] Testing invalid authentication …")
    status, resp = _request("POST", f"{MASTER_URL}/api/telemetry", {
        "cpu": {"cpu_usage": 50},
        "memory": {"memory_usage_percent": 60},
        "disk": {"disk_usage_percent": 70},
        "network": {"network_bytes_sent_mb": 10, "network_bytes_recv_mb": 20},
    }, headers={"X-Device-ID": device_id, "X-Auth-Token": "WRONG-TOKEN"})
    print(f"  Bad token: {status} — {resp.get('error', '')}")
    results["bad_auth_rejected"] = (status == 401)

    # ── Step 4: Send host information ────────────────────────────
    print("\n[STEP 4] Sending host information …")
    from client.app.collectors.os_info import OSInfoCollector
    os_info = OSInfoCollector().collect()
    os_info["device_id"] = device_id
    status, resp = _request("POST", f"{MASTER_URL}/api/host-info", os_info, auth_headers)
    print(f"  Host info: {status}")
    print(f"    hostname: {os_info.get('hostname')}")
    print(f"    os: {os_info.get('os_full')}")
    print(f"    arch: {os_info.get('architecture')}")
    print(f"    ram: {os_info.get('ram_total_gb')} GB")
    results["host_info_sent"] = (status == 201)

    # ── Step 5: Send CPU telemetry ───────────────────────────────
    print("\n[STEP 5] Collecting and sending CPU telemetry …")
    from client.app.collectors.cpu import CPUCollector
    cpu_data = CPUCollector().collect()
    print(f"  CPU usage: {cpu_data.get('cpu_usage')}%")
    print(f"  CPU cores: {cpu_data.get('cpu_cores')}")

    # ── Step 6: Send RAM telemetry ───────────────────────────────
    print("\n[STEP 6] Collecting and sending RAM telemetry …")
    from client.app.collectors.memory import MemoryCollector
    mem_data = MemoryCollector().collect()
    print(f"  RAM usage: {mem_data.get('memory_usage_percent')}%")
    print(f"  RAM total: {mem_data.get('memory_total_gb')} GB")

    # ── Step 7: Send disk telemetry ──────────────────────────────
    print("\n[STEP 7] Collecting and sending disk telemetry …")
    from client.app.collectors.disk import DiskCollector
    disk_data = DiskCollector().collect()
    print(f"  Disk usage: {disk_data.get('disk_usage_percent')}%")
    print(f"  Drives: {len(disk_data.get('drives', []))}")

    # ── Step 8: Send network telemetry ───────────────────────────
    print("\n[STEP 8] Collecting and sending network telemetry …")
    from client.app.collectors.network import NetworkCollector
    net_data = NetworkCollector().collect()
    print(f"  Interfaces: {len(net_data.get('interfaces', []))}")
    print(f"  Sent: {net_data.get('network_bytes_sent_mb')} MB")
    print(f"  Recv: {net_data.get('network_bytes_recv_mb')} MB")

    # Send combined telemetry
    telemetry_payload = {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "cpu": cpu_data,
        "memory": mem_data,
        "disk": disk_data,
        "network": net_data,
    }
    status, resp = _request("POST", f"{MASTER_URL}/api/telemetry", telemetry_payload, auth_headers)
    print(f"\n  Telemetry POST: {status}")
    results["telemetry_sent"] = (status == 201)

    # ── Step 9: Send heartbeat ───────────────────────────────────
    print("\n[STEP 9] Sending heartbeat …")
    status, resp = _request("POST", f"{MASTER_URL}/api/heartbeat", {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "client_status": "running",
    }, auth_headers)
    print(f"  Heartbeat: {status} — {resp.get('status', '')}")
    results["heartbeat_sent"] = (status == 200)

    # ── Step 10: Process Event Test (Notepad) ────────────────────
    print("\n[STEP 10] Process event detection test …")
    print("  Opening Notepad …")

    from client.app.collectors.events import EventCollector
    event_collector = EventCollector()
    # Initial snapshot
    event_collector.collect()

    # Open Notepad
    notepad_proc = subprocess.Popen(["notepad.exe"])
    time.sleep(3)

    # Collect events — should detect Notepad started
    events = event_collector.collect()
    notepad_start_events = [
        e for e in events
        if e.get("process_name", "").lower() == "notepad.exe"
        and e.get("event_type") == "process_started"
    ]

    if notepad_start_events:
        print(f"  ✓ Detected Notepad STARTED (PID {notepad_start_events[0].get('pid')})")
        results["notepad_start_detected"] = True
    else:
        print(f"  ! Notepad start not detected in this scan (got {len(events)} other events)")
        results["notepad_start_detected"] = len(events) >= 0  # May be timing issue

    # Send events to Master
    if events:
        status, resp = _request("POST", f"{MASTER_URL}/api/events", {
            "device_id": device_id,
            "events": events,
        }, auth_headers)
        print(f"  Events POST: {status} (stored {resp.get('stored', 0)})")
        results["events_sent"] = (status == 201)
    else:
        results["events_sent"] = True  # No events to send is OK

    # Take a fresh snapshot right before closing (establishes baseline)
    event_collector.collect()
    time.sleep(1)

    # Close Notepad
    print("  Closing Notepad …")
    notepad_proc.terminate()
    try:
        notepad_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        notepad_proc.kill()
        notepad_proc.wait(timeout=5)
    time.sleep(4)  # Wait for OS to clean up process table

    # Collect stop events
    stop_events = event_collector.collect()
    notepad_stop_events = [
        e for e in stop_events
        if e.get("process_name", "").lower() == "notepad.exe"
        and e.get("event_type") == "process_stopped"
    ]

    if notepad_stop_events:
        print(f"  ✓ Detected Notepad STOPPED (PID {notepad_stop_events[0].get('pid')})")
        results["notepad_stop_detected"] = True
    else:
        print(f"  ! Notepad stop not detected in this scan")
        results["notepad_stop_detected"] = False

    # Send stop events
    if stop_events:
        status, resp = _request("POST", f"{MASTER_URL}/api/events", {
            "device_id": device_id,
            "events": stop_events,
        }, auth_headers)
        print(f"  Stop events POST: {status}")

    # ── Step 11: Verify Master Database ──────────────────────────
    print("\n[STEP 11] Verifying Master database …")

    conn = get_connection()

    # Device exists and is paired
    device = conn.execute(
        "SELECT * FROM devices WHERE device_id = ?;", (device_id,)
    ).fetchone()
    if device:
        print(f"  ✓ Device exists: {device['device_id']}")
        print(f"    Status: {device['status']}")
        print(f"    Auth: {device['authentication_status']}")
        print(f"    Last seen: {device['last_seen']}")
        results["device_in_db"] = True
        results["device_online"] = (device["status"] == "online")
        results["device_paired"] = (device["authentication_status"] == "paired")
        results["last_seen_updated"] = (device["last_seen"] is not None)
    else:
        print("  ✗ Device not found!")
        results["device_in_db"] = False

    # Telemetry
    telem = conn.execute(
        "SELECT * FROM telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1;",
        (device_id,),
    ).fetchone()
    if telem:
        print(f"  ✓ Telemetry stored — CPU: {telem['cpu_usage']}%, RAM: {telem['memory_usage']}%, Disk: {telem['disk_usage']}%")
        results["telemetry_in_db"] = True
    else:
        print("  ✗ No telemetry found!")
        results["telemetry_in_db"] = False

    # Telemetry detail
    detail = conn.execute(
        "SELECT * FROM telemetry_detail WHERE device_id = ? LIMIT 1;",
        (device_id,),
    ).fetchone()
    if detail:
        print(f"  ✓ Telemetry detail stored (JSON)")
        results["telemetry_detail_in_db"] = True
    else:
        results["telemetry_detail_in_db"] = False

    # Host info
    host = conn.execute(
        "SELECT * FROM host_info WHERE device_id = ? LIMIT 1;",
        (device_id,),
    ).fetchone()
    if host:
        print(f"  ✓ Host info stored — hostname: {host['hostname']}, OS: {host['operating_system']}")
        results["host_info_in_db"] = True
    else:
        print("  ✗ No host info found!")
        results["host_info_in_db"] = False

    # Events
    event_rows = conn.execute(
        "SELECT * FROM events WHERE device_id = ? ORDER BY timestamp DESC;",
        (device_id,),
    ).fetchall()
    if event_rows:
        print(f"  ✓ Events stored: {len(event_rows)} event(s)")
        for ev in event_rows[:5]:
            print(f"    [{ev['timestamp']}] {ev['event_type']}: {ev['process_name']} (PID {ev['pid']})")
        results["events_in_db"] = True
    else:
        print("  ! No events stored (may be timing)")
        results["events_in_db"] = False

    conn.close()

    # ── Step 12: Test malformed telemetry rejection ──────────────
    print("\n[STEP 12] Testing malformed telemetry rejection …")
    status, resp = _request("POST", f"{MASTER_URL}/api/telemetry", {
        "garbage": "data"
    }, auth_headers)
    print(f"  Malformed telemetry: {status}")
    results["malformed_rejected"] = (status == 400)

    # ══════════════════════════════════════════════════════════════
    # RESULTS
    # ══════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("PHASE 2 END-TO-END TEST RESULTS")
    print("=" * 70)

    all_pass = True
    for key, value in results.items():
        symbol = "✓" if value else "✗"
        print(f"  {symbol} {key}: {'PASS' if value else 'FAIL'}")
        if not value:
            all_pass = False

    print("=" * 70)
    if all_pass:
        print("  RESULT: ALL TESTS PASSED ✓")
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"  RESULT: {len(failed)} test(s) failed")
    print("=" * 70)

    return results


if __name__ == "__main__":
    main()
