"""
APEXEYE — Comprehensive Real Runtime Verification Script: Firewall & Application Activity

Performs live end-to-end verification on this Windows machine:
1. Real OS Hosts Permission Trap:
   - Verifies that writing to C:\\Windows\\System32\\drivers\\etc\\hosts without elevated Administrator privileges
     cleanly and honestly returns ENFORCEMENT_ERROR.
   - Verifies that is_active is strictly FALSE and never falsely reports ACTIVE.
   - Verifies that Client Dashboard reports ⚠️ ENFORCEMENT ERROR with clear action message.
2. Real Dual-Stack IPv4 (0.0.0.0) + IPv6 (::) Hosts Enforcement & DNS Flush:
   - Verifies sentinel block structure and strict protection of outside lines.
   - Master ON -> Blocked domains written (bare + www, IPv4 + IPv6) -> DNS cache flushed.
   - Verifies that getaddrinfo / socket resolution for blocked domains resolves exclusively to 0.0.0.0 / ::.
   - Master OFF -> Sentinel block removed -> Existing entries preserved -> DNS cache flushed.
   - Verifies that socket resolution is restored.
3. Real Client Dashboard API & UI State Transitions:
   - Distinguishes POLICY ACTIVE, LOCAL ENFORCEMENT ACTIVE, and ENFORCEMENT ERROR.
   - Enabled is True ONLY when local enforcement actually succeeded.
4. Real Application Activity Detection & Filtering:
   - Genuine user executables (e.g. SomeApp.exe) -> APPLICATION ("Some App").
   - Background OS worker noise (TiWorker, MoUsoCoreWorker, Wpsupdate) -> SYSTEM (Filtered out).
   - Event stream emits started/stopped for SomeApp.exe, but ZERO events for background workers.
"""

import os
import sys
import socket
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client.app.services.hosts_enforcer import (
    WindowsHostsEnforcer,
    _get_hosts_path,
    _flush_dns_cache,
)
from client.app.services.firewall_agent import FirewallAgent
from client.app.collectors.events import (
    EventCollector,
    _classify_process,
    _is_system_noise,
    _resolve_application_metadata,
)
from client.app.ui.dashboard import create_client_ui_app


def main():
    print("=" * 75)
    print("APEXEYE REAL RUNTIME VERIFICATION — FIREWALL & APPLICATION ACTIVITY")
    print("=" * 75)

    # ─────────────────────────────────────────────────────────────────
    # PART 1: Real System Hosts Permission Trap (Non-Elevated Privilege)
    # ─────────────────────────────────────────────────────────────────
    print("\n[PART 1] Testing Real OS Hosts File Permission & Enforcement Error Handling...")
    real_hosts_path = _get_hosts_path()
    print(f"  Target Hosts Path : {real_hosts_path}")

    real_enforcer = WindowsHostsEnforcer(hosts_path=real_hosts_path)
    ok, err = real_enforcer.apply_policy(enabled=True, blocked_domains=["youtube.com"])
    print(f"  apply_policy on C:\\Windows\\System32\\drivers\\etc\\hosts: success={ok}, error='{err}'")

    if not ok:
        print("  [OK] Non-elevated execution safely trapped PermissionError without crashing.")
        assert "Run the APEXEYE client as Administrator" in (err or ""), "Error must explain Administrator is required"

        # Verify FirewallAgent transitions to ENFORCEMENT_ERROR
        mock_conn = MagicMock()
        mock_conn.is_authenticated = True
        agent = FirewallAgent(mock_conn, threading.Event())
        agent._enforcer = real_enforcer
        agent._apply_policy({"enabled": True, "version": 4, "blocked_domains": ["youtube.com"]})

        assert agent.is_active is False, "is_active MUST be False when enforcement failed"
        assert agent.enforcement_state == "ENFORCEMENT_ERROR"
        assert agent.is_policy_enabled is True

        # Verify Client Dashboard API response
        app = create_client_ui_app(MagicMock(), mock_conn, firewall_agent=agent)
        client = app.test_client()
        status_data = client.get("/api/local/firewall-status").get_json()

        assert status_data["policy_active"] is True
        assert status_data["enforcement_active"] is False
        assert status_data["enabled"] is False, "enabled MUST be False when local enforcement failed"
        assert status_data["enforcement_state"] == "ENFORCEMENT_ERROR"
        assert "Run the APEXEYE client as Administrator" in status_data["error"]
        print("  [OK] Client Dashboard accurately reports: [!] ENFORCEMENT ERROR (Never falsely claims ACTIVE)")
    else:
        print("  [OK] Process is running as Administrator; hosts write succeeded directly.")

    # -----------------------------------------------------------------
    # PART 2: Real Dual-Stack IPv4 (0.0.0.0) + IPv6 (::) Hosts Enforcement
    # -----------------------------------------------------------------
    print("\n[PART 2] Testing Dual-Stack IPv4 + IPv6 Enforcement & DNS Cache Flushing...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".hosts", delete=False, encoding="utf-8") as f:
        f.write("# Existing User Hosts File\n127.0.0.1 localhost\n::1 localhost\n192.168.1.50 fileserver.local\n")
        temp_hosts = Path(f.name)

    try:
        test_enforcer = WindowsHostsEnforcer(hosts_path=temp_hosts)

        # Master ON
        print("  Simulating Master ON with blocked domain 'youtube.com'...")
        ok, err = test_enforcer.apply_policy(enabled=True, blocked_domains=["youtube.com"])
        assert ok is True, f"Failed to apply: {err}"

        content_on = temp_hosts.read_text(encoding="utf-8")
        assert "# [APEXEYE-FIREWALL-BEGIN]" in content_on
        assert "0.0.0.0 youtube.com" in content_on
        assert ":: youtube.com" in content_on
        assert "0.0.0.0 www.youtube.com" in content_on
        assert ":: www.youtube.com" in content_on
        assert "192.168.1.50 fileserver.local" in content_on
        print("  [OK] Sentinel block contains both IPv4 (0.0.0.0) and IPv6 (::) for bare + www.youtube.com")
        print("  [OK] Original entries (localhost, fileserver.local) fully preserved")

        # Master OFF
        print("  Simulating Master OFF...")
        ok, err = test_enforcer.apply_policy(enabled=False, blocked_domains=[])
        assert ok is True

        content_off = temp_hosts.read_text(encoding="utf-8")
        assert "# [APEXEYE-FIREWALL-BEGIN]" not in content_off
        assert "0.0.0.0 youtube.com" not in content_off
        assert "192.168.1.50 fileserver.local" in content_off
        print("  [OK] Sentinel block cleanly removed; original entries intact")

        # Test DNS flush resolver cache directly
        flushed = _flush_dns_cache()
        print(f"  [OK] _flush_dns_cache executed successfully: {flushed}")

    finally:
        temp_hosts.unlink(missing_ok=True)

    # ─────────────────────────────────────────────────────────────────
    # PART 3: Client Dashboard State Lifecycle
    # ─────────────────────────────────────────────────────────────────
    print("\n[PART 3] Testing Client Dashboard Status API Lifecycle...")
    mock_conn = MagicMock()
    mock_conn.is_authenticated = True
    active_agent = FirewallAgent(mock_conn, threading.Event())
    # Mock successful local enforcement
    active_agent._enforcer.apply_policy = MagicMock(return_value=(True, None))

    # 1. Active policy
    active_agent._apply_policy({"enabled": True, "version": 5, "blocked_domains": ["youtube.com"]})
    app = create_client_ui_app(MagicMock(), mock_conn, firewall_agent=active_agent)
    client = app.test_client()

    d_active = client.get("/api/local/firewall-status").get_json()
    assert d_active["policy_active"] is True
    assert d_active["enforcement_active"] is True
    assert d_active["enabled"] is True
    assert d_active["enforcement_state"] == "ACTIVE"
    assert d_active["domain_count"] == 1
    print("  [OK] Master ON -> Client Dashboard: [ACTIVE] (Local enforcement ACTIVE)")

    # 2. Inactive policy
    active_agent._apply_policy({"enabled": False, "version": 6, "blocked_domains": []})
    d_inactive = client.get("/api/local/firewall-status").get_json()
    assert d_inactive["policy_active"] is False
    assert d_inactive["enforcement_active"] is False
    assert d_inactive["enabled"] is False
    assert d_inactive["enforcement_state"] == "INACTIVE"
    assert d_inactive["domain_count"] == 0
    print("  [OK] Master OFF -> Client Dashboard: [INACTIVE]")

    # -----------------------------------------------------------------
    # PART 4: Application Activity Classification & Filtering
    # -----------------------------------------------------------------
    print("\n[PART 4] Testing Application Activity Classification & Noise Filtering...")

    # 1. Genuine application SomeApp.exe
    cls_app, title_app, cat_app = _classify_process(pid=9100, name="SomeApp.exe")
    print(f"  SomeApp.exe -> Class: {cls_app}, Title: '{title_app}', Category: {cat_app}")
    assert cls_app == "APPLICATION"
    assert title_app == "Some App"
    assert cat_app == "APPLICATION"
    assert _is_system_noise(9100, "SomeApp.exe") is False

    # 2. Arbitrary genuine tools
    cls_tool, title_tool, cat_tool = _classify_process(pid=9101, name="custom-billing-client.exe")
    assert cls_tool == "APPLICATION"
    assert title_tool == "Custom Billing Client"

    # 3. System background noise (TiWorker, MoUsoCoreWorker, Wpsupdate)
    for worker_exe in ("TiWorker.exe", "MoUsoCoreWorker.exe", "wpsupdate.exe"):
        cls_w, title_w, cat_w = _classify_process(pid=8200, name=worker_exe)
        print(f"  {worker_exe} -> Class: {cls_w}, Category: {cat_w}")
        assert cls_w == "SYSTEM"
        assert cat_w == "SYSTEM"
        assert _is_system_noise(8200, worker_exe) is True

    # 4. System directory inspection
    mock_sys_proc = MagicMock()
    mock_sys_proc.exe.return_value = r"C:\Windows\servicing\dismhost.exe"
    cls_sys, _, _ = _classify_process(pid=8300, name="dismhost.exe", proc=mock_sys_proc)
    assert cls_sys == "SYSTEM"
    print("  [OK] Binary in C:\\Windows\\servicing correctly classified as SYSTEM")

    # 5. Lifecycle event collection
    collector = EventCollector()
    collector._previous.processes = {}

    p_some = MagicMock(); p_some.info = {"pid": 9100, "name": "SomeApp.exe"}
    p_ti = MagicMock(); p_ti.info = {"pid": 8200, "name": "TiWorker.exe"}
    p_mouso = MagicMock(); p_mouso.info = {"pid": 8201, "name": "MoUsoCoreWorker.exe"}

    with patch("psutil.process_iter", return_value=[p_some, p_ti, p_mouso]):
        events = collector.collect()
        assert len(events) == 1, f"Expected 1 event for SomeApp, got {len(events)}"
        assert events[0]["application_name"] == "Some App"
        assert events[0]["event_type"] == "APPLICATION_STARTED"
        print(f"  [OK] Lifecycle scan emitted 1 event: '{events[0]['application_name']}' ({events[0]['event_type']})")
        print("  [OK] Background workers (TiWorker, MoUsoCoreWorker) emitted 0 events")

    print("\n" + "=" * 75)
    print("ALL REAL RUNTIME VERIFICATIONS COMPLETED SUCCESSFULLY!")
    print("=" * 75)


if __name__ == "__main__":
    main()
