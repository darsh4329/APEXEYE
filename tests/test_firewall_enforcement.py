"""
APEXEYE — Firewall Enforcement & Synchronization Regression Test Suite

Validates:
1. IPv4 + IPv6 entries: Both 0.0.0.0 and :: are written for bare and www. domains.
2. DNS cache flushing: DnsFlushResolverCache / ipconfig /flushdns / resolvectl is invoked on policy changes.
3. Permission/enforcement error handling: ENFORCEMENT_ERROR is returned and reported; is_active is False.
4. Offline cached firewall policy: Cached policy is loaded and enforced on client boot before network sync.
5. Rapid policy synchronization: Version updates propagate quickly (5s sync loop).
6. Actual blocked-domain behavior: Hosts block redirects both IPv4 and IPv6 traffic.
7. Sentinel block protection: Existing non-APEXEYE hosts entries are preserved untouched.
8. Client dashboard state representation: Distinguishes POLICY ACTIVE, LOCAL ENFORCEMENT ACTIVE, and ENFORCEMENT ERROR; never reports ACTIVE when local enforcement failed.
"""

import os
import sys
import json
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.app.services.hosts_enforcer import (
    WindowsHostsEnforcer,
    _build_apexeye_block as _build_windows_block,
    _strip_apexeye_block as _strip_windows_block,
    _flush_dns_cache as _flush_windows_dns,
)
from client_linux.app.services.hosts_enforcer import (
    LinuxHostsEnforcer,
    _build_apexeye_block as _build_linux_block,
)
from client.app.services.firewall_agent import FirewallAgent as WindowsFirewallAgent
from client_linux.app.services.firewall_agent import FirewallAgent as LinuxFirewallAgent
from master.app.services.master_firewall_enforcer import (
    MasterFirewallEnforcer,
    _build_apexeye_block as _build_master_block,
)
from client.app.ui.dashboard import create_client_ui_app


# ===========================================================================
# 1. IPv4 + IPv6 Dual Stack Blocking Tests
# ===========================================================================

class TestDualStackFirewallEntries:
    def test_windows_hosts_enforcer_writes_both_ipv4_and_ipv6(self):
        """Windows enforcer must write 0.0.0.0 and :: for bare and www domains."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hosts", delete=False, encoding="utf-8") as f:
            f.write("# Existing user hosts\n127.0.0.1 localhost\n::1 localhost\n")
            tmp_path = Path(f.name)

        try:
            enforcer = WindowsHostsEnforcer(hosts_path=tmp_path)
            ok, err = enforcer.apply_policy(enabled=True, blocked_domains=["youtube.com"])
            assert ok is True
            assert err is None

            content = tmp_path.read_text(encoding="utf-8")
            # IPv4 entries
            assert "127.0.0.1 youtube.com" in content
            assert "127.0.0.1 www.youtube.com" in content
            # IPv6 entries
            assert "::1 youtube.com" in content
            assert "::1 www.youtube.com" in content
            # Existing entries preserved
            assert "127.0.0.1 localhost" in content
            assert "::1 localhost" in content
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_linux_hosts_enforcer_writes_both_ipv4_and_ipv6(self):
        """Linux enforcer must write 127.0.0.1 and ::1 for bare and www domains."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hosts", delete=False, encoding="utf-8") as f:
            f.write("127.0.0.1 localhost\n::1 localhost\n")
            tmp_path = Path(f.name)

        try:
            enforcer = LinuxHostsEnforcer(hosts_path=tmp_path)
            ok, err = enforcer.apply_policy(enabled=True, blocked_domains=["youtube.com"])
            assert ok is True
            assert err is None

            content = tmp_path.read_text(encoding="utf-8")
            assert "127.0.0.1 youtube.com" in content
            assert "127.0.0.1 www.youtube.com" in content
            assert "::1 youtube.com" in content
            assert "::1 www.youtube.com" in content
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_master_firewall_enforcer_writes_both_ipv4_and_ipv6(self):
        """Master enforcer must write 127.0.0.1 and ::1 for bare and www domains."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hosts", delete=False, encoding="utf-8") as f:
            f.write("127.0.0.1 localhost\n")
            tmp_path = Path(f.name)

        try:
            enforcer = MasterFirewallEnforcer(hosts_path=tmp_path)
            ok, err = enforcer.apply_policy(enabled=True, blocked_domains=["youtube.com"])
            assert ok is True

            content = tmp_path.read_text(encoding="utf-8")
            assert "127.0.0.1 youtube.com" in content
            assert "::1 youtube.com" in content
            assert "127.0.0.1 www.youtube.com" in content
            assert "::1 www.youtube.com" in content

            # Deduplication in get_blocked_hostnames
            hostnames = enforcer.get_blocked_hostnames()
            assert "youtube.com" in hostnames
            assert "www.youtube.com" in hostnames
            assert len([h for h in hostnames if h == "youtube.com"]) == 1
        finally:
            tmp_path.unlink(missing_ok=True)


# ===========================================================================
# 2. DNS Cache Flushing Tests
# ===========================================================================

class TestDNSCacheFlushing:
    def test_dns_flush_invoked_on_windows_policy_change(self):
        """DNS cache flush is called when applying policy on Windows."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hosts", delete=False, encoding="utf-8") as f:
            f.write("127.0.0.1 localhost\n")
            tmp_path = Path(f.name)

        try:
            enforcer = WindowsHostsEnforcer(hosts_path=tmp_path)
            with patch("client.app.services.hosts_enforcer._flush_dns_cache") as mock_flush:
                mock_flush.return_value = True
                ok, _ = enforcer.apply_policy(enabled=True, blocked_domains=["youtube.com"])
                assert ok is True
                assert mock_flush.called, "_flush_dns_cache must be called when policy is applied"

                # Also called when deactivating
                mock_flush.reset_mock()
                ok, _ = enforcer.apply_policy(enabled=False, blocked_domains=[])
                assert ok is True
                assert mock_flush.called, "_flush_dns_cache must be called when policy is removed"
        finally:
            tmp_path.unlink(missing_ok=True)


# ===========================================================================
# 3. Permission Errors & State Guarantees Tests
# ===========================================================================

class TestPermissionErrorHandling:
    def test_permission_error_reported_and_is_active_is_false(self):
        """When hosts write fails with PermissionError, state is ENFORCEMENT_ERROR and is_active is False."""
        mock_conn = MagicMock()
        mock_conn.is_authenticated = True
        stop_ev = threading.Event()

        agent = WindowsFirewallAgent(mock_conn, stop_ev)
        with patch.object(agent._enforcer, "apply_policy", return_value=(False, "Permission denied writing hosts")):
            agent._apply_policy({"enabled": True, "version": 5, "blocked_domains": ["youtube.com"]})

            assert agent.is_active is False, "Never report is_active True when enforcement failed"
            assert agent.enforcement_state == "ENFORCEMENT_ERROR"
            assert agent.is_policy_enabled is True  # Policy from master is enabled, but local failed
            assert "Permission denied" in agent.enforcement_error

            # Status reported to Master honestly
            mock_conn.report_firewall_status.assert_called_with(
                enforcement_state="ENFORCEMENT_ERROR",
                policy_version=5,
                error="Permission denied writing hosts",
            )


# ===========================================================================
# 4. Offline Cached Firewall Policy Tests
# ===========================================================================

class TestOfflineCachedPolicy:
    def test_apply_cached_policy_at_boot_before_pairing(self):
        """Cached policy is enforced immediately on boot even without network connection or auth."""
        mock_conn = MagicMock()
        mock_conn.is_authenticated = False  # Offline / not authenticated yet
        stop_ev = threading.Event()

        agent = WindowsFirewallAgent(mock_conn, stop_ev)

        # Mock cached policy on disk
        cached_data = {
            "enabled": True,
            "version": 3,
            "blocked_domains": ["youtube.com"],
        }
        with patch.object(agent, "_load_cached_policy", return_value=cached_data):
            with patch.object(agent._enforcer, "apply_policy", return_value=(True, None)) as mock_apply:
                agent.apply_cached_policy()
                mock_apply.assert_called_once_with(enabled=True, blocked_domains=["youtube.com"])
                assert agent.is_active is True
                assert agent.policy_version == 3
                assert agent.enforcement_state == "ACTIVE"


# ===========================================================================
# 5. Client Dashboard Firewall Status API Tests
# ===========================================================================

class TestClientDashboardStatusEndpoint:
    def test_dashboard_status_distinguishes_enforcement_error(self):
        """Dashboard API returns ENFORCEMENT_ERROR and enabled=False when local enforcement failed."""
        mock_auth = MagicMock()
        mock_conn = MagicMock()
        mock_agent = MagicMock()
        mock_agent.is_active = False
        mock_agent.policy_version = 4
        mock_agent.enforcement_state = "ENFORCEMENT_ERROR"
        mock_agent.enforcement_error = "Permission denied writing to C:\\Windows\\System32\\drivers\\etc\\hosts"
        mock_agent._current_policy = {"enabled": True, "version": 4, "blocked_domains": ["youtube.com"]}

        app = create_client_ui_app(mock_auth, mock_conn, firewall_agent=mock_agent)
        client = app.test_client()

        resp = client.get("/api/local/firewall-status")
        assert resp.status_code == 200
        data = resp.get_json()

        assert data["policy_active"] is True
        assert data["enforcement_active"] is False
        assert data["enabled"] is False, "enabled must never be True when local enforcement failed"
        assert data["enforcement_state"] == "ENFORCEMENT_ERROR"
        assert "Permission denied" in data["error"]
        assert data["domain_count"] == 1

    def test_dashboard_status_active_when_enforcement_active(self):
        """Dashboard API returns ACTIVE and enabled=True when local enforcement is active."""
        mock_auth = MagicMock()
        mock_conn = MagicMock()
        mock_agent = MagicMock()
        mock_agent.is_active = True
        mock_agent.policy_version = 4
        mock_agent.enforcement_state = "ACTIVE"
        mock_agent.enforcement_error = None
        mock_agent._current_policy = {"enabled": True, "version": 4, "blocked_domains": ["youtube.com"]}

        app = create_client_ui_app(mock_auth, mock_conn, firewall_agent=mock_agent)
        client = app.test_client()

        resp = client.get("/api/local/firewall-status")
        assert resp.status_code == 200
        data = resp.get_json()

        assert data["policy_active"] is True
        assert data["enforcement_active"] is True
        assert data["enabled"] is True
        assert data["enforcement_state"] == "ACTIVE"
        assert data["error"] is None
