"""
APEXEYE — Regression Test Suite for Log Timezone & Custom Block Page Rendering

Covers:
1. Timezone: UTC → local conversion dynamically (machine/operator timezone)
2. Timezone: Correct display of timestamps in Master API & Client ring buffer
3. Timezone: Existing chronological ordering preserved (SQL query ordering matches UTC timeline)
4. Timezone: No double conversion (idempotent serialization)
5. Timezone: No timezone shift when timestamp is already local / timezone-aware
6. Block Server: HTTP port 80 delivers APEXEYE 403 HTML block page over IPv4 (127.0.0.1) & IPv6 (::1)
7. Block Server: Clean TCP shutdown without RST (no ERR_CONNECTION_RESET)
8. Block Server: HTTPS port 443 cleanly rejects TLS handshake with TLS Alert (zero-MITM)
"""

import os
import socket
import struct
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import pytest

from master.app.database import init_database, get_connection
from master.app.services.firewall_service import FirewallService
from master.app.utils.timezone import utc_to_local_display, get_local_timezone
from client.app.services.firewall_agent import FirewallAgent
from client.app.services.block_server import (
    BlockServer,
    _TLS_ALERT_RECORD,
    _graceful_close,
)
from client.app.services.block_page import render_block_page


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_client_hello(server_name: str) -> bytes:
    """Construct a minimal valid TLS ClientHello with SNI extension."""
    sni_bytes = server_name.encode("utf-8")
    sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions_block = struct.pack("!H", len(sni_ext)) + sni_ext
    client_version = bytes([0x03, 0x03])
    random_bytes = b"\xaa" * 32
    session_id = bytes([0x20]) + (b"\xbb" * 32)
    cipher_suites = bytes([0x00, 0x02, 0x13, 0x01])
    compression = bytes([0x01, 0x00])
    handshake_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_block
    handshake_header = bytes([0x01]) + struct.pack("!I", len(handshake_body))[1:]
    handshake_record = handshake_header + handshake_body
    tls_record_header = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(handshake_record))
    return tls_record_header + handshake_record


# ── Timezone Regression Tests ────────────────────────────────────────────────

class TestFirewallTimezone:
    """Validates dynamic UTC to local display, ordering, idempotence, and no shift."""

    def test_utc_to_local_conversion_basic(self):
        """Test conversion of naive UTC string to local machine timezone."""
        local_tz = get_local_timezone()
        # Given a known UTC time
        utc_dt = datetime(2026, 9, 11, 9, 31, 0, tzinfo=timezone.utc)
        expected_local = utc_dt.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")

        # Convert naive string stored in DB
        result = utc_to_local_display("2026-09-11 09:31:00")
        assert result == expected_local

    def test_utc_to_local_iso_with_z(self):
        """Test conversion of ISO string ending with 'Z'."""
        local_tz = get_local_timezone()
        utc_dt = datetime(2026, 9, 11, 10, 0, 0, tzinfo=timezone.utc)
        expected_local = utc_dt.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")

        result = utc_to_local_display("2026-09-11T10:00:00Z")
        assert result == expected_local

    def test_no_timezone_shift_when_already_local(self):
        """If a timestamp already has local timezone offset, no shift occurs."""
        local_tz = get_local_timezone()
        now_local = datetime.now().astimezone(local_tz)
        local_iso = now_local.isoformat()
        expected_str = now_local.strftime("%Y-%m-%d %H:%M:%S")

        result = utc_to_local_display(local_iso)
        assert result == expected_str

    def test_idempotent_no_double_conversion(self, tmp_path):
        """Calling serialize_log repeatedly does not re-shift timestamps."""
        init_database()
        svc = FirewallService()

        # Log an event
        logged = svc.log_blocked_attempt(
            device_id="DEV-TZ-01",
            device_name="Operator-PC",
            domain="timezone-check.com",
            policy_version=1,
        )
        assert logged is not None
        first_display = logged["timestamp"]
        raw_utc = logged["timestamp_utc"]

        # Call serialize_log again on the already serialized entry
        second = svc.serialize_log(logged)
        assert second["timestamp"] == first_display
        assert second["timestamp_utc"] == raw_utc

        # Even if _is_serialized flag is stripped, timestamp_utc prevents double conversion
        stripped = dict(second)
        stripped.pop("_is_serialized", None)
        third = svc.serialize_log(stripped)
        assert third["timestamp"] == first_display
        assert third["timestamp_utc"] == raw_utc

    def test_timestamp_chronological_ordering_preserved(self):
        """Database ordering (ORDER BY timestamp DESC) matches chronological order."""
        init_database()
        svc = FirewallService()

        conn = get_connection()
        try:
            conn.execute("DELETE FROM firewall_logs WHERE domain LIKE 'order-test%.com';")
            # Insert 3 logs with explicit chronological UTC timestamps
            conn.execute(
                "INSERT INTO firewall_logs (device_id, device_name, domain, url, timestamp, action, policy_version, dedup_key) "
                "VALUES ('DEV-ORD', 'PC', 'order-test-1.com', '', '2026-09-11 08:00:00', 'BLOCKED', 1, 'k1');"
            )
            conn.execute(
                "INSERT INTO firewall_logs (device_id, device_name, domain, url, timestamp, action, policy_version, dedup_key) "
                "VALUES ('DEV-ORD', 'PC', 'order-test-2.com', '', '2026-09-11 09:00:00', 'BLOCKED', 1, 'k2');"
            )
            conn.execute(
                "INSERT INTO firewall_logs (device_id, device_name, domain, url, timestamp, action, policy_version, dedup_key) "
                "VALUES ('DEV-ORD', 'PC', 'order-test-3.com', '', '2026-09-11 10:00:00', 'BLOCKED', 1, 'k3');"
            )
            conn.commit()
        finally:
            conn.close()

        logs = svc.get_logs(device_id="DEV-ORD", limit=10)
        assert len(logs) == 3
        # Most recent first
        assert logs[0]["domain"] == "order-test-3.com"
        assert logs[1]["domain"] == "order-test-2.com"
        assert logs[2]["domain"] == "order-test-1.com"

        # Local timestamps are strictly decreasing
        local_tz = get_local_timezone()
        t3 = datetime.strptime(logs[0]["timestamp"], "%Y-%m-%d %H:%M:%S")
        t2 = datetime.strptime(logs[1]["timestamp"], "%Y-%m-%d %H:%M:%S")
        t1 = datetime.strptime(logs[2]["timestamp"], "%Y-%m-%d %H:%M:%S")
        assert t3 > t2 > t1

    def test_client_recent_blocks_consistent_with_master(self):
        """Client ring buffer records local timestamp and matches Master display."""
        mock_conn = MagicMock()
        mock_conn.is_authenticated = True
        mock_conn._device_id = "CLIENT-TZ-TEST"
        stop_event = threading.Event()

        agent = FirewallAgent(mock_conn, stop_event)
        agent.report_blocked_attempt(
            domain="client-tz-domain.com",
            url="http://client-tz-domain.com/",
            destination_ip="127.0.0.1",
        )

        recent = agent.get_recent_blocks(1)
        assert len(recent) == 1
        entry = recent[0]
        assert entry["domain"] == "client-tz-domain.com"
        assert "timestamp" in entry
        assert "timestamp_utc" in entry
        # timestamp is local time, not UTC
        local_tz = get_local_timezone()
        utc_dt = datetime.strptime(entry["timestamp_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        expected_local = utc_dt.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")
        assert entry["timestamp"] == expected_local


# ── Block Server HTTP Rendering & HTTPS Rejection Tests ──────────────────────

class TestBlockServerRenderingAndSecurity:
    """Validates HTTP block page rendering and zero-MITM HTTPS rejection."""

    @pytest.fixture
    def active_block_server(self):
        """Setup a BlockServer on ephemeral ports with a test policy."""
        # Find two unused ports
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            p_http = s1.getsockname()[1]
            p_https = s2.getsockname()[1]

        mock_agent = MagicMock()
        mock_agent.is_policy_enabled = True
        mock_agent.policy_version = 42
        mock_agent._current_policy = {
            "enabled": True,
            "version": 42,
            "blocked_domains": ["blocked-test.site", "restricted-zone.org"],
        }
        mock_agent._conn = MagicMock()
        mock_agent._conn._device_id = "TEST-DEV-BLOCK"

        bs = BlockServer(
            firewall_agent=mock_agent,
            http_port=p_http,
            https_port=p_https,
        )
        ok, err = bs.start()
        assert ok, f"BlockServer failed to start: {err}"
        time.sleep(0.1)

        yield bs, mock_agent, p_http, p_https

        bs.stop()

    def test_http_blocked_domain_renders_custom_block_page_ipv4(self, active_block_server):
        """HTTP GET to blocked domain returns HTTP 403 Forbidden with APEXEYE block page."""
        bs, agent, p_http, _ = active_block_server

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", p_http))

        # Send standard browser HTTP request
        req = (
            "GET /login HTTP/1.1\r\n"
            "Host: blocked-test.site\r\n"
            "User-Agent: Mozilla/5.0 APEXEYE-Test\r\n"
            "Accept: text/html\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        s.sendall(req)

        # Receive complete response until server FIN
        resp_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp_data += chunk
        s.close()

        resp_text = resp_data.decode("utf-8", errors="replace")

        # Assert status line
        assert "HTTP/1.1 403 Forbidden" in resp_text
        # Assert Content-Type
        assert "Content-Type: text/html" in resp_text
        # Assert Cache-Control
        assert "Cache-Control: no-cache" in resp_text
        # Assert APEXEYE branding in HTML body
        assert "APEXEYE" in resp_text
        assert "Access Blocked" in resp_text
        assert "blocked-test.site" in resp_text
        # Assert reported to agent
        agent.report_blocked_attempt.assert_called_once()

    def test_http_blocked_domain_renders_custom_block_page_ipv6(self, active_block_server):
        """HTTP GET to blocked domain over IPv6 (::1) returns 403 block page."""
        bs, agent, p_http, _ = active_block_server

        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.settimeout(3.0)
            s6.connect(("::1", p_http))
        except OSError:
            pytest.skip("IPv6 loopback not available in this environment")

        req = (
            "GET /download HTTP/1.1\r\n"
            "Host: restricted-zone.org\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        s6.sendall(req)

        resp_data = b""
        while True:
            chunk = s6.recv(4096)
            if not chunk:
                break
            resp_data += chunk
        s6.close()

        resp_text = resp_data.decode("utf-8", errors="replace")
        assert "HTTP/1.1 403 Forbidden" in resp_text
        assert "restricted-zone.org" in resp_text
        assert "APEXEYE" in resp_text

    def test_http_no_connection_reset_on_graceful_close(self, active_block_server):
        """Verify socket shutdown is graceful without RST."""
        bs, agent, p_http, _ = active_block_server

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", p_http))

        req = (
            "GET / HTTP/1.1\r\n"
            "Host: blocked-test.site\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        s.sendall(req)

        # Read full response until server FIN / EOF
        full_resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            full_resp += chunk

        assert len(full_resp) > 0
        assert b"HTTP/1.1 403 Forbidden" in full_resp
        assert b"APEXEYE" in full_resp

        # Further recv immediately returns empty bytes (graceful FIN), NOT ConnectionResetError
        more = s.recv(1024)
        assert more == b""
        s.close()

    def test_https_zero_mitm_tls_alert_rejection(self, active_block_server):
        """HTTPS ClientHello to blocked domain returns TLS Alert; no fake cert (Zero-MITM)."""
        bs, agent, _, p_https = active_block_server

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", p_https))

        # Send real TLS ClientHello with SNI = "blocked-test.site"
        hello = make_client_hello("blocked-test.site")
        s.sendall(hello)

        # Server should respond with standard TLS Fatal Alert (0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31)
        resp = s.recv(1024)
        s.close()

        assert resp == _TLS_ALERT_RECORD
        # Confirm attempt was logged
        agent.report_blocked_attempt.assert_called()
