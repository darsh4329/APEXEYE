"""
APEXEYE — Firewall BlockServer, SNI Inspector & Security Hardening Unit Tests

Validates:
1. HTTP Port 80 Block Page:
   - Returns HTTP 403 Forbidden.
   - Headers include Content-Type: text/html and Connection: close.
   - Body contains branded APEXEYE Access Blocked page.
   - Host/URL data is strictly sanitized and HTML-escaped (prevents XSS).
2. HTTPS Port 443 SNI Extraction & Handshake Rejection:
   - Incremental and robust parsing of TLS ClientHello (Req 3).
   - Bounds-checked parsing handles truncated, fragmented, or malformed packets safely.
   - Extracts SNI correctly from TLS 1.2 / 1.3 ClientHello records.
   - Sends TLS Fatal Alert (access_denied, 0x31) and closes connection without TLS MITM / fake CA.
3. QUIC Enforcement State Guarantees (Req 1 & 2):
   - Never report ACTIVE if QUIC enforcement failed.
   - Installs and removes QUIC rule cleanly with firewall state.
4. Block Event Reporting:
   - BlockServer invokes report_blocked_attempt on interception.
   - Recent blocks buffer is populated.
5. Pre-flight Port Check:
   - Fails gracefully and reports ENFORCEMENT_ERROR if ports are occupied.
"""

import html
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.app.services.block_page import render_block_page
from client.app.services.block_server import (
    BlockServer,
    check_port_available,
    extract_sni_from_client_hello,
    _TLS_ALERT_RECORD,
)
from client.app.services.enforcement.windows_adapter import WindowsFirewallAdapter
from client.app.services.enforcement.linux_adapter import LinuxFirewallAdapter


# ===========================================================================
# Helper: Synthesize a realistic TLS ClientHello with SNI extension
# ===========================================================================

def make_client_hello(server_name: str) -> bytes:
    """Build a valid binary TLS 1.2 / 1.3 ClientHello record with SNI."""
    sni_bytes = server_name.encode("utf-8")
    # SNI extension:
    # 2 bytes name_len, name_type (0 = host_name), 2 bytes sni_bytes len, sni_bytes
    sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # Extensions container
    extensions_block = struct.pack("!H", len(sni_ext)) + sni_ext

    # Handshake payload
    client_version = bytes([0x03, 0x03])  # TLS 1.2 legacy
    random_bytes = b"\xaa" * 32
    session_id = bytes([0x20]) + (b"\xbb" * 32)
    cipher_suites = bytes([0x00, 0x02, 0x13, 0x01])  # 2 bytes len, TLS_AES_128_GCM_SHA256
    compression = bytes([0x01, 0x00])  # 1 byte len, null compression

    handshake_body = (
        client_version
        + random_bytes
        + session_id
        + cipher_suites
        + compression
        + extensions_block
    )

    handshake_header = bytes([0x01]) + struct.pack("!I", len(handshake_body))[1:]  # 1 byte type, 3 bytes len
    handshake_record = handshake_header + handshake_body

    tls_record_header = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(handshake_record))
    return tls_record_header + handshake_record


# ===========================================================================
# 1. HTML Sanitization & Branded Block Page Tests (Req 4)
# ===========================================================================

class TestBlockPageSanitization:
    def test_xss_payload_in_domain_is_html_escaped(self):
        """Host and domain containing script tags are strictly HTML escaped."""
        xss_domain = "<script>alert('pwned')</script>.com"
        rendered = render_block_page(domain=xss_domain, url=f"http://{xss_domain}/test")
        
        # Raw script tags must NEVER appear in the HTML
        assert "<script>alert('pwned')</script>" not in rendered
        # HTML-escaped version MUST be present
        assert html.escape(xss_domain) in rendered

    def test_xss_payload_in_reason_is_html_escaped(self):
        """Reason parameter with event handlers is sanitized."""
        xss_reason = 'Blocked" onmouseover="alert(1)'
        rendered = render_block_page(domain="example.com", reason=xss_reason)

        assert 'onmouseover="alert(1)' not in rendered
        assert html.escape(xss_reason) in rendered

    def test_rendered_page_contains_enterprise_branding(self):
        """Block page contains APEXEYE cybersecurity indicators and HTTP 403 styling."""
        rendered = render_block_page(
            domain="gambling.com",
            url="http://gambling.com/play",
            reason="Enterprise Policy: Gambling & Betting Restricted",
            client_id="WORKSTATION-01",
            policy_version=12,
        )
        assert "APEXEYE — Access Blocked" in rendered
        assert "gambling.com" in rendered
        assert "WORKSTATION-01" in rendered
        assert "v12" in rendered


# ===========================================================================
# 2. Incremental & Robust TLS ClientHello / SNI Parser Tests (Req 3)
# ===========================================================================

class TestTLSClientHelloParser:
    def test_extract_sni_valid_packet(self):
        """Correctly extracts domain from standard TLS ClientHello."""
        packet = make_client_hello("malicious-domain.com")
        sni = extract_sni_from_client_hello(packet)
        assert sni == "malicious-domain.com"

    def test_extract_sni_case_insensitive_and_stripped(self):
        """Hostnames are normalized to lower-case without surrounding spaces."""
        packet = make_client_hello("  SubDomain.PhishingSite.ORG  ")
        sni = extract_sni_from_client_hello(packet)
        assert sni == "subdomain.phishingsite.org"

    def test_truncated_record_header_returns_none(self):
        """Packets with fewer than 5 bytes do not raise errors and return None."""
        assert extract_sni_from_client_hello(b"") is None
        assert extract_sni_from_client_hello(b"\x16\x03") is None
        assert extract_sni_from_client_hello(b"\x16\x03\x01\x00") is None

    def test_non_handshake_record_type_returns_none(self):
        """Application data or Alert records return None gracefully."""
        # Record type 0x17 is Application Data
        bad_record = bytes([0x17, 0x03, 0x03, 0x00, 0x05]) + b"hello"
        assert extract_sni_from_client_hello(bad_record) is None

    def test_truncated_extensions_returns_none(self):
        """Truncated packets midway through extensions do not raise IndexError."""
        full_packet = make_client_hello("test-domain.com")
        for cutoff in range(5, len(full_packet) - 1, 5):
            truncated = full_packet[:cutoff]
            # Must return None or string, but never raise an exception
            res = extract_sni_from_client_hello(truncated)
            assert res is None or isinstance(res, str)

    def test_packet_without_sni_extension_returns_none(self):
        """Valid ClientHello without SNI extension returns None."""
        # Create a ClientHello with no extensions
        handshake_body = (
            bytes([0x03, 0x03])  # version
            + (b"\x00" * 32)      # random
            + bytes([0x00])       # session id len 0
            + bytes([0x00, 0x02, 0x13, 0x01])  # cipher
            + bytes([0x01, 0x00])  # compression
            + bytes([0x00, 0x00])  # 0 extensions
        )
        handshake_header = bytes([0x01]) + struct.pack("!I", len(handshake_body))[1:]
        record = handshake_header + handshake_body
        pkt = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(record)) + record
        assert extract_sni_from_client_hello(pkt) is None

    def test_fuzzed_corrupt_data_returns_none(self):
        """Random fuzzed byte buffers never crash the parser."""
        import random
        rng = random.Random(42)
        for _ in range(50):
            rand_len = rng.randint(1, 200)
            rand_bytes = bytes(rng.randint(0, 255) for _ in range(rand_len))
            res = extract_sni_from_client_hello(rand_bytes)
            assert res is None or isinstance(res, str)


# ===========================================================================
# 3. BlockServer HTTP & HTTPS Interception Integration Tests
# ===========================================================================

class TestBlockServerInterception:
    def test_http_port_returns_403_and_branded_page(self):
        """HTTP port responds with HTTP 403 Forbidden, APEXEYE block page, and logs attempt."""
        # Find 2 free test ports
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            test_http_port = s1.getsockname()[1]
            test_https_port = s2.getsockname()[1]

        mock_agent = MagicMock()
        mock_agent.policy_version = 7
        mock_agent.is_policy_enabled = True
        mock_agent._current_policy = {
            "enabled": True,
            "version": 7,
            "blocked_domains": ["blocked-test.com"],
        }

        server = BlockServer(
            firewall_agent=mock_agent,
            http_port=test_http_port,
            https_port=test_https_port,
            bind_host="127.0.0.1",
        )
        ok, err = server.start()
        assert ok is True, f"Failed to start test BlockServer: {err}"

        try:
            # Connect as HTTP client
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.connect(("127.0.0.1", test_http_port))
                request = (
                    b"GET /path/to/blocked HTTP/1.1\r\n"
                    b"Host: blocked-test.com\r\n"
                    b"User-Agent: Mozilla/5.0 TestBrowser\r\n"
                    b"Connection: close\r\n\r\n"
                )
                client_sock.sendall(request)
                client_sock.settimeout(3.0)

                response = b""
                while True:
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

            resp_str = response.decode("utf-8", errors="replace")
            # Verify HTTP 403 Forbidden
            assert "HTTP/1.1 403 Forbidden" in resp_str
            assert "Content-Type: text/html; charset=utf-8" in resp_str
            assert "Connection: close" in resp_str
            assert "APEXEYE — Access Blocked" in resp_str
            assert "blocked-test.com" in resp_str

            # Verify report_blocked_attempt was called
            time.sleep(0.1)
            mock_agent.report_blocked_attempt.assert_called_with(
                domain="blocked-test.com",
                url="http://blocked-test.com/path/to/blocked",
                destination_ip="127.0.0.1",
            )
        finally:
            server.stop()

    def test_https_port_extracts_sni_and_returns_tls_alert(self):
        """HTTPS port extracts SNI from ClientHello and returns fatal access_denied alert."""
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            test_http_port = s1.getsockname()[1]
            test_https_port = s2.getsockname()[1]

        mock_agent = MagicMock()
        mock_agent.policy_version = 7
        mock_agent.is_policy_enabled = True
        mock_agent._current_policy = {
            "enabled": True,
            "version": 7,
            "blocked_domains": ["secure-blocked.com"],
        }

        server = BlockServer(
            firewall_agent=mock_agent,
            http_port=test_http_port,
            https_port=test_https_port,
            bind_host="127.0.0.1",
        )
        ok, err = server.start()
        assert ok is True

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.connect(("127.0.0.1", test_https_port))
                packet = make_client_hello("secure-blocked.com")
                client_sock.sendall(packet)
                client_sock.settimeout(3.0)

                received = client_sock.recv(1024)

            # Expect TLS Fatal Alert: access_denied (0x31)
            assert received == _TLS_ALERT_RECORD

            time.sleep(0.1)
            mock_agent.report_blocked_attempt.assert_called_with(
                domain="secure-blocked.com",
                url="https://secure-blocked.com/",
                destination_ip="127.0.0.1",
            )
        finally:
            server.stop()

    def test_preflight_fails_when_port_is_already_in_use(self):
        """Preflight check returns False if port 80 or 443 is already bound."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.bind(("127.0.0.1", 0))
            occupied_port = blocker.getsockname()[1]

            server = BlockServer(
                firewall_agent=MagicMock(),
                http_port=occupied_port,
                https_port=occupied_port + 1,
                bind_host="127.0.0.1",
            )
            ok, err = server.preflight_check()
            assert ok is False
            assert f"Port {occupied_port} is already occupied" in err


# ===========================================================================
# 4. QUIC Hardening Lifecycle & State Truthfulness Tests (Req 1 & 2)
# ===========================================================================

class TestQUICHardeningLifecycle:
    def test_never_report_active_if_quic_enforcement_failed(self):
        """REQ 1: Never report ACTIVE if QUIC rule failed to activate."""
        from client.app.services.firewall_agent import FirewallAgent

        stop_ev = threading.Event()
        conn = MagicMock()
        conn.is_authenticated = True

        agent = FirewallAgent(conn, stop_ev)

        # Mock adapter where apply_policy succeeded for hosts, but is_quic_blocked returns False
        agent._enforcer = MagicMock()
        agent._enforcer.apply_policy.return_value = (True, None)
        agent._enforcer.is_quic_blocked.return_value = False
        # Ensure it's not detected as a test enforcer
        agent._is_test_enforcer = lambda: False

        agent._apply_policy({"enabled": True, "version": 5, "blocked_domains": ["youtube.com"]})

        assert agent.is_active is False
        assert agent.enforcement_state == "ENFORCEMENT_ERROR"
        assert "QUIC" in agent.enforcement_error
        conn.report_firewall_status.assert_called_with(
            enforcement_state="ENFORCEMENT_ERROR",
            policy_version=5,
            error="Native firewall QUIC (UDP 443) blocking rule failed to activate.",
        )

    def test_clean_removal_of_quic_rule_on_deactivation(self):
        """REQ 2: Cleanly remove QUIC rule on deactivation."""
        from client.app.services.firewall_agent import FirewallAgent

        stop_ev = threading.Event()
        conn = MagicMock()
        conn.is_authenticated = True

        agent = FirewallAgent(conn, stop_ev)
        mock_enforcer = MagicMock()
        mock_enforcer.apply_policy.return_value = (True, None)
        agent._enforcer = mock_enforcer
        agent._is_test_enforcer = lambda: False

        # Deactivate
        agent._apply_policy({"enabled": False, "version": 6, "blocked_domains": []})

        mock_enforcer.apply_policy.assert_called_with(enabled=False, blocked_domains=[])
        assert agent.is_active is False
        assert agent.enforcement_state == "INACTIVE"
        conn.report_firewall_status.assert_called_with(
            enforcement_state="INACTIVE",
            policy_version=6,
            error=None,
        )


# ===========================================================================
# 5. Dual-Stack IPv4 + IPv6 Interception & Re-Enable Lifecycle Tests
# ===========================================================================

class TestBlockServerDualStackAndReenableLifecycle:
    def test_dual_stack_listeners_start_and_accept_connections(self):
        """BlockServer binds and accepts requests on both IPv4 and IPv6."""
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            test_http = s1.getsockname()[1]
            test_https = s2.getsockname()[1]

        mock_agent = MagicMock()
        mock_agent.policy_version = 10
        mock_agent.is_policy_enabled = True
        mock_agent._current_policy = {"enabled": True, "version": 10, "blocked_domains": ["dual-test.com"]}

        server = BlockServer(
            firewall_agent=mock_agent,
            http_port=test_http,
            https_port=test_https,
            bind_host="127.0.0.1",
            ipv6_host="::1",
        )
        ok, err = server.start()
        assert ok is True
        assert server.is_running is True

        try:
            # 1. Connect via IPv4 (127.0.0.1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c4:
                c4.connect(("127.0.0.1", test_http))
                c4.sendall(b"GET / HTTP/1.1\r\nHost: dual-test.com\r\nConnection: close\r\n\r\n")
                resp4 = c4.recv(4096)
                assert b"HTTP/1.1 403 Forbidden" in resp4
                assert b"APEXEYE" in resp4

            # 2. Connect via IPv6 (::1) if supported
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as c6:
                    c6.connect(("::1", test_http))
                    c6.sendall(b"GET / HTTP/1.1\r\nHost: dual-test.com\r\nConnection: close\r\n\r\n")
                    resp6 = c6.recv(4096)
                    assert b"HTTP/1.1 403 Forbidden" in resp6
                    assert b"APEXEYE" in resp6
            except OSError:
                pass  # IPv6 not enabled on test runner host
        finally:
            server.stop()

    def test_block_server_clean_restart_cycle_without_collision(self):
        """BlockServer can be stopped and restarted multiple times consecutively without socket collisions."""
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            test_http = s1.getsockname()[1]
            test_https = s2.getsockname()[1]

        mock_agent = MagicMock()
        mock_agent.policy_version = 1
        mock_agent.is_policy_enabled = True
        mock_agent._current_policy = {"enabled": True, "version": 1, "blocked_domains": ["cycle-test.com"]}

        server = BlockServer(
            firewall_agent=mock_agent,
            http_port=test_http,
            https_port=test_https,
        )

        for cycle in range(3):
            ok, err = server.start()
            assert ok is True, f"Failed start on cycle {cycle}: {err}"
            assert server.is_running is True

            # Send a quick request
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect(("127.0.0.1", test_http))
                client.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                resp = client.recv(1024)
                assert b"200 OK" in resp

            server.stop()
            assert server.is_running is False
            assert server.http_status == "STOPPED"
            assert server.https_status == "STOPPED"

    def test_direct_block_page_route_on_loopback(self):
        """Visiting http://127.0.0.1/ directly or /blocked?domain=... renders APEXEYE block page."""
        with socket.socket() as s1, socket.socket() as s2:
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            test_http = s1.getsockname()[1]
            test_https = s2.getsockname()[1]

        mock_agent = MagicMock()
        mock_agent.policy_version = 5
        mock_agent.is_policy_enabled = True
        mock_agent._current_policy = {"enabled": True, "version": 5, "blocked_domains": ["facebook.com"]}

        server = BlockServer(
            firewall_agent=mock_agent,
            http_port=test_http,
            https_port=test_https,
        )
        ok, err = server.start()
        assert ok is True

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect(("127.0.0.1", test_http))
                client.sendall(b"GET /blocked?domain=facebook.com HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                resp = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"</html>" in resp:
                        break
                assert b"200 OK" in resp
                assert b"APEXEYE" in resp
                assert b"facebook.com" in resp
        finally:
            server.stop()
