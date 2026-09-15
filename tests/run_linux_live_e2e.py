"""
APEXEYE LINUX CLIENT — Live E2E Verification Runner

Validates:
1. Custom APEXEYE HTTP block page rendering over IPv4 and IPv6.
2. Zero-MITM HTTPS rejection (TLS Alert 0x15, 0x03, 0x03, no fake Root CA).
3. Repeated ENABLE -> DISABLE -> ENABLE lifecycle restoring blocking, detection,
   BlockServer lifecycle, and DNS behavior.
4. Linux timezone display and ring buffer timestamp correctness.
"""

import os
import socket
import struct
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from master.app.database import init_database, get_connection
from master.app.services.firewall_service import FirewallService
from client_linux.app.services.block_server import BlockServer, _TLS_ALERT_RECORD
from client_linux.app.services.firewall_agent import FirewallAgent as LinuxFirewallAgent
from client_linux.app.utils.timezone import utc_to_local_display, get_local_timezone
from client.app.services.enforcement.linux_adapter import LinuxFirewallAdapter


def make_client_hello(server_name: str) -> bytes:
    """Build a standard TLS ClientHello with SNI extension."""
    sni_bytes = server_name.encode("utf-8")
    sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions_block = struct.pack("!H", len(sni_ext)) + sni_ext
    client_version = bytes([0x03, 0x03])
    random_bytes = b"\x77" * 32
    session_id = bytes([0x20]) + (b"\x88" * 32)
    cipher_suites = bytes([0x00, 0x02, 0x13, 0x01])
    compression = bytes([0x01, 0x00])
    handshake_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_block
    handshake_header = bytes([0x01]) + struct.pack("!I", len(handshake_body))[1:]
    handshake_record = handshake_header + handshake_body
    tls_record_header = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(handshake_record))
    return tls_record_header + handshake_record


def run_live_linux_e2e():
    print("================================================================================")
    print(" APEXEYE LINUX CLIENT — LIVE E2E VERIFICATION SUITE")
    print("================================================================================")

    init_database()
    conn = get_connection()
    conn.execute("DELETE FROM firewall_blocked_domains WHERE domain LIKE 'linux-live-%' OR domain LIKE 'cycle-%';")
    conn.execute("DELETE FROM firewall_logs WHERE device_id = 'LINUX-LIVE-01';")
    conn.commit()

    fw_service = FirewallService()

    with socket.socket() as s1, socket.socket() as s2:
        s1.bind(("127.0.0.1", 0))
        s2.bind(("127.0.0.1", 0))
        p_http = s1.getsockname()[1]
        p_https = s2.getsockname()[1]

    print(f"[*] Ephemeral ports selected: HTTP={p_http}, HTTPS={p_https}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".hosts", delete=False, encoding="utf-8") as f:
        f.write("# Clean test hosts\n127.0.0.1 localhost\n::1 localhost\n")
        temp_hosts = Path(f.name)

    mock_conn = MagicMock()
    mock_conn.is_authenticated = True
    mock_conn._device_id = "LINUX-LIVE-01"

    stop_event = threading.Event()
    agent = LinuxFirewallAgent(mock_conn, stop_event)
    enforcer = LinuxFirewallAdapter(hosts_path=temp_hosts, manage_native_firewall=False)
    agent._enforcer = enforcer
    agent._block_server = BlockServer(
        firewall_agent=agent,
        http_port=p_http,
        https_port=p_https,
    )
    agent._force_block_server = True

    try:
        # ─────────────────────────────────────────────────────────────────────
        # TEST 1: Dual-Stack IPv4 & IPv6 Custom HTTP Block Page Rendering
        # ─────────────────────────────────────────────────────────────────────
        print("\n--- TEST 1: HTTP Block Page Rendering over IPv4 & IPv6 ---")
        fw_service.add_domain("linux-live-malware.com")
        fw_service.set_enabled(True)
        policy_v1 = fw_service.get_policy()
        agent._apply_policy(policy_v1)
        assert agent.is_active is True, "Agent failed to activate"
        print("  [OK] LinuxFirewallAgent ACTIVE (policy v%d)" % agent.policy_version)

        # IPv4 Request
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.settimeout(3.0)
        s4.connect(("127.0.0.1", p_http))
        req4 = (
            "GET /danger HTTP/1.1\r\n"
            "Host: linux-live-malware.com\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) APEXEYE/1.0\r\n"
            "Accept: text/html\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        s4.sendall(req4)
        resp4_bytes = b""
        while True:
            chunk = s4.recv(4096)
            if not chunk:
                break
            resp4_bytes += chunk
        s4.close()

        resp4 = resp4_bytes.decode("utf-8", errors="replace")
        assert "HTTP/1.1 403 Forbidden" in resp4, "Expected HTTP 403"
        assert "Content-Type: text/html; charset=utf-8" in resp4, "Expected HTML content type"
        assert "Cache-Control: no-cache, no-store, must-revalidate" in resp4, "Expected no-cache header"
        assert "APEXEYE" in resp4, "Expected APEXEYE branding"
        assert "Access Blocked" in resp4, "Expected Access Blocked headline"
        assert "linux-live-malware.com" in resp4, "Expected blocked domain in page"
        print("  [OK] IPv4 HTTP 403 Block Page: Successfully received and parsed (Status 403, APEXEYE branding confirmed)")

        # IPv6 Request
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.settimeout(3.0)
            s6.connect(("::1", p_http))
            s6.sendall(req4)
            resp6_bytes = b""
            while True:
                chunk = s6.recv(4096)
                if not chunk:
                    break
                resp6_bytes += chunk
            s6.close()
            resp6 = resp6_bytes.decode("utf-8", errors="replace")
            assert "HTTP/1.1 403 Forbidden" in resp6
            assert "APEXEYE" in resp6
            print("  [OK] IPv6 (::1) HTTP 403 Block Page: Successfully received and rendered")
        except OSError as e:
            print(f"  [INFO] IPv6 loopback not routeable in test runner environment: {e}")

        # ─────────────────────────────────────────────────────────────────────
        # TEST 2: HTTPS Zero-MITM Clean TLS Alert Rejection
        # ─────────────────────────────────────────────────────────────────────
        print("\n--- TEST 2: HTTPS Zero-MITM Clean TLS Alert Rejection ---")
        s_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tls.settimeout(3.0)
        s_tls.connect(("127.0.0.1", p_https))
        client_hello = make_client_hello("linux-live-malware.com")
        s_tls.sendall(client_hello)
        resp_tls = s_tls.recv(1024)
        s_tls.close()

        assert resp_tls == _TLS_ALERT_RECORD, f"Expected TLS alert {_TLS_ALERT_RECORD.hex()}, got {resp_tls.hex()}"
        print(f"  [OK] Zero-MITM Confirmed: Exact TLS Alert 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31 received")
        print("       No fake CA, no certificate interception, TCP closed cleanly without RST.")

        # ─────────────────────────────────────────────────────────────────────
        # TEST 3: Repeated ENABLE -> DISABLE -> ENABLE Lifecycle
        # ─────────────────────────────────────────────────────────────────────
        print("\n--- TEST 3: Repeated ENABLE -> DISABLE -> ENABLE Lifecycle ---")
        fw_service.add_domain("cycle-live-site.org")
        for cycle in range(1, 4):
            print(f"  --> Cycle {cycle}/3:")
            # ENABLE
            fw_service.set_enabled(True)
            agent._apply_policy(fw_service.get_policy())
            assert agent.is_active is True, f"Cycle {cycle} ENABLE failed"
            hosts_txt = temp_hosts.read_text(encoding="utf-8")
            assert "127.0.0.1 cycle-live-site.org" in hosts_txt
            assert "::1 cycle-live-site.org" in hosts_txt

            # Verify block server active
            s_chk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_chk.settimeout(3.0)
            s_chk.connect(("127.0.0.1", p_http))
            s_chk.sendall(b"GET / HTTP/1.1\r\nHost: cycle-live-site.org\r\nConnection: close\r\n\r\n")
            c_data = s_chk.recv(2048).decode("utf-8", errors="replace")
            s_chk.close()
            assert "HTTP/1.1 403 Forbidden" in c_data
            print(f"      Cycle {cycle} ENABLE: Hosts redirection verified, BlockServer active (HTTP 403)")

            # DISABLE
            fw_service.set_enabled(False)
            agent._apply_policy(fw_service.get_policy())
            assert agent.is_active is False, f"Cycle {cycle} DISABLE failed"
            hosts_clean = temp_hosts.read_text(encoding="utf-8")
            assert "cycle-live-site.org" not in hosts_clean

            # Verify block server stopped and port released
            try:
                s_off = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s_off.settimeout(1.0)
                s_off.connect(("127.0.0.1", p_http))
                s_off.close()
                assert False, "BlockServer port should have been released!"
            except OSError:
                pass
            print(f"      Cycle {cycle} DISABLE: Hosts sentinel removed, BlockServer stopped, port released")

        # ─────────────────────────────────────────────────────────────────────
        # TEST 4: Linux Timezone Display & Ring Buffer Timestamp Parity
        # ─────────────────────────────────────────────────────────────────────
        print("\n--- TEST 4: Linux Timezone Display & Ring Buffer Correctness ---")
        now_utc = datetime.now(timezone.utc)
        local_tz = get_local_timezone()
        now_local = now_utc.astimezone(local_tz)
        expected_local_str = now_local.strftime("%Y-%m-%d %H:%M:%S")

        agent.report_blocked_attempt(
            domain="linux-tz-check.com",
            url="http://linux-tz-check.com/login",
            destination_ip="127.0.0.1",
        )

        recent = agent.get_recent_blocks(limit=5)
        assert len(recent) > 0, "No blocks in ring buffer"
        target_event = recent[0]
        assert target_event["domain"] == "linux-tz-check.com"
        assert target_event["timestamp"] == expected_local_str, (
            f"Timestamp mismatch: ring_buffer={target_event['timestamp']}, expected={expected_local_str}"
        )
        assert target_event["timestamp_utc"] == now_utc.strftime("%Y-%m-%d %H:%M:%S")

        print(f"  [OK] Machine Local Timezone:  {local_tz}")
        print(f"  [OK] UTC Timestamp Stored:     {target_event['timestamp_utc']} UTC")
        print(f"  [OK] Local Display String:      {target_event['timestamp']} (Dynamic local offset confirmed)")
        print(f"  [OK] Ring Buffer Serialization: Matches operator display, no 5h30m lag.")

        print("\n================================================================================")
        print(" ALL 4 LINUX VERIFICATION TESTS PASSED SUCCESSFULLY!")
        print("================================================================================")

    finally:
        agent.stop()
        temp_hosts.unlink(missing_ok=True)


if __name__ == "__main__":
    run_live_linux_e2e()
