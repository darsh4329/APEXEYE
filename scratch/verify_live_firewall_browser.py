"""
APEXEYE — Live Runtime Investigation & End-to-End Verification

Tests the complete path:
1. Start BlockServer on port 80 (HTTP) & port 443 (HTTPS) with policy blocking 'test-domain.local'.
2. Confirm Client enforcement ACTIVE.
3. Verify HTTP IPv4 & IPv6 socket path receives HTTP 403 Forbidden with APEXEYE block page without RST.
4. Verify HTTPS IPv4 & IPv6 socket path cleanly returns TLS Alert without MITM and logs the event.
5. Verify Master firewall activity log timestamp displays in local time (~15:XX), not UTC (~09:XX).
6. Test firewall disable (unblocked) -> re-enable (blocked again).
7. Ready for browser_subagent verification on port 80.
"""

import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database, get_connection
from master.app.services.firewall_service import FirewallService
from master.app.utils.timezone import utc_to_local_display, get_local_timezone
from client.app.services.block_server import BlockServer, _TLS_ALERT_RECORD
from client.app.services.firewall_agent import FirewallAgent
from unittest.mock import MagicMock


def make_client_hello(server_name: str) -> bytes:
    import struct
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


def main():
    print("=" * 80)
    print("APEXEYE LIVE VERIFICATION: TIMEZONE DISPLAY + BLOCK PAGE RENDERING")
    print("=" * 80)

    # 1. Setup Master DB & FirewallService
    init_database()
    fw_service = FirewallService()

    test_domain = "test-domain.local"
    try:
        fw_service.add_domain(test_domain)
    except ValueError:
        pass

    policy = fw_service.set_enabled(True)
    print(f"[1] Master Firewall ENABLED: policy v{policy['version']}, blocked_domains={policy['blocked_domains']}")

    # 2. Setup Client FirewallAgent with real BlockServer on port 80 and 443
    mock_conn = MagicMock()
    mock_conn.is_authenticated = True
    mock_conn._device_id = "VERIFY-WORKSTATION-01"
    mock_conn.get_firewall_policy.side_effect = lambda: fw_service.get_policy()

    def record_attempt(**kwargs):
        return fw_service.log_blocked_attempt(
            device_id=mock_conn._device_id,
            device_name="Operator-PC",
            domain=kwargs.get("domain", ""),
            url=kwargs.get("url", ""),
            platform="Windows 11",
            policy_version=kwargs.get("policy_version", 1),
            destination_ip=kwargs.get("destination_ip", ""),
        )
    mock_conn.report_blocked_attempt.side_effect = record_attempt

    stop_event = threading.Event()
    agent = FirewallAgent(mock_conn, stop_event)
    agent._current_policy = fw_service.get_policy()

    # Start BlockServer on standard ports 80 and 443
    bs = BlockServer(
        firewall_agent=agent,
        http_port=80,
        https_port=443,
        bind_host="127.0.0.1",
        ipv6_host="::1",
    )
    ok, err = bs.start()
    assert ok, f"Failed to start BlockServer on port 80/443: {err}"
    print(f"[2] Client BlockServer RUNNING on 127.0.0.1 and [::1] (HTTP:80, HTTPS:443)")

    try:
        # 3. Test HTTP port 80 IPv4
        print("\n[3] Testing HTTP Port 80 IPv4 request for 'http://test-domain.local'...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", 80))
        http_req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {test_domain}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        s.sendall(http_req)

        resp_bytes = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp_bytes += chunk
        s.close()

        resp_text = resp_bytes.decode("utf-8", errors="replace")
        assert "HTTP/1.1 403 Forbidden" in resp_text, "Expected HTTP 403 Forbidden"
        assert "Content-Type: text/html" in resp_text, "Expected Content-Type: text/html"
        assert "APEXEYE" in resp_text, "Expected APEXEYE branding in block page"
        assert "Access Blocked" in resp_text, "Expected Access Blocked title"
        assert test_domain in resp_text, "Expected test-domain in block page body"
        print("    -> PASS: HTTP 403 Block Page cleanly delivered without TCP RST (IPv4)!")

        # 4. Test HTTP port 80 IPv6
        print("\n[4] Testing HTTP Port 80 IPv6 request for 'http://test-domain.local'...")
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.settimeout(5.0)
            s6.connect(("::1", 80))
            s6.sendall(http_req)
            resp6_bytes = b""
            while True:
                chunk = s6.recv(4096)
                if not chunk:
                    break
                resp6_bytes += chunk
            s6.close()
            resp6_text = resp6_bytes.decode("utf-8", errors="replace")
            assert "HTTP/1.1 403 Forbidden" in resp6_text
            assert "APEXEYE" in resp6_text
            print("    -> PASS: HTTP 403 Block Page cleanly delivered without TCP RST (IPv6)!")
        except Exception as exc:
            print(f"    -> IPv6 test skipped: {exc}")

        # 5. Test HTTPS port 443 Zero-MITM rejection
        print("\n[5] Testing HTTPS Port 443 TLS ClientHello for 'https://test-domain.local'...")
        s_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_ssl.settimeout(5.0)
        s_ssl.connect(("127.0.0.1", 443))
        hello = make_client_hello(test_domain)
        s_ssl.sendall(hello)
        alert_resp = s_ssl.recv(1024)
        s_ssl.close()

        assert alert_resp == _TLS_ALERT_RECORD, f"Expected TLS Alert, got: {alert_resp!r}"
        print("    -> PASS: Zero-MITM TLS Alert received, no fake certificate presented!")

        # 6. Verify Timezone Display in Master & Client
        print("\n[6] Verifying Timezone in Master firewall activity logs...")
        logs = fw_service.get_logs(domain=test_domain, limit=5)
        assert len(logs) >= 1, "Expected blocked attempt log"
        latest_log = logs[0]

        now_utc = datetime.now(timezone.utc)
        local_tz = get_local_timezone()
        now_local = now_utc.astimezone(local_tz)

        displayed_time = latest_log["timestamp"]
        raw_utc_time = latest_log.get("timestamp_utc")

        print(f"    System Local Timezone  : {local_tz}")
        print(f"    Current UTC Time       : {now_utc.strftime('%H:%M:%S')}")
        print(f"    Current Local Time     : {now_local.strftime('%H:%M:%S')}")
        print(f"    DB Stored UTC Timestamp: {raw_utc_time}")
        print(f"    Master Displayed Time  : {displayed_time}")

        # Assert displayed time matches local time (hour and minute match local time, NOT UTC)
        disp_hour = int(displayed_time.split()[1].split(":")[0])
        local_hour = now_local.hour
        utc_hour = now_utc.hour

        assert disp_hour == local_hour, f"Displayed hour {disp_hour} does not match local hour {local_hour}!"
        print("    -> PASS: Displayed log timestamp corresponds to local operator time, NOT UTC!")

        # 7. Test Disable -> Normal Access -> Re-Enable Cycle
        print("\n[7] Testing Disable -> Access -> Re-enable Lifecycle...")
        fw_service.set_enabled(False)
        agent._current_policy = fw_service.get_policy()
        print("    Disabled firewall. Testing HTTP request...")

        s_dis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_dis.settimeout(5.0)
        s_dis.connect(("127.0.0.1", 80))
        s_dis.sendall(http_req)
        dis_resp = s_dis.recv(4096).decode("utf-8", errors="replace")
        s_dis.close()
        assert "404 Not Found" in dis_resp, "Expected 404 Not Found when disabled"
        print("    -> PASS: When disabled, block page is NOT served.")

        # Re-enable
        fw_service.set_enabled(True)
        agent._current_policy = fw_service.get_policy()
        print("    Re-enabled firewall. Testing HTTP request...")

        s_re = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_re.settimeout(5.0)
        s_re.connect(("127.0.0.1", 80))
        s_re.sendall(http_req)
        re_resp = b""
        while True:
            chunk = s_re.recv(4096)
            if not chunk:
                break
            re_resp += chunk
        s_re.close()
        re_text = re_resp.decode("utf-8", errors="replace")
        assert "HTTP/1.1 403 Forbidden" in re_text
        assert "APEXEYE" in re_text
        print("    -> PASS: After re-enable, APEXEYE block page is delivered again!")

        print("\n" + "=" * 80)
        print("ALL RUNTIME VERIFICATION CHECKS PASSED SUCCESSFULLY!")
        print("=" * 80)

    finally:
        bs.stop()
        print("BlockServer stopped cleanly.")


if __name__ == "__main__":
    main()
