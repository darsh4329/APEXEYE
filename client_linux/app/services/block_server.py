"""
APEXEYE LINUX CLIENT — Block Server & Network Interception Responder (Linux Parity)

Listens locally on:
- Port 80 (HTTP): Serves APEXEYE Branded Block Page (HTTP 403) and logs attempt to Master.
- Port 443 (HTTPS): Inspects TLS ClientHello/SNI incrementally, logs attempt to Master,
  and safely rejects TLS handshake with a TLS Alert (access_denied).

Security & Protocol Invariants:
- Never performs TLS MITM or certificate forgery.
- ClientHello SNI parser is incremental, bounds-checked, and immune to malformed inputs.
- All dynamic fields passed to the block page are HTML-escaped.
- Performs pre-flight port availability checks before activation.
"""

import html
import select
import socket
import struct
import sys
import threading
import time
from typing import Optional, Callable

from client_linux.app.services.block_page import render_block_page
from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.block_server")

# TLS Constants
_TLS_RECORD_HANDSHAKE = 0x16
_TLS_HANDSHAKE_CLIENT_HELLO = 0x01
_TLS_EXTENSION_SERVER_NAME = 0x0000
_TLS_ALERT_RECORD = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31])  # Alert (Fatal, Access Denied)


def _graceful_close(sock: socket.socket) -> None:
    """
    Perform a graceful TCP FIN shutdown and drain pending client bytes.
    Closing a stream socket abruptly without FIN/drain emits a TCP RST segment.
    When modern browsers (Chrome/Firefox) receive TCP RST, they abort the stream
    and display ERR_CONNECTION_RESET instead of rendering the received HTTP response.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    try:
        sock.settimeout(0.3)
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def check_port_available(port: int, host: str = "127.0.0.1") -> tuple[bool, Optional[str]]:
    """Probe whether a port can be bound on loopback with SO_REUSEADDR."""
    is_ipv6 = ":" in host
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.close()
        return True, None
    except PermissionError as exc:
        return False, f"Port {port} is already occupied or unavailable on {host} (Permission denied. Run as Administrator/root: {exc})"
    except OSError as exc:
        return False, f"Port {port} is already occupied or unavailable on {host}: {exc}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def _bind_listeners(port: int, host_ipv4: str = "127.0.0.1", host_ipv6: str = "::1") -> list[socket.socket]:
    """Bind listeners on both IPv4 and IPv6 loopback addresses."""
    socks: list[socket.socket] = []
    # 1. Bind IPv4 loopback
    s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s4.bind((host_ipv4, port))
    s4.listen(64)
    s4.settimeout(1.0)
    socks.append(s4)

    # 2. Bind IPv6 loopback if supported on the host
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "IPV6_V6ONLY"):
            try:
                s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except Exception:
                pass
        s6.bind((host_ipv6, port))
        s6.listen(64)
        s6.settimeout(1.0)
        socks.append(s6)
    except Exception as exc:
        logger.debug("IPv6 listener bind on [%s]:%d skipped or failed: %s", host_ipv6, port, exc)

    return socks


def extract_sni_from_client_hello(data: bytes) -> Optional[str]:
    """
    Robust, bounds-checked incremental parser for TLS ClientHello SNI (Server Name Indication).
    Returns normalized hostname string if present and valid, otherwise None.
    Immune to buffer truncation, malformed lengths, and index errors.
    """
    try:
        n = len(data)
        if n < 5:
            return None

        record_type, legacy_version, record_len = struct.unpack("!BHH", data[0:5])
        if record_type != _TLS_RECORD_HANDSHAKE:
            return None

        # Position within handshake payload
        offset = 5
        if offset + 4 > n:
            return None

        msg_type = data[offset]
        if msg_type != _TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        # 3-byte handshake length
        handshake_len = int.from_bytes(data[offset + 1:offset + 4], byteorder="big")
        offset += 4  # Now at Client Version

        # Skip Client Version (2 bytes) + Random (32 bytes)
        offset += 2 + 32
        if offset >= n:
            return None

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len
        if offset + 2 > n:
            return None

        # Cipher Suites
        cipher_suites_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2 + cipher_suites_len
        if offset >= n:
            return None

        # Compression Methods
        compression_len = data[offset]
        offset += 1 + compression_len
        if offset + 2 > n:
            return None

        # Extensions Length
        extensions_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        extensions_end = min(offset + extensions_len, n)

        # Parse Extensions
        while offset + 4 <= extensions_end:
            ext_type, ext_len = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            ext_data_end = offset + ext_len
            if ext_data_end > extensions_end:
                break

            if ext_type == _TLS_EXTENSION_SERVER_NAME:
                # SNI Extension
                if offset + 2 > ext_data_end:
                    break
                server_name_list_len = struct.unpack("!H", data[offset:offset + 2])[0]
                sni_offset = offset + 2
                sni_end = min(sni_offset + server_name_list_len, ext_data_end)

                while sni_offset + 3 <= sni_end:
                    name_type = data[sni_offset]
                    name_len = struct.unpack("!H", data[sni_offset + 1:sni_offset + 3])[0]
                    sni_offset += 3
                    if sni_offset + name_len <= sni_end:
                        if name_type == 0:  # host_name
                            sni_bytes = data[sni_offset:sni_offset + name_len]
                            return sni_bytes.decode("utf-8", errors="ignore").lower().strip()
                    sni_offset += name_len
                break

            offset = ext_data_end

    except Exception as exc:
        logger.debug("SNI parsing encountered exception on non-standard payload: %s", exc)
    return None


class BlockServer:
    """
    Dual-stack local interception daemon running on loopback (127.0.0.1 and [::1]):
    - HTTP (80): Delivers APEXEYE HTML block page across IPv4 and IPv6.
    - HTTPS (443): Extracts SNI and cleanly rejects TLS handshake without MITM.
    """

    def __init__(
        self,
        firewall_agent,
        http_port: int = 80,
        https_port: int = 443,
        bind_host: str = "127.0.0.1",
        ipv6_host: str = "::1",
    ):
        self._firewall_agent = firewall_agent
        self.http_port = http_port
        self.https_port = https_port
        self.bind_host = bind_host
        self.ipv6_host = ipv6_host

        self._stop_event = threading.Event()
        self._http_socks: list[socket.socket] = []
        self._https_socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []

        # Backward compatibility references to primary sockets
        self._http_sock: Optional[socket.socket] = None
        self._https_sock: Optional[socket.socket] = None

        self.http_status: str = "STOPPED"  # STOPPED, RUNNING, FAILED
        self.https_status: str = "STOPPED"
        self.last_error: Optional[str] = None

    def preflight_check(self) -> tuple[bool, Optional[str]]:
        """Verify ports 80 and 443 are available to bind on loopback."""
        h_ok, h_err = check_port_available(self.http_port, self.bind_host)
        if not h_ok:
            self.http_status = "FAILED"
            self.last_error = h_err
            return False, h_err

        s_ok, s_err = check_port_available(self.https_port, self.bind_host)
        if not s_ok:
            self.https_status = "FAILED"
            self.last_error = s_err
            return False, s_err

        return True, None

    def start(self) -> tuple[bool, Optional[str]]:
        """Start both HTTP and HTTPS dual-stack listeners. Returns (success, error)."""
        self.stop()
        self._stop_event.clear()

        # 1. Bind HTTP Port 80 (IPv4 + IPv6)
        try:
            http_socks = _bind_listeners(self.http_port, self.bind_host, self.ipv6_host)
            if not http_socks:
                raise OSError(f"Could not bind HTTP listener on port {self.http_port}")
            self._http_socks = http_socks
            self._http_sock = http_socks[0]
            self.http_status = "RUNNING"
        except Exception as exc:
            self.http_status = "FAILED"
            err = f"Failed to bind HTTP listener on {self.bind_host}:{self.http_port}: {exc}"
            self.last_error = err
            logger.error(err)
            self.stop()
            return False, err

        # 2. Bind HTTPS Port 443 (IPv4 + IPv6)
        try:
            https_socks = _bind_listeners(self.https_port, self.bind_host, self.ipv6_host)
            if not https_socks:
                raise OSError(f"Could not bind HTTPS listener on port {self.https_port}")
            self._https_socks = https_socks
            self._https_sock = https_socks[0]
            self.https_status = "RUNNING"
        except Exception as exc:
            self.https_status = "FAILED"
            err = f"Failed to bind HTTPS listener on {self.bind_host}:{self.https_port}: {exc}"
            self.last_error = err
            logger.error(err)
            self.stop()
            return False, err

        # 3. Launch listener threads for all active sockets
        for s in self._http_socks:
            t = threading.Thread(
                target=self._run_http_loop,
                args=(s,),
                name=f"ApexEye-Linux-BlockServer-HTTP-{s.family.name}",
                daemon=True,
            )
            self._threads.append(t)
            t.start()

        for s in self._https_socks:
            t = threading.Thread(
                target=self._run_https_loop,
                args=(s,),
                name=f"ApexEye-Linux-BlockServer-HTTPS-{s.family.name}",
                daemon=True,
            )
            self._threads.append(t)
            t.start()

        logger.info(
            "APEXEYE Linux Block Server started successfully on %s and [%s] (HTTP:%d, HTTPS:%d, %d listeners)",
            self.bind_host, self.ipv6_host, self.http_port, self.https_port, len(self._threads),
        )
        self.last_error = None
        return True, None

    def stop(self) -> None:
        """Stop listeners cleanly and join background listener threads."""
        self._stop_event.set()

        all_socks = list(self._http_socks) + list(self._https_socks)
        if self._http_sock and self._http_sock not in all_socks:
            all_socks.append(self._http_sock)
        if self._https_sock and self._https_sock not in all_socks:
            all_socks.append(self._https_sock)

        for sock in all_socks:
            try:
                sock.close()
            except Exception:
                pass

        for t in list(self._threads):
            try:
                t.join(timeout=1.0)
            except Exception:
                pass

        self._threads.clear()
        self._http_socks.clear()
        self._https_socks.clear()
        self._http_sock = None
        self._https_sock = None
        self.http_status = "STOPPED"
        self.https_status = "STOPPED"

    @property
    def is_running(self) -> bool:
        return self.http_status == "RUNNING" and self.https_status == "RUNNING"

    def get_status(self) -> dict:
        return {
            "http_listener": {"status": self.http_status, "port": self.http_port},
            "https_listener": {"status": self.https_status, "port": self.https_port},
            "bind_host": self.bind_host,
            "ipv6_host": self.ipv6_host,
            "running": self.is_running,
            "error": self.last_error,
        }

    # ── HTTP Port 80 Handler Loop ──────────────────────────────────────────

    def _run_http_loop(self, sock: socket.socket) -> None:
        while not self._stop_event.is_set():
            try:
                client_sock, client_addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(
                target=self._handle_http_client,
                args=(client_sock, client_addr),
                daemon=True,
            )
            t.start()

    def _handle_http_client(self, sock: socket.socket, addr) -> None:
        try:
            sock.settimeout(3.0)
            data = b""
            # Read until HTTP headers end or timeout
            while b"\r\n\r\n" not in data and b"\n\n" not in data and len(data) < 16384:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk

            if not data:
                return

            req_text = data.decode("iso-8859-1", errors="ignore")
            lines = req_text.splitlines()
            if not lines:
                return

            req_line = lines[0].split()
            path = req_line[1] if len(req_line) > 1 else "/"

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            host_header = headers.get("host", "")
            # Robust host header parsing (handles IPv4, domain:port, and [IPv6]:port)
            if host_header.startswith("[") and "]" in host_header:
                raw_host = host_header.split("]")[0][1:].strip().lower()
            else:
                raw_host = host_header.split(":")[0].strip().lower()
            raw_host = raw_host.rstrip(".")

            dest_ip = addr[0] if (addr and isinstance(addr, tuple)) else self.bind_host

            # Health check on localhost
            if raw_host in ("127.0.0.1", "localhost", "::1") and path == "/health":
                resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                sock.sendall(resp)
                _graceful_close(sock)
                return

            # Direct block page display on loopback (e.g. http://127.0.0.1/ or http://localhost/blocked?domain=...)
            if raw_host in ("127.0.0.1", "localhost", "::1") and (path.startswith("/blocked") or path.startswith("/block") or path == "/"):
                target_domain = "Restricted Website"
                if "?" in path:
                    query = path.split("?", 1)[1]
                    for param in query.split("&"):
                        if param.startswith("domain="):
                            target_domain = param.split("=", 1)[1].strip()
                            break
                elif getattr(self._firewall_agent, "_current_policy", None):
                    domains = self._firewall_agent._current_policy.get("blocked_domains", [])
                    if domains:
                        target_domain = domains[0]

                client_id = getattr(self._firewall_agent._conn, "_device_id", "CLIENT-01") or "CLIENT-01"
                policy_ver = getattr(self._firewall_agent, "policy_version", 0)
                html_content = render_block_page(
                    domain=target_domain,
                    url=f"http://{target_domain}/",
                    reason="Blocked by APEXEYE firewall policy",
                    client_id=client_id,
                    policy_version=policy_ver,
                )
                body_bytes = html_content.encode("utf-8")
                headers_resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n"
                    "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                    "Pragma: no-cache\r\n"
                    "Expires: 0\r\n"
                    "Server: APEXEYE-Firewall-Gateway\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(headers_resp + body_bytes)
                _graceful_close(sock)
                return

            # Check if domain matches firewall policy
            is_blocked, domain, full_url = self._evaluate_domain_blocked(raw_host, path)

            if is_blocked:
                # 1. Trigger actual enforcement log to Master
                client_id = getattr(self._firewall_agent._conn, "_device_id", "CLIENT-01") or "CLIENT-01"
                policy_ver = getattr(self._firewall_agent, "policy_version", 0)
                self._firewall_agent.report_blocked_attempt(
                    domain=domain,
                    url=full_url,
                    destination_ip=dest_ip,
                )

                # 2. Render APEXEYE Branded HTML Block Page (HTML-sanitized)
                html_content = render_block_page(
                    domain=domain,
                    url=full_url,
                    reason="Blocked by firewall policy",
                    client_id=client_id,
                    policy_version=policy_ver,
                )
                body_bytes = html_content.encode("utf-8")
                headers_out = (
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n"
                    "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                    "Pragma: no-cache\r\n"
                    "Expires: 0\r\n"
                    "Server: APEXEYE-Firewall-Gateway\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(headers_out + body_bytes)
                logger.info("APEXEYE HTTP 403 Block Page delivered for domain=%s (client=%s)", domain, client_id)
                _graceful_close(sock)
            else:
                # Not active or not blocked
                sock.sendall(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nNot Found")
                _graceful_close(sock)
        except Exception as exc:
            logger.debug("HTTP client error: %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── HTTPS Port 443 Handler Loop ────────────────────────────────────────

    def _run_https_loop(self, sock: socket.socket) -> None:
        while not self._stop_event.is_set():
            try:
                client_sock, client_addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(
                target=self._handle_https_client,
                args=(client_sock, client_addr),
                daemon=True,
            )
            t.start()

    def _handle_https_client(self, sock: socket.socket, addr) -> None:
        try:
            sock.settimeout(3.0)
            # Read first packet incrementally to get ClientHello
            buf = b""
            while len(buf) < 1024:
                chunk = sock.recv(1024 - len(buf))
                if not chunk:
                    break
                buf += chunk
                # Check if we have at least 5 bytes record header and full record
                if len(buf) >= 5:
                    record_len = struct.unpack("!H", buf[3:5])[0]
                    if len(buf) >= 5 + record_len:
                        break

            if not buf:
                return

            sni_hostname = extract_sni_from_client_hello(buf)
            if not sni_hostname:
                # No valid SNI extracted, terminate connection
                return

            dest_ip = addr[0] if (addr and isinstance(addr, tuple)) else self.bind_host
            is_blocked, domain, full_url = self._evaluate_domain_blocked(sni_hostname, "/", is_https=True)

            if is_blocked:
                client_id = getattr(self._firewall_agent._conn, "_device_id", "CLIENT-01") or "CLIENT-01"
                self._firewall_agent.report_blocked_attempt(
                    domain=domain,
                    url=full_url,
                    destination_ip=dest_ip,
                )
                logger.info("APEXEYE HTTPS Blocked attempt logged for SNI=%s (client=%s)", domain, client_id)
                # Reject TLS handshake cleanly with TLS Alert
                try:
                    sock.sendall(_TLS_ALERT_RECORD)
                except Exception:
                    pass
                _graceful_close(sock)
        except Exception as exc:
            logger.debug("HTTPS client error: %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── Helper: Evaluate domain against active policy ──────────────────────

    def _evaluate_domain_blocked(
        self,
        raw_host: str,
        path: str = "/",
        is_https: bool = False,
    ) -> tuple[bool, str, str]:
        """
        Check if raw_host is currently blocked by APEXEYE policy.
        Returns (is_blocked: bool, normalized_domain: str, full_url: str).
        """
        if not raw_host:
            return False, "", ""

        # Normalize host (strip www. if comparing)
        host = raw_host.lower().strip()
        scheme = "https" if is_https else "http"
        full_url = f"{scheme}://{host}{path}"

        # If firewall is not currently active on client, do not block
        if not getattr(self._firewall_agent, "is_policy_enabled", False):
            return False, host, full_url

        policy = getattr(self._firewall_agent, "_current_policy", {}) or {}
        blocked_domains = [d.lower().strip() for d in policy.get("blocked_domains", [])]

        # Exact match
        if host in blocked_domains:
            return True, host, full_url

        # Check with/without www
        if host.startswith("www.") and host[4:] in blocked_domains:
            return True, host[4:], full_url
        if f"www.{host}" in blocked_domains:
            return True, host, full_url

        # Subdomain match
        for bd in blocked_domains:
            if host.endswith(f".{bd}"):
                return True, bd, full_url

        return False, host, full_url


__all__ = [
    "BlockServer",
    "check_port_available",
    "extract_sni_from_client_hello",
    "_TLS_ALERT_RECORD",
]
