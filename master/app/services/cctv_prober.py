"""
APEXEYE MASTER — CCTV Network & RTSP Prober Engine (Phase 4.5 Hardened)

Performs direct, lightweight network reachability checks for registered CCTV
and NVR devices:
  1. TCP port reachability & latency measurement
  2. RTSP availability probing (OPTIONS with DESCRIBE fallback)
  3. Comprehensive Authentication Challenge Handling:
     - HTTP/RTSP Basic Authentication
     - RFC 2617 Digest Authentication (qop=auth, cnonce, nc, opaque, MD5)
     - Socket reconnect on 401 connection closure

Safety & Privacy:
  - NEVER pulls, decodes, records, or stores video streams, frames, or audio.
  - NEVER performs port scans or IP range discovery; only checks registered targets.
  - Zero heavy video/OpenCV dependencies — built with pure Python socket & stdlib.
  - Zero credential leakage in logs, headers, or error exceptions.
"""

import base64
import hashlib
import os
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from master.app.config import config
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.cctv.prober")


def check_tcp_connectivity(
    host: str, port: int, timeout: float | None = None
) -> tuple[bool, float | None, str | None]:
    """
    Test basic TCP reachability to a CCTV IP/hostname and port.

    Returns:
        (is_reachable: bool, response_time_ms: float | None, error_reason: str | None)
    """
    timeout = timeout or config.CCTV_TCP_TIMEOUT
    start_time = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        sock.close()
        return True, elapsed_ms, None

    except socket.timeout:
        return False, None, "TCP_TIMEOUT (Target did not respond within timeout)"
    except ConnectionRefusedError:
        return False, None, "TCP_CONNECTION_REFUSED (Port closed or refused by target)"
    except socket.gaierror:
        return False, None, f"DNS_FAILURE (Could not resolve hostname '{host}')"
    except OSError as exc:
        return False, None, f"TCP_UNREACHABLE ({exc.strerror or str(exc)})"
    except Exception as exc:
        return False, None, f"TCP_ERROR ({str(exc)})"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _build_digest_header(
    challenge_header: str,
    method: str,
    rtsp_url: str,
    username: str,
    password: str,
) -> str | None:
    """
    Build RFC 2617 Digest Authorization header from server WWW-Authenticate challenge.
    Supports basic MD5 digest as well as qop="auth" with cnonce and nc.
    """
    realm_m = re.search(r'realm="([^"]+)"', challenge_header)
    nonce_m = re.search(r'nonce="([^"]+)"', challenge_header)
    if not realm_m or not nonce_m:
        return None

    realm = realm_m.group(1)
    nonce = nonce_m.group(1)

    opaque_m = re.search(r'opaque="([^"]+)"', challenge_header)
    opaque = opaque_m.group(1) if opaque_m else None

    qop_m = re.search(r'qop="?([^",\s]+)"?', challenge_header, re.IGNORECASE)
    qop = qop_m.group(1) if qop_m else None

    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode("utf-8")).hexdigest()
    ha2 = hashlib.md5(f"{method}:{rtsp_url}".encode("utf-8")).hexdigest()

    if qop and "auth" in qop.lower():
        cnonce = os.urandom(8).hex()
        nc = "00000001"
        digest_resp = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode("utf-8")
        ).hexdigest()
        parts = [
            f'Digest username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{rtsp_url}"',
            f'response="{digest_resp}"',
            'qop="auth"',
            f'nc={nc}',
            f'cnonce="{cnonce}"',
        ]
    else:
        digest_resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
        parts = [
            f'Digest username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{rtsp_url}"',
            f'response="{digest_resp}"',
        ]

    if opaque:
        parts.append(f'opaque="{opaque}"')

    return "Authorization: " + ", ".join(parts)


def check_rtsp_availability(
    host: str,
    port: int,
    rtsp_url: str,
    username: str | None = None,
    password: str | None = None,
    timeout: float | None = None,
) -> tuple[bool, float | None, str, str | None]:
    """
    Perform a lightweight RTSP handshake probe (OPTIONS request with DESCRIBE fallback).

    Returns:
        (is_available: bool, response_time_ms: float | None, status_code_str: str, message: str | None)
    """
    timeout = timeout or config.CCTV_RTSP_TIMEOUT
    start_time = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        # 1. Build initial RTSP OPTIONS request (with Basic auth if credentials provided upfront)
        cseq = 1
        req_lines = [
            f"OPTIONS {rtsp_url} RTSP/1.0",
            f"CSeq: {cseq}",
            "User-Agent: ApexEye-CCTV-Monitor/1.0",
        ]
        if username and password:
            cred_str = f"{username}:{password}"
            b64_creds = base64.b64encode(cred_str.encode("utf-8")).decode("ascii")
            req_lines.append(f"Authorization: Basic {b64_creds}")

        req_lines.extend(["", ""])
        sock.sendall("\r\n".join(req_lines).encode("utf-8"))

        # Read response header
        response_bytes = sock.recv(2048)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        if not response_bytes:
            return False, None, "RTSP_EMPTY_RESPONSE", "Server closed connection with empty response"

        response_text = response_bytes.decode("utf-8", errors="replace")
        status_match = re.match(r"^RTSP/\d\.\d\s+(\d{3})\s*(.*)", response_text)

        if not status_match:
            return False, None, "RTSP_INVALID_PROTOCOL", "Target did not return valid RTSP response"

        code = int(status_match.group(1))
        reason = status_match.group(2).strip()

        # ── 200 OK ──────────────────────────────────────────────
        if code == 200:
            return True, elapsed_ms, "RTSP_AVAILABLE", f"RTSP 200 {reason}"

        # ── 401 Unauthorized ────────────────────────────────────
        if code == 401:
            if username and password:
                # Check for Digest challenge
                digest_match = re.search(
                    r'WWW-Authenticate:\s*Digest\s+([^\r\n]+)',
                    response_text,
                    re.IGNORECASE,
                )
                if digest_match:
                    challenge = digest_match.group(1)
                    auth_hdr = _build_digest_header(
                        challenge, "OPTIONS", rtsp_url, username, password
                    )
                    if auth_hdr:
                        cseq += 1
                        digest_req = [
                            f"OPTIONS {rtsp_url} RTSP/1.0",
                            f"CSeq: {cseq}",
                            auth_hdr,
                            "User-Agent: ApexEye-CCTV-Monitor/1.0",
                            "",
                            "",
                        ]
                        # Some cameras close socket on 401; handle reconnection if needed
                        try:
                            sock.sendall("\r\n".join(digest_req).encode("utf-8"))
                            digest_resp_bytes = sock.recv(2048)
                        except (socket.error, OSError):
                            sock.close()
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(timeout)
                            sock.connect((host, port))
                            sock.sendall("\r\n".join(digest_req).encode("utf-8"))
                            digest_resp_bytes = sock.recv(2048)

                        if digest_resp_bytes:
                            d_text = digest_resp_bytes.decode("utf-8", errors="replace")
                            d_m = re.match(r"^RTSP/\d\.\d\s+(\d{3})\s*(.*)", d_text)
                            if d_m:
                                d_code = int(d_m.group(1))
                                if d_code in (200, 404):
                                    return True, elapsed_ms, "RTSP_AVAILABLE", "RTSP Digest Authenticated OK"
                                elif d_code == 401:
                                    return False, elapsed_ms, "RTSP_AUTH_FAILED", "RTSP 401 Invalid Digest Credentials"
                                elif d_code == 403:
                                    return True, elapsed_ms, "RTSP_FORBIDDEN", "RTSP 403 Forbidden (Access Denied)"

                return False, elapsed_ms, "RTSP_AUTH_FAILED", "RTSP 401 Invalid Credentials"

            return True, elapsed_ms, "RTSP_AUTH_REQUIRED", "RTSP 401 Authentication Required"

        # ── 405 / 501 Method Not Allowed -> Try DESCRIBE Fallback ──
        if code in (405, 501):
            cseq += 1
            desc_req = [
                f"DESCRIBE {rtsp_url} RTSP/1.0",
                f"CSeq: {cseq}",
                "Accept: application/sdp",
                "User-Agent: ApexEye-CCTV-Monitor/1.0",
                "",
                "",
            ]
            try:
                sock.sendall("\r\n".join(desc_req).encode("utf-8"))
                desc_bytes = sock.recv(2048)
                if desc_bytes:
                    desc_text = desc_bytes.decode("utf-8", errors="replace")
                    desc_m = re.match(r"^RTSP/\d\.\d\s+(\d{3})\s*(.*)", desc_text)
                    if desc_m:
                        desc_code = int(desc_m.group(1))
                        if desc_code in (200, 401, 403, 404):
                            return True, elapsed_ms, "RTSP_AVAILABLE", f"RTSP DESCRIBE {desc_code} Responsive"
            except Exception:
                pass
            return True, elapsed_ms, "RTSP_AVAILABLE", f"RTSP {code} {reason}"

        # ── 403 Forbidden / 404 Path Not Found / 454 Session Not Found ──
        if code == 403:
            return True, elapsed_ms, "RTSP_FORBIDDEN", "RTSP 403 Forbidden (Stream/Account Access Denied)"

        if code == 404:
            return True, elapsed_ms, "RTSP_PATH_INVALID", "RTSP 404 Stream/Channel Not Found"

        if code in (454, 500):
            return True, elapsed_ms, "RTSP_AVAILABLE", f"RTSP {code} {reason}"

        return False, elapsed_ms, f"RTSP_{code}", f"RTSP {code} {reason}"

    except socket.timeout:
        return False, None, "RTSP_TIMEOUT", "RTSP handshake timed out"
    except ConnectionRefusedError:
        return False, None, "RTSP_CONNECTION_REFUSED", "RTSP port refused connection"
    except Exception as exc:
        return False, None, "RTSP_ERROR", f"RTSP probe error: {str(exc)}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe_cctv(cctv: dict) -> dict:
    """
    Run full network connectivity and RTSP availability probe on a CCTV record.

    Returns telemetry dict ready for database ingestion.
    """
    cctv_id = cctv["cctv_id"]
    ip_address = cctv["ip_address"]
    port = int(cctv.get("port", 554))
    rtsp_url = cctv.get("rtsp_url") or f"rtsp://{ip_address}:{port}{cctv.get('rtsp_path', '/stream1')}"
    username = cctv.get("username")
    password = cctv.get("password")  # deobfuscated if available

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Step 1: TCP Port Probe
    tcp_ok, tcp_ms, tcp_err = check_tcp_connectivity(ip_address, port)

    if not tcp_ok:
        return {
            "cctv_id": cctv_id,
            "timestamp": now,
            "tcp_reachable": False,
            "tcp_response_time_ms": None,
            "rtsp_reachable": False,
            "rtsp_response_time_ms": None,
            "status": "OFFLINE",
            "failure_reason": tcp_err,
            "details": {
                "ip_address": ip_address,
                "port": port,
                "error": tcp_err,
                "step": "tcp_check",
            },
        }

    # Step 2: RTSP Handshake Probe
    rtsp_ok, rtsp_ms, rtsp_status, rtsp_msg = check_rtsp_availability(
        ip_address, port, rtsp_url, username=username, password=password
    )

    if rtsp_ok:
        overall_status = "ONLINE"
        reason = rtsp_msg or "Healthy"
    else:
        # TCP is reachable, but RTSP failed (e.g. AUTH_FAILED, RTSP_UNAVAILABLE, timeout)
        overall_status = "ONLINE_NETWORK"
        reason = rtsp_msg or rtsp_status

    return {
        "cctv_id": cctv_id,
        "timestamp": now,
        "tcp_reachable": True,
        "tcp_response_time_ms": tcp_ms,
        "rtsp_reachable": rtsp_ok,
        "rtsp_response_time_ms": rtsp_ms,
        "status": overall_status,
        "failure_reason": reason if overall_status != "ONLINE" else "Healthy",
        "details": {
            "ip_address": ip_address,
            "port": port,
            "tcp_response_time_ms": tcp_ms,
            "rtsp_status": rtsp_status,
            "rtsp_message": rtsp_msg,
            "rtsp_response_time_ms": rtsp_ms,
        },
    }
