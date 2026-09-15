"""
APEXEYE MASTER — Local LAN Discovery Service (UDP 9101)

Advertises the APEXEYE Master endpoint on the local network:
1. Listens for client UDP discovery probes (APEXEYE_DISCOVERY) on port 9101 and responds immediately.
2. Periodically broadcasts discovery beacon announcements on the LAN and active subnets.
3. Automatically uses the primary active physical LAN IPv4 address (filters out VirtualBox, link-local, loopback).
4. NEVER exposes secrets, tokens, passwords, database paths, or admin credentials.
"""

import json
import os
import socket
import threading
import time
from typing import Optional, List

from master.app.config import config
from master.app.utils.network import get_primary_lan_ip
from master.app.utils.logger import get_logger
from client.app.discovery import get_active_subnet_broadcasts

logger = get_logger("apexeye.master.discovery")

DISCOVERY_PORT = int(os.getenv("APEXEYE_DISCOVERY_PORT", "9101"))
BEACON_INTERVAL = float(os.getenv("APEXEYE_BEACON_INTERVAL", "3.0"))


class MasterDiscoveryService:
    """Runs a background UDP listener and periodic beacon for automatic LAN discovery."""

    def __init__(self, port: int = DISCOVERY_PORT, api_port: Optional[int] = None):
        self.port = port
        self.api_port = api_port or config.PORT
        self._stop_event = threading.Event()
        self._listener_thread: Optional[threading.Thread] = None
        self._beacon_thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def get_discovery_payload(self) -> dict:
        """Construct non-sensitive discovery advertisement payload."""
        lan_ip = config.primary_lan_ip
        hostname = socket.gethostname()
        return {
            "service": "APEXEYE_MASTER",
            "version": config.VERSION,
            "port": self.api_port,
            "lan_ip": lan_ip,
            "hostname": hostname,
            "protocol": "http",
        }

    def start(self) -> None:
        """Start the discovery listener and beacon threads."""
        if self._listener_thread and self._listener_thread.is_alive():
            return

        self._stop_event.clear()

        # Start UDP listener thread
        self._listener_thread = threading.Thread(
            target=self._run_listener,
            name="ApexEye-MasterDiscoveryListener",
            daemon=True,
        )
        self._listener_thread.start()

        # Start periodic beacon broadcast thread
        self._beacon_thread = threading.Thread(
            target=self._run_beacon,
            name="ApexEye-MasterDiscoveryBeacon",
            daemon=True,
        )
        self._beacon_thread.start()

        logger.info(
            "Master Discovery Service started on UDP %d (Advertising http://%s:%d)",
            self.port,
            config.primary_lan_ip,
            self.api_port,
        )

    def stop(self) -> None:
        """Stop discovery service."""
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._listener_thread:
            self._listener_thread.join(timeout=2.0)
        if self._beacon_thread:
            self._beacon_thread.join(timeout=2.0)
        logger.info("Master Discovery Service stopped.")

    def _run_listener(self) -> None:
        """Listen for discovery probes from clients and reply."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.port))
            sock.settimeout(1.0)
            self._sock = sock
        except Exception as exc:
            logger.warning("Could not bind UDP discovery port %d: %s. Direct LAN probing will be used.", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
                if not data:
                    continue

                # Check if request is an APEXEYE discovery probe
                text = data.decode("utf-8", errors="ignore").strip()
                is_probe = False
                if "APEXEYE_DISCOVERY" in text:
                    is_probe = True
                else:
                    try:
                        parsed = json.loads(text)
                        if parsed.get("query") == "APEXEYE_DISCOVERY" or parsed.get("service") == "APEXEYE":
                            is_probe = True
                    except Exception:
                        pass

                if is_probe:
                    payload = self.get_discovery_payload()
                    resp_bytes = json.dumps(payload).encode("utf-8")
                    sock.sendto(resp_bytes, addr)
                    logger.debug("Discovery probe answered for client %s:%d -> %s", addr[0], addr[1], payload["lan_ip"])
            except socket.timeout:
                continue
            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.debug("Discovery listener error: %s", exc)
                time.sleep(0.5)

        try:
            sock.close()
        except Exception:
            pass

    def _run_beacon(self) -> None:
        """Periodically broadcast discovery announcement on the local network and active subnets."""
        broadcast_sock = None
        try:
            broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            broadcast_sock.settimeout(1.0)
        except Exception as exc:
            logger.debug("Could not create UDP broadcast socket: %s", exc)
            return

        while not self._stop_event.is_set():
            try:
                payload = self.get_discovery_payload()
                msg = json.dumps(payload).encode("utf-8")
                targets = get_active_subnet_broadcasts()
                for target_bcast in targets:
                    try:
                        broadcast_sock.sendto(msg, (target_bcast, self.port))
                    except Exception:
                        pass
            except Exception as exc:
                logger.debug("Beacon broadcast send error: %s", exc)

            self._stop_event.wait(timeout=BEACON_INTERVAL)

        try:
            broadcast_sock.close()
        except Exception:
            pass


master_discovery_service = MasterDiscoveryService()
