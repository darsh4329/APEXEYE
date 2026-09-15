"""
APEXEYE MASTER — Host Info Service (Phase 2)

Receives host/OS information from Client agents and stores it
as a JSON blob in the devices.host_details column.

No separate host_info table — reuses the existing devices table.
"""

import json
from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.services.host_info")


class HostInfoService:
    """Manages host/OS information stored on the devices table."""

    def store_host_info(self, device_id: str, info: dict) -> dict:
        """
        Store host information as JSON in devices.host_details.

        Also updates hostname, operating_system, and ip_address columns
        on the devices table for quick access.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Build the host_details JSON (all host info fields)
        host_details = json.dumps({
            "timestamp": info.get("timestamp", now),
            "hostname": info.get("hostname"),
            "operating_system": info.get("operating_system"),
            "os_version": info.get("os_version"),
            "os_release": info.get("os_release"),
            "os_full": info.get("os_full"),
            "architecture": info.get("architecture"),
            "processor": info.get("processor"),
            "cpu_model": info.get("cpu_model"),
            "cpu_cores_logical": info.get("cpu_cores_logical"),
            "cpu_cores_physical": info.get("cpu_cores_physical"),
            "cpu_max_freq_mhz": info.get("cpu_max_freq_mhz"),
            "ram_total_gb": info.get("ram_total_gb"),
            "local_ip": info.get("local_ip"),
            "boot_time": info.get("boot_time"),
            "python_version": info.get("python_version"),
            "machine_type": info.get("machine_type"),
        })

        # Infer device type and name if present
        os_str = info.get("os_full") or info.get("operating_system") or ""
        dev_type = None
        if "windows" in os_str.lower():
            dev_type = "WINDOWS_PC"
        elif "linux" in os_str.lower():
            dev_type = "LINUX_PC"
        elif info.get("device_type"):
            dev_type = str(info["device_type"]).upper()

        dev_name = info.get("device_name") or info.get("hostname")

        conn = get_connection()
        try:
            # Update device record with host info
            conn.execute(
                """UPDATE devices SET
                    device_name = COALESCE(?, device_name),
                    device_type = COALESCE(?, device_type),
                    hostname = COALESCE(?, hostname),
                    operating_system = COALESCE(?, operating_system),
                    ip_address = COALESCE(?, ip_address),
                    host_details = ?,
                    status = 'online',
                    last_seen = ?,
                    updated_at = ?
                   WHERE device_id = ?""",
                (
                    dev_name,
                    dev_type,
                    info.get("hostname"),
                    os_str or None,
                    info.get("local_ip") or info.get("ip_address"),
                    host_details,
                    now,
                    now,
                    device_id,
                ),
            )
            conn.commit()

            logger.info("Host info stored for device %s", device_id)
            return {"device_id": device_id, "status": "stored"}

        except Exception as exc:
            conn.rollback()
            logger.error(
                "Failed to store host info for %s: %s", device_id, exc
            )
            raise
        finally:
            conn.close()

    def get_host_info(self, device_id: str) -> dict | None:
        """Return the host info for a device from devices.host_details."""
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT host_details FROM devices WHERE device_id = ?;",
                (device_id,),
            ).fetchone()
            if not row or not row["host_details"]:
                return None
            try:
                return json.loads(row["host_details"])
            except (json.JSONDecodeError, TypeError):
                return None
        finally:
            conn.close()
