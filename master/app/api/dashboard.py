"""
APEXEYE MASTER — Dashboard Routes (Phase 1-5)

Serves the web dashboard UI with devices, CCTV endpoints, and centralized logs.
"""

from flask import Blueprint, render_template

from master.app.api.security import require_admin
from master.app.services.device_service import DeviceService
from master.app.services.cctv_service import CCTVService
from master.app.services.log_service import LogService

from master.app.services.firewall_service import FirewallService

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    template_folder="templates",
    static_folder="static",
)

_device_svc = DeviceService()
_cctv_svc = CCTVService()
_log_svc = LogService()
_fw_svc = FirewallService()


@dashboard_bp.route("/")
@require_admin
def index():
    """Render the main dashboard."""
    summary = _device_svc.get_summary()
    devices = _device_svc.list_devices_with_telemetry()
    cctv_summary = _cctv_svc.get_summary()
    cctv_devices = _cctv_svc.list_cctv(include_secrets=False)
    log_summary = _log_svc.get_log_summary()
    recent_logs = _log_svc.search_logs(limit=25).get("logs", [])
    try:
        firewall_summary = _fw_svc.get_status()
    except Exception:
        firewall_summary = {"enabled": False, "version": 0, "domain_count": 0, "blocked_today": 0}

    return render_template(
        "dashboard.html",
        summary=summary,
        devices=devices,
        cctv_summary=cctv_summary,
        cctv_devices=cctv_devices,
        log_summary=log_summary,
        recent_logs=recent_logs,
        firewall_summary=firewall_summary,
    )
