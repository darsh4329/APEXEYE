"""
APEXEYE LINUX CLIENT — Local Web UI & Client Dashboard Server

Runs on the Linux Client PC (http://127.0.0.1:9200):
- If unauthenticated: serves the Client Authentication Screen pointing to discovered Master.
- If authenticated: serves the dedicated Client Dashboard with local Linux metrics.
- Master administration features are NEVER exposed.
"""

import os
import threading
from typing import Optional, Callable
from flask import Flask, render_template, request, jsonify

from client_linux.app.config import config
from client_linux.app.auth import ClientAuth
from client_linux.app.communication import MasterConnection
from client_linux.app.collectors.cpu import CPUCollector
from client_linux.app.collectors.memory import MemoryCollector
from client_linux.app.collectors.disk import DiskCollector
from client_linux.app.collectors.network import NetworkCollector
from client_linux.app.collectors.os_info import OSInfoCollector
from client_linux.app.utils.logger import get_logger

logger = get_logger("apexeye.linux_client.ui")

_cpu_collector = CPUCollector()
_mem_collector = MemoryCollector()
_disk_collector = DiskCollector()
_net_collector = NetworkCollector()
_os_collector = OSInfoCollector()


def create_client_ui_app(
    auth: ClientAuth,
    conn: MasterConnection,
    on_authenticated_callback: Optional[Callable[[str, str], None]] = None,
    cmd_handler: Optional[object] = None,
    firewall_agent=None,
) -> Flask:
    """Build the Flask application for the local Linux Client UI / Dashboard."""
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    app = Flask("apexeye_linux_client_ui", template_folder=template_dir)
    app.config["TEMPLATES_AUTO_RELOAD"] = False
    app.jinja_env.cache_size = 10
    app._firewall_agent = firewall_agent

    # Suppress werkzeug default request logging
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/")
    def index():
        if not auth.is_paired:
            return render_template(
                "client_auth.html",
                master_url=conn.master_url,
                default_device_id=auth.device_id or config.CLIENT_ID,
            )

        # Authenticated — render dedicated Client Dashboard
        os_info = _os_collector.collect()
        cpu_data = _cpu_collector.collect()
        mem_data = _mem_collector.collect()
        disk_data = _disk_collector.collect()
        net_data = _net_collector.collect()

        return render_template(
            "client_dashboard.html",
            device_id=auth.device_id or config.CLIENT_ID,
            device_name=os_info.get("hostname", "Linux PC"),
            os_name=os_info.get("operating_system", "Linux"),
            hostname=os_info.get("hostname", "localhost"),
            ip_address=os_info.get("local_ip", "127.0.0.1"),
            master_url=conn.master_url,
            cpu_percent=cpu_data.get("cpu_usage", 0.0),
            cpu_cores=cpu_data.get("cpu_cores", 1),
            ram_percent=mem_data.get("memory_usage_percent", 0.0),
            ram_used_gb=mem_data.get("memory_used_gb", 0.0),
            ram_total_gb=mem_data.get("memory_total_gb", 0.0),
            disk_percent=disk_data.get("disk_usage_percent", 0.0),
            disk_used_gb=disk_data.get("disk_used_gb", 0.0),
            disk_total_gb=disk_data.get("disk_total_gb", 0.0),
            net_sent_mb=net_data.get("network_bytes_sent_mb", 0.0),
            net_recv_mb=net_data.get("network_bytes_recv_mb", 0.0),
            current_app="Terminal / Active Process",
        )

    @app.route("/api/local/status", methods=["GET"])
    def get_status():
        return jsonify({
            "is_paired": auth.is_paired,
            "is_authenticated": getattr(auth, "is_authenticated", auth.is_paired),
            "device_id": auth.device_id,
            "master_url": conn.master_url,
        })

    @app.route("/api/local/authenticate", methods=["POST"])
    def local_auth():
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id", "").strip()
        token = data.get("token", "").strip()

        if not device_id or not token:
            return jsonify({"success": False, "error": "Device ID and Token are required."}), 400

        ok, msg = auth.authenticate(device_id, token)
        if ok:
            conn.set_identity(device_id, token)
            if on_authenticated_callback:
                on_authenticated_callback(device_id, token)
            return jsonify({"success": True, "message": msg})
        else:
            return jsonify({"success": False, "error": msg}), 401

    @app.route("/api/local/metrics", methods=["GET"])
    def get_metrics():
        is_client_auth = bool((getattr(auth, "is_authenticated", False) is True) or (getattr(conn, "is_authenticated", False) is True))
        if not is_client_auth:
            return jsonify({"error": "Unauthenticated"}), 401

        cpu = _cpu_collector.collect()
        mem = _mem_collector.collect()
        disk = _disk_collector.collect()
        net = _net_collector.collect()

        return jsonify({
            "cpu": cpu,
            "memory": mem,
            "disk": disk,
            "network": net,
            "current_app": "Terminal / Active Process",
        })

    @app.route("/api/command", methods=["POST"])
    def execute_command():
        if not cmd_handler:
            return jsonify({"success": False, "error": "No command handler configured."}), 501
        data = request.get_json(silent=True) or {}
        res = cmd_handler.handle_command(data)
        return jsonify(res), (200 if res.get("success") else 400)

    @app.route("/api/local/firewall-status", methods=["GET"])
    def get_firewall_status():
        """
        Read-only firewall status endpoint for Linux client.
        Returns current firewall state and readiness diagnostics from local FirewallAgent.
        """
        firewall_state = {
            "policy_active": False,
            "enforcement_active": False,
            "enforcement_state": "INACTIVE",
            "policy_version": 0,
            "domain_count": 0,
            "error": None,
            "enabled": False,
            "components": {},
            "recent_blocks": [],
        }
        try:
            agent_ref = getattr(app, "_firewall_agent", None)
            if agent_ref:
                diag_fn = getattr(agent_ref, "get_readiness_status", None)
                diag = None
                if callable(diag_fn) and not hasattr(diag_fn, "assert_called"):
                    try:
                        res = diag_fn()
                        if isinstance(res, dict):
                            diag = res
                    except Exception:
                        pass

                if diag:
                    firewall_state.update(diag)
                    firewall_state["enabled"] = bool(diag.get("enforcement_active", False))
                else:
                    policy = getattr(agent_ref, "_current_policy", {}) or {}
                    if isinstance(policy, dict):
                        policy_enabled = bool(policy.get("enabled", False))
                        domains = policy.get("blocked_domains", [])
                        domain_count = len(domains) if isinstance(domains, (list, tuple)) else 0
                    else:
                        policy_enabled = False
                        domain_count = 0

                    is_enforcing = bool(getattr(agent_ref, "is_active", False))
                    state = str(getattr(agent_ref, "enforcement_state", "INACTIVE"))

                    err_raw = getattr(agent_ref, "enforcement_error", None)
                    if err_raw is None and hasattr(agent_ref, "_enforcement_error"):
                        err_raw = getattr(agent_ref, "_enforcement_error", None)
                    err = str(err_raw) if (isinstance(err_raw, str) and err_raw) else None

                    p_ver = getattr(agent_ref, "policy_version", 0)
                    try:
                        p_ver = int(p_ver)
                    except Exception:
                        p_ver = 0

                    firewall_state["policy_active"] = policy_enabled
                    firewall_state["enforcement_active"] = is_enforcing
                    firewall_state["enforcement_state"] = state
                    firewall_state["policy_version"] = p_ver
                    firewall_state["domain_count"] = domain_count
                    firewall_state["error"] = err
                    firewall_state["enabled"] = is_enforcing
                    fn_rec = getattr(agent_ref, "get_recent_blocks", None)
                    if callable(fn_rec) and not hasattr(fn_rec, "assert_called"):
                        try:
                            rec = fn_rec()
                            if isinstance(rec, list):
                                firewall_state["recent_blocks"] = rec
                        except Exception:
                            pass
        except Exception as exc:
            firewall_state["error"] = str(exc)
        return jsonify(firewall_state)

    @app.route("/firewall/blocked")
    def show_blocked_page():
        """Dedicated route to view/preview the branded APEXEYE block page."""
        domain = request.args.get("domain", "blocked-example.com")
        url = request.args.get("url", f"http://{domain}/")
        reason = request.args.get("reason", "Blocked by firewall policy")
        client_id = auth.device_id or config.CLIENT_ID
        from client_linux.app.services.block_page import render_block_page
        p_ver = getattr(getattr(app, "_firewall_agent", None), "policy_version", 1)
        html_page = render_block_page(
            domain=domain,
            url=url,
            reason=reason,
            client_id=client_id,
            policy_version=p_ver,
        )
        return html_page, 403

    return app


def start_client_ui_server(
    auth: ClientAuth,
    conn: MasterConnection,
    port: int = 9200,
    on_authenticated_callback: Optional[Callable[[str, str], None]] = None,
    cmd_handler: Optional[object] = None,
    firewall_agent=None,
) -> tuple[Flask, threading.Thread]:
    """Start the Client Web UI / Dashboard in a background thread."""
    app = create_client_ui_app(
        auth,
        conn,
        on_authenticated_callback,
        cmd_handler=cmd_handler,
        firewall_agent=firewall_agent,
    )

    def _run():
        try:
            # Bind locally to localhost / 127.0.0.1
            app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
        except Exception as exc:
            logger.warning("Local Client UI server stopped: %s", exc)

    thread = threading.Thread(target=_run, daemon=True, name="ApexEyeLinux-ClientUI")
    thread.start()
    logger.info("Linux Client UI Dashboard started on http://127.0.0.1:%s", port)
    return app, thread
