"""
APEXEYE MASTER — Firewall REST API

Provides:
  Admin-only endpoints (loopback only):
    GET  /firewall                  — Firewall management page (HTML)
    POST /api/firewall/enable       — Enable firewall
    POST /api/firewall/disable      — Disable firewall
    POST /api/firewall/domains      — Add blocked domain
    DELETE /api/firewall/domains/<id> — Remove blocked domain
    GET  /api/firewall/logs         — Activity log (filterable)
    GET  /api/firewall/summary      — Dashboard widget summary

  Authenticated-client endpoints (device credentials required):
    GET  /api/firewall/policy       — Retrieve current policy
    POST /api/firewall/log          — Report a blocked connection attempt
    POST /api/firewall/status       — Report local enforcement state
"""

from flask import Blueprint, request, jsonify, make_response, render_template, g

from master.app.api.security import require_admin
from master.app.api.auth_middleware import require_device_auth
from master.app.services.firewall_service import FirewallService
from master.app.services.master_firewall_enforcer import master_firewall_enforcer
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.firewall_api")

firewall_bp = Blueprint(
    "firewall",
    __name__,
    template_folder="templates",
)

_fw_service = FirewallService()


# ============================================================
# Admin-only: Management page
# ============================================================

@firewall_bp.route("/firewall")
@require_admin
def firewall_page():
    """Render the Firewall Management page."""
    status = _fw_service.get_status()
    domains = _fw_service.list_domains()
    logs = _fw_service.get_logs(limit=50)
    return render_template(
        "firewall.html",
        firewall_enabled=status.get("enabled", False),
        policy_version=status.get("version", 0),
        domain_count=status.get("domain_count", 0),
        blocked_today=status.get("blocked_today", 0),
        updated_at=status.get("updated_at", ""),
        updated_by=status.get("updated_by", "system"),
        domains=domains,
        logs=logs,
    )


# ============================================================
# Admin-only: Enable / Disable
# ============================================================

@firewall_bp.route("/api/firewall/enable", methods=["POST"])
@require_admin
def enable_firewall():
    """Enable the Master firewall and distribute policy."""
    body = request.get_json(silent=True) or {}
    actor = body.get("actor", "admin")
    try:
        policy = _fw_service.set_enabled(True, actor=actor)
        # Apply enforcement on the Master machine itself
        ok, err = master_firewall_enforcer.apply_policy(
            enabled=True,
            blocked_domains=policy.get("blocked_domains", []),
        )
        return jsonify({
            "success": True,
            "enabled": True,
            "policy_version": policy["version"],
            "blocked_domains": policy["blocked_domains"],
            "master_enforcement": "ok" if ok else "error",
            "master_enforcement_error": err,
        })
    except Exception as exc:
        logger.error("Failed to enable firewall: %s", exc, exc_info=True)
        return make_response(jsonify({"success": False, "error": str(exc)}), 500)


@firewall_bp.route("/api/firewall/disable", methods=["POST"])
@require_admin
def disable_firewall():
    """Disable the Master firewall (preserves the blocked domain list)."""
    body = request.get_json(silent=True) or {}
    actor = body.get("actor", "admin")
    try:
        policy = _fw_service.set_enabled(False, actor=actor)
        # Remove enforcement on Master (list is preserved in DB, not in hosts file)
        ok, err = master_firewall_enforcer.apply_policy(
            enabled=False,
            blocked_domains=[],
        )
        return jsonify({
            "success": True,
            "enabled": False,
            "policy_version": policy["version"],
            "blocked_domains": policy["blocked_domains"],
            "master_enforcement": "ok" if ok else "error",
            "master_enforcement_error": err,
        })
    except Exception as exc:
        logger.error("Failed to disable firewall: %s", exc, exc_info=True)
        return make_response(jsonify({"success": False, "error": str(exc)}), 500)


# ============================================================
# Admin-only: Domain management
# ============================================================

@firewall_bp.route("/api/firewall/domains", methods=["POST"])
@require_admin
def add_domain():
    """Add a website/domain to the blocked list."""
    body = request.get_json(silent=True) or {}
    raw_domain = (body.get("domain") or "").strip()
    actor = body.get("actor", "admin")

    if not raw_domain:
        return make_response(jsonify({"error": "domain is required."}), 400)

    try:
        result = _fw_service.add_domain(raw_domain, actor=actor)
        # Re-apply enforcement if firewall is currently active
        _sync_master_enforcement(actor=actor)
        return jsonify({"success": True, "domain": result}), 201
    except ValueError as ve:
        return make_response(jsonify({"error": str(ve)}), 400)
    except Exception as exc:
        logger.error("Failed to add domain: %s", exc, exc_info=True)
        return make_response(jsonify({"error": str(exc)}), 500)


@firewall_bp.route("/api/firewall/domains/<int:domain_id>", methods=["DELETE"])
@require_admin
def remove_domain(domain_id: int):
    """Remove a website/domain from the blocked list."""
    body = request.get_json(silent=True) or {}
    actor = body.get("actor", "admin")

    try:
        result = _fw_service.remove_domain(domain_id, actor=actor)
        # Re-apply enforcement if firewall is currently active
        _sync_master_enforcement(actor=actor)
        return jsonify({"success": True, "result": result})
    except ValueError as ve:
        return make_response(jsonify({"error": str(ve)}), 404)
    except Exception as exc:
        logger.error("Failed to remove domain %d: %s", domain_id, exc, exc_info=True)
        return make_response(jsonify({"error": str(exc)}), 500)


# ============================================================
# Admin-only: Logs & Summary
# ============================================================

@firewall_bp.route("/api/firewall/logs", methods=["GET"])
@require_admin
def get_firewall_logs():
    """Return firewall activity logs with optional filters."""
    device_id = request.args.get("device_id")
    domain = request.args.get("domain")
    action = request.args.get("action")
    since = request.args.get("since")
    until = request.args.get("until")
    limit = request.args.get("limit", default=100, type=int)

    try:
        logs = _fw_service.get_logs(
            device_id=device_id,
            domain=domain,
            action=action,
            since=since,
            until=until,
            limit=limit,
        )
        return jsonify({"logs": logs, "count": len(logs)})
    except Exception as exc:
        logger.error("Firewall log query error: %s", exc, exc_info=True)
        return make_response(jsonify({"error": str(exc)}), 500)


@firewall_bp.route("/api/firewall/summary", methods=["GET"])
@require_admin
def get_firewall_summary():
    """Return summary for the dashboard widget."""
    try:
        return jsonify(_fw_service.get_status())
    except Exception as exc:
        logger.error("Firewall summary error: %s", exc, exc_info=True)
        return make_response(jsonify({"error": str(exc)}), 500)


# ============================================================
# Client-facing: Policy distribution (authenticated devices)
# ============================================================

@firewall_bp.route("/api/firewall/policy", methods=["GET"])
@require_device_auth
def get_firewall_policy():
    """
    Return the current firewall policy to an authenticated client.
    Clients use this to sync and apply enforcement locally.
    """
    try:
        policy = _fw_service.get_policy()
        return jsonify(policy)
    except Exception as exc:
        logger.error("Firewall policy endpoint error: %s", exc, exc_info=True)
        return make_response(jsonify({"error": str(exc)}), 500)


@firewall_bp.route("/api/firewall/log", methods=["POST"])
@require_device_auth
def report_blocked_attempt():
    """
    Client reports a blocked connection attempt.
    Authenticated client only — device_id comes from validated headers.
    """
    device_id = g.device_id
    body = request.get_json(silent=True) or {}

    domain = (body.get("domain") or "").strip()
    if not domain:
        return make_response(jsonify({"error": "domain is required."}), 400)

    result = _fw_service.log_blocked_attempt(
        device_id=device_id,
        device_name=body.get("device_name", device_id),
        domain=domain,
        url=body.get("url", ""),
        platform=body.get("platform", "unknown"),
        policy_version=body.get("policy_version", 0),
        destination_ip=body.get("destination_ip", ""),
        metadata=body.get("metadata"),
    )

    if result is None:
        # Suppressed as duplicate
        return jsonify({"logged": False, "reason": "duplicate_suppressed"})
    return jsonify({"logged": True, "log_id": result.get("id")}), 201


@firewall_bp.route("/api/firewall/status", methods=["POST"])
@require_device_auth
def report_client_status():
    """
    Client reports its current local enforcement state.
    This is informational; Master does not alter policy based on client reports.
    """
    device_id = g.device_id
    body = request.get_json(silent=True) or {}
    state = body.get("enforcement_state", "unknown")
    policy_version = body.get("policy_version", 0)
    error = body.get("error")

    if error:
        logger.warning(
            "Firewall ENFORCEMENT_ERROR reported by device=%s: %s (policy v%d)",
            device_id, error, policy_version,
        )
    else:
        logger.debug(
            "Firewall status from device=%s: state=%s policy_v=%d",
            device_id, state, policy_version,
        )

    return jsonify({"received": True, "device_id": device_id})


# ============================================================
# Internal helper
# ============================================================

def _sync_master_enforcement(actor: str = "admin") -> None:
    """Re-apply the current policy to the Master hosts file after a change."""
    try:
        policy = _fw_service.get_policy()
        master_firewall_enforcer.apply_policy(
            enabled=policy["enabled"],
            blocked_domains=policy["blocked_domains"],
        )
    except Exception as exc:
        logger.warning("Master self-enforcement sync failed: %s", exc)
