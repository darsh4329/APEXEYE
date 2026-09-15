"""
APEXEYE MASTER — PDF Reports API (Phase 9)

REST API endpoints for requesting, querying, and securely downloading
generated multi-page executive PDF audit reports.
"""

from flask import Blueprint, request, jsonify, send_file
from master.app.api.security import require_admin
from master.app.services.report_service import ReportService
from master.app.services.rate_limiter import rate_limit
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.reports")

reports_bp = Blueprint("reports_api", __name__)
_rep_svc = ReportService()


@reports_bp.route("/reports/generate", methods=["POST"])
@require_admin
@rate_limit(max_requests=10, window_seconds=60, scope="reports")
def generate_report():
    """
    Generate a new PDF report.

    Payload:
      {
        "scope": "single_device" | "selected_devices" | "system",
        "device_id": "optional_for_single",
        "device_ids": ["opt1", "opt2"],
        "start_date": "2026-08-25 00:00:00",
        "end_date": "2026-08-29 00:00:00",
        "options": { ... }
      }
    """
    data = request.get_json(silent=True) or {}
    scope = data.get("scope", "system")
    device_id = data.get("device_id")
    device_ids = data.get("device_ids")
    start_date = data.get("start_date") or data.get("start")
    end_date = data.get("end_date") or data.get("end")
    options = data.get("options") or {}

    try:
        result = _rep_svc.generate_report(
            scope=scope,
            device_id=device_id,
            device_ids=device_ids,
            start_date=start_date,
            end_date=end_date,
            options=options,
        )
        return jsonify(result), 201
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    except Exception as exc:
        logger.error("Error generating report: %s", exc)
        return jsonify({"error": "Internal server error."}), 500


@reports_bp.route("/reports/<int:report_id>", methods=["GET"])
@require_admin
def get_report_metadata(report_id: int):
    """Retrieve metadata for a generated report."""
    meta = _rep_svc.get_report_by_id(report_id)
    if not meta:
        return jsonify({"error": f"Report {report_id} not found."}), 404
    return jsonify(meta), 200


@reports_bp.route("/reports/<int:report_id>/download", methods=["GET"])
@require_admin
def download_report(report_id: int):
    """
    Download generated PDF report with strict path-traversal protection.
    """
    safe_path = _rep_svc.get_report_file_path(report_id)
    if not safe_path:
        return jsonify({"error": "Report file not found or unauthorized path."}), 404

    return send_file(
        safe_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=safe_path.name,
    )


@reports_bp.route("/reports", methods=["GET"])
@require_admin
def list_reports():
    """List recent reports."""
    limit_raw = request.args.get("limit", 20)
    try:
        limit = min(max(1, int(limit_raw)), 100)
    except ValueError:
        limit = 20

    reports = _rep_svc.list_reports(limit=limit)
    return jsonify({"reports": reports, "count": len(reports)}), 200
