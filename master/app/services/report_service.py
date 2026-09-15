"""
APEXEYE MASTER — Report Generation Service (Phase 9)

Coordinates data extraction, AI analysis, chart rendering, and PDF compilation.
Persists report metadata in the existing 'reports' table.
Provides secure path-traversal protected file retrieval.
"""

import os
from pathlib import Path
from datetime import datetime, timezone

from master.app.database import get_connection
from master.app.config import _PROJECT_ROOT
from master.app.services.report_data_builder import ReportDataBuilder
from master.app.services.ai_service import AIService
from master.app.services.pdf_renderer import PDFRenderer
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.report_service")


class ReportService:
    """Manages PDF report generation lifecycle and persistence."""

    def __init__(
        self,
        data_builder: ReportDataBuilder | None = None,
        ai_service: AIService | None = None,
        pdf_renderer: PDFRenderer | None = None,
        reports_dir: str | Path | None = None,
    ):
        self.data_builder = data_builder or ReportDataBuilder()
        self.ai_service = ai_service or AIService()
        self.pdf_renderer = pdf_renderer or PDFRenderer()
        self.reports_dir = Path(reports_dir or (_PROJECT_ROOT / "reports"))
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        scope: str = "system",
        device_id: str | None = None,
        device_ids: list[str] | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        options: dict | None = None,
    ) -> dict:
        """
        Generate a PDF audit report.
        Scopes:
          - 'single_device'
          - 'selected_devices'
          - 'system'
        """
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        ts_slug = now.strftime("%Y%m%d_%H%M%S")

        # Validate explicit start and end dates
        if start_date and end_date:
            try:
                s_check = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                e_check = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                if s_check >= e_check:
                    raise ValueError("Start date must be earlier than end date.")
            except ValueError as ve:
                if "Start date must be earlier" in str(ve):
                    raise ve

        # 1. Execute Analysis & PDF Generation
        if scope == "single_device" and device_id:
            raw_data = self.data_builder.build_single_device_data(device_id, start_date, end_date)
            if not raw_data.get("exists"):
                raise ValueError(f"Device '{device_id}' does not exist.")
            analysis = self.ai_service.analyze_device(device_id, start_date, end_date)
            pdf_bytes = self.pdf_renderer.render_single_device_report(analysis, raw_data)
            file_name = f"apexeye_report_{device_id}_{ts_slug}.pdf"
            report_type = f"single_device:{device_id}"
            start_str = raw_data["start_time"]
            end_str = raw_data["end_time"]

        elif scope == "selected_devices" and device_ids:
            raw_data = self.data_builder.build_multi_device_data(device_ids, start_date, end_date)
            analysis = self.ai_service.analyze_system(device_ids=device_ids, start_time=start_date, end_time=end_date)
            pdf_bytes = self.pdf_renderer.render_system_report(analysis, raw_data)
            file_name = f"apexeye_report_selected_{ts_slug}.pdf"
            report_type = f"selected_devices:{len(device_ids)}"
            start_str = raw_data["start_time"]
            end_str = raw_data["end_time"]

        else:
            # Entire System
            raw_data = self.data_builder.build_system_data(start_date, end_date)
            analysis = self.ai_service.analyze_system(start_time=start_date, end_time=end_date)
            pdf_bytes = self.pdf_renderer.render_system_report(analysis, raw_data)
            file_name = f"apexeye_report_system_{ts_slug}.pdf"
            report_type = "entire_system"
            start_str = raw_data["start_time"]
            end_str = raw_data["end_time"]

        # 2. Write PDF to Secure Reports Directory
        out_path = self.reports_dir / file_name
        out_path.write_bytes(pdf_bytes)

        # 3. Persist in existing reports table
        conn = get_connection()
        try:
            cur = conn.execute(
                """INSERT INTO reports (report_type, generated_at, start_date, end_date, file_path, status)
                   VALUES (?, ?, ?, ?, ?, 'ready');""",
                (report_type, now_str, start_str, end_str, str(out_path)),
            )
            conn.commit()
            report_id = cur.lastrowid
        finally:
            conn.close()

        logger.info("Report %d generated successfully: %s (%d bytes)", report_id, file_name, len(pdf_bytes))

        return {
            "report_id": report_id,
            "report_type": report_type,
            "file_name": file_name,
            "file_size": len(pdf_bytes),
            "generated_at": now_str,
            "start_date": start_str,
            "end_date": end_str,
            "status": "ready",
            "download_url": f"/api/reports/{report_id}/download",
        }

    def get_report_by_id(self, report_id: int) -> dict | None:
        """Retrieve report metadata by database ID."""
        conn = get_connection()
        try:
            row = conn.execute("SELECT * FROM reports WHERE id = ?;", (report_id,)).fetchone()
            if not row:
                return None
            return dict(row)
        finally:
            conn.close()

    def get_report_file_path(self, report_id: int) -> Path | None:
        """
        Retrieve and validate report file path with strict path-traversal protection.
        """
        meta = self.get_report_by_id(report_id)
        if not meta or not meta.get("file_path"):
            return None

        raw_path = Path(meta["file_path"]).resolve()
        reports_root = self.reports_dir.resolve()

        # Security: Guarantee path is inside authorized reports directory
        try:
            raw_path.relative_to(reports_root)
        except ValueError:
            logger.warning("Path traversal attempt detected for report_id %d: %s", report_id, raw_path)
            return None

        if not raw_path.exists() or not raw_path.is_file():
            return None

        return raw_path

    def list_reports(self, limit: int = 20) -> list[dict]:
        """List recently generated reports."""
        conn = get_connection()
        try:
            rows = conn.execute(
                """SELECT id, report_type, generated_at, start_date, end_date, file_path, status
                   FROM reports
                   ORDER BY id DESC LIMIT ?;""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # Backward compatibility with Phase 0 placeholder
    def generate(self, report_type: str, params: dict) -> str:
        res = self.generate_report(scope=report_type, **params)
        return str(res.get("report_id"))
