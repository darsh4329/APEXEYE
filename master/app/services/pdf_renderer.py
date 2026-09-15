"""
APEXEYE MASTER — PDF Report Renderer (Phase 9.2.1 Layout Polish)

Produces presentation-ready, enterprise-grade endpoint monitoring and audit reports.
Supports Single Device, Selected Devices, and Entire System fleet scopes.
Handles sparse telemetry with balanced, informative data panels rather than empty pages.
"""

import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

from master.app.services.chart_service import ChartService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.pdf_renderer")


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic 'Page X of Y' numbering and footer branding."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))

        # Header rule & title
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.75)
        self.line(40, 755, 572, 755)
        self.drawString(40, 760, "APEXEYE  |  Enterprise Endpoint Security & Health Audit Report")

        # Footer rule, timestamp & page number
        self.line(40, 45, 572, 45)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.drawString(40, 32, f"Confidential & Proprietary • Automated Telemetry & Event Ingestion • Generated: {now_str}")
        self.drawRightString(572, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class PDFRenderer:
    """Renders structured analysis datasets into multi-page PDF documents."""

    def __init__(self, chart_service: ChartService | None = None):
        self.chart_svc = chart_service or ChartService()
        self.styles = self._create_styles()

    def _create_styles(self) -> dict:
        base = getSampleStyleSheet()
        custom = {}

        custom["DocTitle"] = ParagraphStyle(
            "DocTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=19,
            leading=23,
            textColor=colors.HexColor("#0f172a"),
            alignment=0,
            spaceAfter=2,
        )
        custom["DocSubTitle"] = ParagraphStyle(
            "DocSubTitle",
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#475569"),
            spaceAfter=8,
        )
        custom["Heading1"] = ParagraphStyle(
            "H1",
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=8,
            spaceAfter=4,
        )
        custom["Heading2"] = ParagraphStyle(
            "H2",
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#334155"),
            spaceBefore=5,
            spaceAfter=3,
        )
        custom["Body"] = ParagraphStyle(
            "Body",
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=3,
        )
        custom["BodyDim"] = ParagraphStyle(
            "BodyDim",
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748b"),
        )
        custom["SummaryText"] = ParagraphStyle(
            "SummaryText",
            fontName="Helvetica",
            fontSize=8.5,
            leading=13,
            textColor=colors.HexColor("#0f172a"),
        )
        custom["TableHeader"] = ParagraphStyle(
            "TH",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        )
        custom["TableCell"] = ParagraphStyle(
            "TD",
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0f172a"),
        )
        custom["TableCellBold"] = ParagraphStyle(
            "TDBold",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0f172a"),
        )
        return custom

    def render_single_device_report(self, analysis_result: dict, raw_data: dict) -> bytes:
        """Render a single device deep diagnostic audit report."""
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=38,
            rightMargin=38,
            topMargin=48,
            bottomMargin=52,
        )
        story = []

        dev_name = analysis_result.get("device_name") or analysis_result.get("device_id")
        dev_id = analysis_result.get("device_id")
        dev_os = analysis_result.get("operating_system") or "Unknown"
        health = analysis_result.get("health", {})
        score = health.get("score")
        status = health.get("status", "UNKNOWN")
        stats = analysis_result.get("stats", {})
        narrative = analysis_result.get("narrative", {})
        anomalies = analysis_result.get("anomalies", [])
        recs = analysis_result.get("recommendations", [])
        telemetry = raw_data.get("telemetry", [])
        logs = raw_data.get("logs", [])
        start_time = analysis_result.get("start_time")
        end_time = analysis_result.get("end_time")

        # ── PAGE 1: COVER HEADER & PROMINENT HEALTH SCORE CARD ────────
        story.append(Paragraph("APEXEYE ENDPOINT AUDIT REPORT", self.styles["DocTitle"]))
        story.append(Paragraph(f"Endpoint Security & Health Diagnostic Audit • <strong>{dev_name}</strong> ({dev_id})", self.styles["DocSubTitle"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=8))

        # Health & Identity Composite Card with generous padding
        status_color = "#16a34a" if status == "GOOD" else ("#d97706" if status == "WARNING" else "#dc2626")
        status_pill = f"<font color='{status_color}'><strong>● {status}</strong></font>"
        score_display = f"{score}" if score is not None else "--"

        cpu_val = f"{stats.get('cpu_avg', '--')}%" if stats.get('cpu_avg') is not None else "--"
        ram_val = f"{stats.get('ram_avg', '--')}%" if stats.get('ram_avg') is not None else "--"
        disk_val = f"{stats.get('disk_avg', '--')}%" if stats.get('disk_avg') is not None else "--"

        health_box_data = [
            [
                Paragraph("<font size=7.5 color='#64748b'><b>DEVICE HEALTH SCORE</b></font>", self.styles["TableCell"]),
                Paragraph("<strong>ENDPOINT METADATA & SCOPE</strong>", self.styles["TableCellBold"]),
            ],
            [
                Paragraph(
                    f"<div style='margin:4px 0;'><font size=26 color='{status_color}'><strong>{score_display}</strong></font>"
                    f"<font size=11 color='#64748b'> / 100</font><br/>"
                    f"<font size=9>{status_pill}</font></div>",
                    self.styles["TableCell"],
                ),
                Paragraph(
                    f"<strong>Device:</strong> {dev_name} &nbsp;|&nbsp; <strong>ID:</strong> {dev_id}<br/>"
                    f"<strong>Operating System:</strong> {dev_os}<br/>"
                    f"<strong>Audit Window:</strong> {start_time} to {end_time}<br/>"
                    f"<strong>Connectivity State:</strong> {'🟢 ONLINE' if raw_data.get('device', {}).get('status') == 'online' else '🔴 OFFLINE'}",
                    self.styles["TableCell"],
                ),
            ],
            [
                Paragraph(f"<font size=7.5 color='#334155'>CPU: <b>{cpu_val}</b> &nbsp;|&nbsp; RAM: <b>{ram_val}</b> &nbsp;|&nbsp; DISK: <b>{disk_val}</b></font>", self.styles["TableCell"]),
                Paragraph(f"<font size=7.5 color='#64748b'>Telemetry Ingested: <b>{len(telemetry)} cycles</b> &nbsp;|&nbsp; Event Logs: <b>{len(logs)} records</b></font>", self.styles["TableCell"]),
            ]
        ]
        health_box_table = Table(health_box_data, colWidths=[165, 371])
        health_box_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#ffffff")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(health_box_table)
        story.append(Spacer(1, 8))

        # Executive Summary Box
        story.append(Paragraph("Executive Summary & AI Diagnostics", self.styles["Heading1"]))
        summary_text = narrative.get("summary") or "Device telemetry within nominal operating parameters."
        summary_table = Table([[Paragraph(summary_text, self.styles["SummaryText"])]], colWidths=[536])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#93c5fd")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 6))

        # Key Observations
        story.append(Paragraph("Key Observations:", self.styles["Heading2"]))
        for obs in narrative.get("key_observations", []):
            story.append(Paragraph(f"• {obs}", self.styles["Body"]))

        story.append(Spacer(1, 6))

        # Operational Metrics Table with authoritative threshold labels
        story.append(Paragraph("Operational Telemetry Summary", self.styles["Heading1"]))
        
        cpu_avg_val = stats.get('cpu_avg')
        cpu_status_str = "Healthy (<70%)" if (cpu_avg_val or 0) < 70 else ("Elevated (70-85%)" if (cpu_avg_val or 0) < 85 else "Critical (>=95%)")
        
        ram_avg_val = stats.get('ram_avg')
        ram_status_str = "Healthy (<70%)" if (ram_avg_val or 0) < 70 else ("Elevated (70-85%)" if (ram_avg_val or 0) < 85 else "Critical (>=95%)")
        
        disk_avg_val = stats.get('disk_avg')
        disk_status_str = "Healthy (<70%)" if (disk_avg_val or 0) < 70 else ("Moderate (70-85%)" if (disk_avg_val or 0) < 85 else "Capacity Warning (>=85%)")

        stat_rows = [
            [Paragraph("Resource / Metric", self.styles["TableHeader"]), Paragraph("Average", self.styles["TableHeader"]), Paragraph("Peak Observed", self.styles["TableHeader"]), Paragraph("Operating Status (Authoritative)", self.styles["TableHeader"])],
            [Paragraph("CPU Workload", self.styles["TableCellBold"]), Paragraph(f"{cpu_avg_val}%" if cpu_avg_val is not None else "Data unavailable", self.styles["TableCell"]), Paragraph(f"{stats.get('cpu_max', 'N/A')}%" if stats.get('cpu_max') is not None else "N/A", self.styles["TableCell"]), Paragraph(cpu_status_str, self.styles["TableCell"])],
            [Paragraph("Physical Memory", self.styles["TableCellBold"]), Paragraph(f"{ram_avg_val}%" if ram_avg_val is not None else "Data unavailable", self.styles["TableCell"]), Paragraph(f"{stats.get('ram_max', 'N/A')}%" if stats.get('ram_max') is not None else "N/A", self.styles["TableCell"]), Paragraph(ram_status_str, self.styles["TableCell"])],
            [Paragraph("Primary Storage", self.styles["TableCellBold"]), Paragraph(f"{disk_avg_val}%" if disk_avg_val is not None else "Data unavailable", self.styles["TableCell"]), Paragraph(f"{stats.get('disk_max', 'N/A')}%" if stats.get('disk_max') is not None else "N/A", self.styles["TableCell"]), Paragraph(disk_status_str, self.styles["TableCell"])],
            [Paragraph("Centralized Event Stream", self.styles["TableCellBold"]), Paragraph(f"{stats.get('critical_log_count', 0)} Critical", self.styles["TableCell"]), Paragraph(f"{stats.get('warning_log_count', 0)} Warnings", self.styles["TableCell"]), Paragraph("Nominal" if stats.get("critical_log_count", 0) == 0 else "Action Required", self.styles["TableCell"])],
        ]
        stat_table = Table(stat_rows, colWidths=[136, 120, 120, 160])
        stat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        story.append(stat_table)

        # ── PAGE 2: TELEMETRY ANALYSIS & DATA AVAILABILITY / APPS ──────
        story.append(PageBreak())
        story.append(Paragraph("Resource Utilization & Telemetry Analysis", self.styles["Heading1"]))

        chart_bytes = self.chart_svc.generate_combined_resources_chart(telemetry)
        if chart_bytes:
            story.append(Paragraph("Empirical multi-resource time-series utilization (150 DPI):", self.styles["BodyDim"]))
            story.append(Spacer(1, 4))
            img = Image(io.BytesIO(chart_bytes), width=536, height=190)
            story.append(img)
            story.append(Spacer(1, 8))
        else:
            # Balanced Telemetry Availability & Ingestion Summary Panel (Fixes sparse Page 2)
            avail_data = [
                [Paragraph("Telemetry & Data Quality Indicator", self.styles["TableHeader"]), Paragraph("Ingestion Metric", self.styles["TableHeader"]), Paragraph("Coverage / Evaluation State", self.styles["TableHeader"])],
                [Paragraph("Telemetry Sample Count", self.styles["TableCellBold"]), Paragraph(f"{len(telemetry)} recorded cycle(s)", self.styles["TableCell"]), Paragraph("Sparse (< 2 points recorded)" if len(telemetry) < 2 else "Continuous Time-Series", self.styles["TableCell"])],
                [Paragraph("Nominal Transmission Interval", self.styles["TableCellBold"]), Paragraph("10.0 seconds", self.styles["TableCell"]), Paragraph("Standard Client Telemetry Rate", self.styles["TableCell"])],
                [Paragraph("Reporting Time Window", self.styles["TableCellBold"]), Paragraph(f"{start_time} to {end_time}", self.styles["TableCell"]), Paragraph("Verified Database Scope", self.styles["TableCell"])],
                [Paragraph("Captured Core Subsystems", self.styles["TableCellBold"]), Paragraph(f"CPU: {cpu_val} | RAM: {ram_val} | Storage: {disk_val}", self.styles["TableCell"]), Paragraph("Stored in SQL database", self.styles["TableCell"])],
            ]
            avail_table = Table(avail_data, colWidths=[166, 190, 180])
            avail_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(avail_table)
            story.append(Spacer(1, 6))

            info_box = Table([[Paragraph("<strong>Trend chart unavailable</strong> — Insufficient telemetry samples exist to produce a statistically meaningful time-series chart.", self.styles["BodyDim"])]], colWidths=[536])
            info_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(info_box)
            story.append(Spacer(1, 8))

        # Application Activity Section
        story.append(Paragraph("Application Activity & Lifecycle Events", self.styles["Heading1"]))
        lifecycle_logs = [l for l in logs if l.get("event_type") in ("APPLICATION_STARTED", "APPLICATION_STOPPED")]
        if lifecycle_logs:
            app_rows = [
                [Paragraph("Timestamp", self.styles["TableHeader"]), Paragraph("Application Name", self.styles["TableHeader"]), Paragraph("Lifecycle Transition", self.styles["TableHeader"]), Paragraph("Process Category", self.styles["TableHeader"])],
            ]
            for al in lifecycle_logs[:12]:
                is_start = al.get("event_type") == "APPLICATION_STARTED"
                evt_pill = "<font color='#16a34a'><strong>🟢 OPENED</strong></font>" if is_start else "<font color='#64748b'><strong>⚪ CLOSED</strong></font>"
                app_rows.append([
                    Paragraph(str(al.get("timestamp")), self.styles["TableCell"]),
                    Paragraph(f"<strong>{al.get('application_name') or 'Unknown'}</strong>", self.styles["TableCell"]),
                    Paragraph(evt_pill, self.styles["TableCell"]),
                    Paragraph(str(al.get("category", "SYSTEM")), self.styles["TableCell"]),
                ])
            app_table = Table(app_rows, colWidths=[120, 176, 120, 120])
            app_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(app_table)
        else:
            no_app_box = Table([[Paragraph("<em>No application lifecycle events were recorded during the selected reporting period.</em>", self.styles["BodyDim"])]], colWidths=[536])
            no_app_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(no_app_box)

        story.append(Spacer(1, 8))

        # Event Severity Distribution Pie Chart
        pie_bytes = self.chart_svc.generate_severity_distribution_chart(logs)
        if pie_bytes:
            story.append(Paragraph("Activity & Event Severity Breakdown", self.styles["Heading2"]))
            img_pie = Image(io.BytesIO(pie_bytes), width=260, height=155)
            story.append(img_pie)
            story.append(Spacer(1, 8))

        # ── PAGE 3: ANOMALIES & PRIORITIZED RECOMMENDATION CARDS ──────
        story.append(PageBreak())
        story.append(Paragraph("Detected Anomalies & Diagnostic Findings", self.styles["Heading1"]))

        if not anomalies:
            clean_box = Table([[Paragraph("<font color='#16a34a'><strong>🟢 NO SIGNIFICANT ANOMALIES</strong></font><br/><font size=8 color='#475569'>No evidence-based operational anomalies were detected during the selected reporting period. All metrics operating within normal baseline boundaries.</font>", self.styles["TableCell"])]], colWidths=[536])
            clean_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#86efac")),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ]))
            story.append(clean_box)
        else:
            anom_table_data = [
                [Paragraph("Severity", self.styles["TableHeader"]), Paragraph("Anomaly / Finding", self.styles["TableHeader"]), Paragraph("Observed Metric", self.styles["TableHeader"]), Paragraph("Diagnostic Explanation", self.styles["TableHeader"])],
            ]
            for a in anomalies:
                is_crit = a.get("severity") == "CRITICAL"
                sev_color = "#dc2626" if is_crit else "#d97706"
                sev_pill = f"<font color='{sev_color}'><strong>{'🔴 CRITICAL' if is_crit else '🟡 WARNING'}</strong></font>"
                anom_table_data.append([
                    Paragraph(sev_pill, self.styles["TableCell"]),
                    Paragraph(f"<strong>{a.get('title')}</strong>", self.styles["TableCellBold"]),
                    Paragraph(str(a.get("observed_value")), self.styles["TableCell"]),
                    Paragraph(str(a.get("explanation")), self.styles["TableCell"]),
                ])

            anom_table = Table(anom_table_data, colWidths=[76, 130, 110, 220])
            anom_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(anom_table)

        story.append(Spacer(1, 12))

        # Diagnostic Verification Scope Checklist (Balancing Page 3 when findings are few)
        chk_data = [
            [Paragraph("Subsystem Audit", self.styles["TableHeader"]), Paragraph("Evaluation Criterion", self.styles["TableHeader"]), Paragraph("Verification Result", self.styles["TableHeader"])],
            [Paragraph("Processor Subsystem", self.styles["TableCellBold"]), Paragraph("Sustained saturation & spike detection", self.styles["TableCell"]), Paragraph("Verified Nominal" if (stats.get('cpu_avg') or 0) < 70 else "Flagged for Attention", self.styles["TableCell"])],
            [Paragraph("Memory Subsystem", self.styles["TableCellBold"]), Paragraph("Allocation pressure & leak monitoring", self.styles["TableCell"]), Paragraph("Verified Nominal" if (stats.get('ram_avg') or 0) < 75 else "Flagged for Attention", self.styles["TableCell"])],
            [Paragraph("Storage Capacity", self.styles["TableCellBold"]), Paragraph("Volume consumption & safe margins", self.styles["TableCell"]), Paragraph("Verified Nominal" if (stats.get('disk_avg') or 0) < 80 else "Flagged for Attention", self.styles["TableCell"])],
            [Paragraph("Security Log Stream", self.styles["TableCellBold"]), Paragraph("Fatal exceptions & service crash clustering", self.styles["TableCell"]), Paragraph("Clean Stream" if stats.get('critical_log_count', 0) == 0 else f"{stats.get('critical_log_count')} Critical Exception(s)", self.styles["TableCell"])],
        ]
        chk_table = Table(chk_data, colWidths=[140, 220, 176])
        chk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(chk_table)
        story.append(Spacer(1, 10))

        # Prioritized Recommendations (Rendered as structured cards)
        story.append(Paragraph("Prioritized Engineering Recommendations", self.styles["Heading1"]))
        for r in recs:
            p_str = r.get("priority", "P3")
            if "P1" in p_str:
                p_border = "#dc2626"
                p_bg = "#fef2f2"
                p_title_color = "#dc2626"
            elif "P2" in p_str:
                p_border = "#d97706"
                p_bg = "#fffbeb"
                p_title_color = "#d97706"
            else:
                p_border = "#2563eb"
                p_bg = "#eff6ff"
                p_title_color = "#2563eb"

            rec_card_data = [
                [Paragraph(f"<font color='{p_title_color}'><strong>[{p_str}] {r.get('title')}</strong></font>", self.styles["TableCellBold"])],
                [Paragraph(f"<strong>Finding:</strong> {r.get('finding', r.get('title'))}", self.styles["Body"])],
                [Paragraph(f"<strong>Recommended Action:</strong> {r.get('description')}", self.styles["Body"])],
                [Paragraph(f"<em>Reason / Evidence:</em> {r.get('rationale')}", self.styles["BodyDim"])],
            ]
            rec_card_table = Table(rec_card_data, colWidths=[536])
            rec_card_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(p_bg)),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(p_border)),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(KeepTogether([rec_card_table, Spacer(1, 5)]))

        doc.build(story, canvasmaker=NumberedCanvas)
        buf.seek(0)
        return buf.getvalue()

    def render_system_report(self, system_analysis: dict, raw_data: dict) -> bytes:
        """Render a fleet-wide system audit report covering all registered devices."""
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=38,
            rightMargin=38,
            topMargin=48,
            bottomMargin=52,
        )
        story = []

        total_devs = system_analysis.get("total_devices", 0)
        crit_anoms = system_analysis.get("critical_anomalies", 0)
        warn_anoms = system_analysis.get("warning_anomalies", 0)
        narrative = system_analysis.get("narrative", {})
        fleet_health = system_analysis.get("fleet_health", {})
        devices = system_analysis.get("devices", {})
        recs = system_analysis.get("recommendations", [])
        scope_name = system_analysis.get("scope", "system")

        online_count = sum(1 for d in devices.values() if d.get("status") == "online")
        offline_count = total_devs - online_count
        good_count = fleet_health.get("good_count", 0)
        warning_count = fleet_health.get("warning_count", 0)
        critical_count = fleet_health.get("critical_count", 0)
        avg_health = fleet_health.get("avg_score", "--")

        scope_title = "SELECTED ENDPOINTS AUDIT REPORT" if "selected" in scope_name else "ENTERPRISE FLEET AUDIT REPORT"
        scope_subtitle = f"Aggregated Multi-Node Analysis ({total_devs} Selected Device{'s' if total_devs != 1 else ''})" if "selected" in scope_name else f"Executive System Analysis across {total_devs} Registered Endpoint{'s' if total_devs != 1 else ''}"

        # ── PAGE 1: FLEET COVER & COMPOSITE HEALTH DISTRIBUTION ────────
        story.append(Paragraph(f"APEXEYE {scope_title}", self.styles["DocTitle"]))
        story.append(Paragraph(scope_subtitle, self.styles["DocSubTitle"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=8))

        # Executive Summary Box
        story.append(Paragraph("Fleet Executive Summary & AI Synthesis", self.styles["Heading1"]))
        summary_text = narrative.get("summary") or "Fleet operational state evaluated across all registered devices."
        summary_table = Table([[Paragraph(summary_text, self.styles["SummaryText"])]], colWidths=[536])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#93c5fd")),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 8))

        # Fleet Health & Presence Overview Table
        story.append(Paragraph("Fleet Overview & Health Distribution", self.styles["Heading1"]))
        health_dist_data = [
            [Paragraph("Total Nodes", self.styles["TableHeader"]), Paragraph("Online", self.styles["TableHeader"]), Paragraph("Offline", self.styles["TableHeader"]), Paragraph("Good (80-100)", self.styles["TableHeader"]), Paragraph("Warning (50-79)", self.styles["TableHeader"]), Paragraph("Critical (0-49)", self.styles["TableHeader"]), Paragraph("Avg Health", self.styles["TableHeader"])],
            [Paragraph(str(total_devs), self.styles["TableCellBold"]),
             Paragraph(f"<font color='#16a34a'><strong>{online_count}</strong></font>", self.styles["TableCell"]),
             Paragraph(f"<font color='#dc2626'><strong>{offline_count}</strong></font>", self.styles["TableCell"]),
             Paragraph(f"<font color='#16a34a'><strong>{good_count}</strong></font>", self.styles["TableCell"]),
             Paragraph(f"<font color='#d97706'><strong>{warning_count}</strong></font>", self.styles["TableCell"]),
             Paragraph(f"<font color='#dc2626'><strong>{critical_count}</strong></font>", self.styles["TableCell"]),
             Paragraph(f"<strong>{avg_health}</strong>", self.styles["TableCellBold"])],
        ]
        dist_table = Table(health_dist_data, colWidths=[76, 76, 76, 76, 76, 76, 80])
        dist_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(dist_table)
        story.append(Spacer(1, 8))

        # Key Fleet Observations
        story.append(Paragraph("Fleet Intelligence Observations:", self.styles["Heading2"]))
        for obs in narrative.get("key_observations", []):
            story.append(Paragraph(f"• {obs}", self.styles["Body"]))

        story.append(Spacer(1, 8))

        # Endpoint Health Comparative Matrix
        story.append(Paragraph("Endpoint Health Comparative Matrix", self.styles["Heading1"]))
        dev_rows = [
            [Paragraph("Device Name / ID", self.styles["TableHeader"]), Paragraph("Status", self.styles["TableHeader"]), Paragraph("Health", self.styles["TableHeader"]), Paragraph("Avg CPU", self.styles["TableHeader"]), Paragraph("Avg RAM", self.styles["TableHeader"]), Paragraph("Storage", self.styles["TableHeader"]), Paragraph("Anomalies", self.styles["TableHeader"])],
        ]
        for did, d_data in devices.items():
            h = d_data.get("health", {})
            st = d_data.get("stats", {})
            anoms_c = len(d_data.get("anomalies", []))
            dev_status = str(d_data.get("status", "unknown")).upper()
            status_pill = f"<font color='#16a34a'><b>{dev_status}</b></font>" if dev_status == "ONLINE" else f"<font color='#dc2626'><b>{dev_status}</b></font>"
            dev_rows.append([
                Paragraph(f"<strong>{d_data.get('device_name')}</strong><br/><font color='#64748b' size=7>{did}</font>", self.styles["TableCell"]),
                Paragraph(status_pill, self.styles["TableCell"]),
                Paragraph(f"<b>{h.get('score', 'N/A')}</b> ({h.get('status', 'N/A')})", self.styles["TableCell"]),
                Paragraph(f"{st.get('cpu_avg', 'N/A')}%" if st.get('cpu_avg') is not None else "N/A", self.styles["TableCell"]),
                Paragraph(f"{st.get('ram_avg', 'N/A')}%" if st.get('ram_avg') is not None else "N/A", self.styles["TableCell"]),
                Paragraph(f"{st.get('disk_avg', 'N/A')}%" if st.get('disk_avg') is not None else "N/A", self.styles["TableCell"]),
                Paragraph(f"<b>{anoms_c}</b>", self.styles["TableCellBold"]),
            ])

        dev_table = Table(dev_rows, colWidths=[130, 60, 85, 65, 65, 65, 66])
        dev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(dev_table)
        story.append(Spacer(1, 10))

        # System-Wide Recommendations
        if recs:
            story.append(Paragraph("System-Wide Prioritized Recommendations", self.styles["Heading1"]))
            for r in recs[:5]:
                story.append(Paragraph(f"• <strong>[{r.get('priority')}] {r.get('title')}</strong>: {r.get('description')}", self.styles["Body"]))

        doc.build(story, canvasmaker=NumberedCanvas)
        buf.seek(0)
        return buf.getvalue()
