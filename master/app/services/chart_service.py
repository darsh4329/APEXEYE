"""
APEXEYE MASTER — Chart Generation Service (Phase 9.2.1 Refined)

Renders high-resolution operational charts for PDF reports using Matplotlib.
Includes authoritative visual threshold context (<70% Healthy, 70-85% Elevated, 85-95% High, >=95% Critical).
Uses headless 'Agg' backend. Does not mutate database records or fabricate points.
"""

import io
import matplotlib
matplotlib.use("Agg")  # Headless rendering for server environment
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime


class ChartService:
    """Generates charts as in-memory image bytes for ReportLab embedding."""

    def __init__(self):
        # Configure dark/executive styling
        plt.style.use("dark_background")

    def _setup_figure(self, width: float = 7.0, height: float = 2.4):
        fig, ax = plt.subplots(figsize=(width, height), dpi=150)
        fig.patch.set_facecolor("#0f172a")
        ax.set_facecolor("#1e293b")
        ax.tick_params(colors="#94a3b8", labelsize=8)
        for spine in ax.spines.values():
            spine.set_color("#334155")
        ax.grid(True, linestyle="--", alpha=0.25, color="#64748b")
        return fig, ax

    def _fig_to_bytes(self, fig) -> bytes:
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close(fig)
        buf.seek(0)
        return buf.getvalue()

    def generate_resource_timeline_chart(
        self,
        telemetry: list[dict],
        metric_key: str,
        label: str,
        unit: str = "%",
        color: str = "#3b82f6",
    ) -> bytes | None:
        """Render a single resource time-series chart (e.g. CPU, RAM, Disk)."""
        valid_pts = []
        for t in telemetry:
            val = t.get(metric_key)
            ts = t.get("timestamp")
            if val is not None and ts:
                try:
                    dt = datetime.fromisoformat(ts)
                    valid_pts.append((dt, float(val)))
                except Exception:
                    pass

        if len(valid_pts) < 2:
            return None

        valid_pts.sort(key=lambda x: x[0])
        dts = [p[0] for p in valid_pts]
        vals = [p[1] for p in valid_pts]

        fig, ax = self._setup_figure()
        ax.plot(dts, vals, color=color, linewidth=2, label=label)
        ax.fill_between(dts, vals, alpha=0.2, color=color)

        if unit == "%":
            # Authoritative threshold guide lines matching HealthService
            ax.axhline(70, color="#f59e0b", linestyle=":", alpha=0.4, linewidth=1, label="Elevated (70%)")
            ax.axhline(85, color="#f97316", linestyle=":", alpha=0.4, linewidth=1, label="High (85%)")
            ax.axhline(95, color="#ef4444", linestyle=":", alpha=0.5, linewidth=1, label="Critical (95%)")
            ax.set_ylim(0, 105)

        ax.set_title(f"{label} Utilization Timeline ({unit})", fontsize=10, color="#f8fafc", weight="bold", pad=8)
        ax.set_ylabel(unit, fontsize=8, color="#94a3b8")
        ax.legend(loc="upper right", fontsize=7.5, facecolor="#0f172a", edgecolor="#334155")

        # Date formatting on X axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        fig.autofmt_xdate(rotation=0, ha="center")

        return self._fig_to_bytes(fig)

    def generate_combined_resources_chart(self, telemetry: list[dict]) -> bytes | None:
        """Render CPU, RAM, and Storage on a single comparative chart with authoritative threshold indicators."""
        pts = []
        for t in telemetry:
            ts = t.get("timestamp")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts)
                    c = t.get("cpu_usage")
                    r = t.get("memory_usage")
                    d = t.get("disk_usage")
                    if c is not None or r is not None or d is not None:
                        pts.append((dt, c, r, d))
                except Exception:
                    pass

        if len(pts) < 2:
            return None

        pts.sort(key=lambda x: x[0])
        dts = [p[0] for p in pts]
        cpu_v = [p[1] for p in pts]
        ram_v = [p[2] for p in pts]
        disk_v = [p[3] for p in pts]

        fig, ax = self._setup_figure(width=7.2, height=2.8)

        # Draw authoritative visual threshold reference lines
        ax.axhline(70, color="#eab308", linestyle=":", alpha=0.35, linewidth=0.9)
        ax.axhline(85, color="#f97316", linestyle=":", alpha=0.35, linewidth=0.9)
        ax.axhline(95, color="#ef4444", linestyle=":", alpha=0.45, linewidth=0.9)

        if any(c is not None for c in cpu_v):
            ax.plot(dts, [c or 0 for c in cpu_v], color="#ef4444", linewidth=2.0, label="CPU (%)")
        if any(r is not None for r in ram_v):
            ax.plot(dts, [r or 0 for r in ram_v], color="#3b82f6", linewidth=2.0, label="RAM (%)")
        if any(d is not None for d in disk_v):
            ax.plot(dts, [d or 0 for d in disk_v], color="#10b981", linewidth=2.0, label="Storage (%)")

        ax.set_title("Multi-Resource Telemetry Utilization Timeline", fontsize=10, color="#f8fafc", weight="bold", pad=8)
        ax.set_ylabel("Utilization (%)", fontsize=8, color="#94a3b8")
        ax.set_ylim(0, 105)
        ax.legend(loc="upper right", fontsize=8, facecolor="#0f172a", edgecolor="#334155")
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        fig.autofmt_xdate(rotation=0, ha="center")

        return self._fig_to_bytes(fig)

    def generate_health_trajectory_chart(self, telemetry: list[dict]) -> bytes | None:
        """Render device health score trajectory over time."""
        pts = []
        for t in telemetry:
            ts = t.get("timestamp")
            h = t.get("health_score")
            if ts and h is not None:
                try:
                    dt = datetime.fromisoformat(ts)
                    pts.append((dt, float(h)))
                except Exception:
                    pass

        if len(pts) < 2:
            return None

        pts.sort(key=lambda x: x[0])
        dts = [p[0] for p in pts]
        h_vals = [p[1] for p in pts]

        fig, ax = self._setup_figure(width=7.2, height=2.2)
        ax.plot(dts, h_vals, color="#22c55e", linewidth=2.2, label="Health Score")
        ax.fill_between(dts, h_vals, alpha=0.15, color="#22c55e")

        ax.axhline(80, color="#22c55e", linestyle="--", alpha=0.4, label="Good (>=80)")
        ax.axhline(50, color="#f59e0b", linestyle="--", alpha=0.4, label="Warning (50-79)")

        ax.set_title("Device Health Score Trajectory (0-100)", fontsize=10, color="#f8fafc", weight="bold", pad=8)
        ax.set_ylabel("Score", fontsize=8, color="#94a3b8")
        ax.set_ylim(0, 105)
        ax.legend(loc="lower right", fontsize=7.5, facecolor="#0f172a", edgecolor="#334155")
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        fig.autofmt_xdate(rotation=0, ha="center")

        return self._fig_to_bytes(fig)

    def generate_severity_distribution_chart(self, logs: list[dict]) -> bytes | None:
        """Render a clean pie chart showing log event severity breakdown."""
        if not logs:
            return None

        sev_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
        for l in logs:
            s = l.get("severity") or l.get("level") or "INFO"
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts["INFO"] += 1

        labels = []
        sizes = []
        colors = []
        color_map = {"INFO": "#3b82f6", "WARNING": "#f59e0b", "ERROR": "#f97316", "CRITICAL": "#ef4444"}

        for k, v in sev_counts.items():
            if v > 0:
                labels.append(f"{k} ({v})")
                sizes.append(v)
                colors.append(color_map[k])

        if not sizes:
            return None

        fig, ax = plt.subplots(figsize=(3.4, 2.1), dpi=150)
        fig.patch.set_facecolor("#0f172a")
        ax.set_facecolor("#0f172a")

        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            colors=colors,
            autopct="%1.0f%%",
            startangle=140,
            textprops={"color": "#f8fafc", "fontsize": 8},
        )
        for at in autotexts:
            at.set_fontsize(7.5)
            at.set_weight("bold")

        ax.set_title("Event Severity Distribution", fontsize=9, color="#f8fafc", weight="bold")
        return self._fig_to_bytes(fig)
