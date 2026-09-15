"""
APEXEYE MASTER — Deterministic Anomaly Detection Engine (Phase 8)

Calculates verifiable, deterministic anomalies from real telemetry time-series
and event logs without hallucination or fabrication.
Serves as the deterministic ground truth for AI explanation and reporting.
"""

from typing import Any


class AnomalyDetectionEngine:
    """Evaluates telemetry and event patterns to detect operational anomalies."""

    def detect_device_anomalies(self, device_data: dict) -> list[dict]:
        """
        Analyze isolated device dataset and produce structured anomalies.
        Returns a list of dicts with keys:
          - id: str
          - category: CPU | MEMORY | STORAGE | NETWORK | APPLICATION | LOGS | CONNECTIVITY
          - severity: CRITICAL | WARNING | NORMAL
          - title: str
          - observed_value: str
          - baseline: str
          - timestamp: str | None
          - explanation: str
          - recommendation: str
          - confidence: float (0.0 - 1.0)
        """
        if not device_data.get("exists"):
            return []

        anomalies = []
        dev_name = device_data["device"].get("device_name") or device_data["device"].get("device_id")
        dev_status = device_data["device"].get("status")
        telemetry = device_data.get("telemetry", [])
        logs = device_data.get("logs", [])
        stats = device_data.get("stats", {})

        # ── 1. CONNECTIVITY ANOMALIES ──────────────────────────────────
        if dev_status == "offline":
            anomalies.append({
                "id": "ANOM-CONN-OFFLINE",
                "category": "CONNECTIVITY",
                "severity": "CRITICAL",
                "title": "Device Offline",
                "observed_value": "Offline",
                "baseline": "Online (3s heartbeat)",
                "timestamp": device_data["device"].get("last_seen"),
                "explanation": f"Device {dev_name} is currently offline and not responding to heartbeats.",
                "recommendation": "Check network connectivity, device power, and client agent daemon status.",
                "confidence": 1.0,
            })

        # ── 2. CPU ANOMALIES ──────────────────────────────────────────
        cpu_vals = [t["cpu_usage"] for t in telemetry if t.get("cpu_usage") is not None]
        if cpu_vals:
            max_cpu = max(cpu_vals)
            avg_cpu = sum(cpu_vals) / len(cpu_vals)
            high_cpu_count = sum(1 for c in cpu_vals if c >= 90.0)

            if max_cpu >= 95.0 or (high_cpu_count >= 2 and avg_cpu >= 85.0):
                # Find timestamp of maximum CPU
                max_rec = next((t for t in telemetry if t.get("cpu_usage") == max_cpu), None)
                ts = max_rec["timestamp"] if max_rec else None

                # Check if an application started shortly before the CPU peak
                correlated_app = self._find_correlated_app_start(logs, ts)
                corr_note = f" (CPU increased shortly after {correlated_app} opened)" if correlated_app else ""

                anomalies.append({
                    "id": "ANOM-CPU-CRITICAL-SATURATION",
                    "category": "CPU",
                    "severity": "CRITICAL",
                    "title": "Critical CPU Saturation",
                    "observed_value": f"{max_cpu:.1f}% peak (avg {avg_cpu:.1f}%)",
                    "baseline": "< 70.0% nominal",
                    "timestamp": ts,
                    "explanation": f"Device {dev_name} experienced sustained processor saturation reaching {max_cpu:.1f}%.{corr_note}",
                    "recommendation": "Inspect background processes, active application compute requirements, and CPU cooling.",
                    "confidence": 0.95,
                })
            elif max_cpu >= 80.0 or avg_cpu >= 75.0:
                anomalies.append({
                    "id": "ANOM-CPU-ELEVATED-LOAD",
                    "category": "CPU",
                    "severity": "WARNING",
                    "title": "Elevated CPU Utilization",
                    "observed_value": f"{max_cpu:.1f}% peak (avg {avg_cpu:.1f}%)",
                    "baseline": "< 70.0% nominal",
                    "timestamp": None,
                    "explanation": f"Processor workload was consistently elevated on {dev_name} during the reporting period.",
                    "recommendation": "Review high-consumption tasks and optimize routine application scheduling.",
                    "confidence": 0.90,
                })

            # Check for sudden CPU spike (> 40% jump between consecutive telemetry points)
            for i in range(1, len(telemetry)):
                prev = telemetry[i-1].get("cpu_usage")
                curr = telemetry[i].get("cpu_usage")
                if prev is not None and curr is not None and (curr - prev) >= 40.0 and curr >= 80.0:
                    anomalies.append({
                        "id": f"ANOM-CPU-SPIKE-{telemetry[i].get('id')}",
                        "category": "CPU",
                        "severity": "WARNING",
                        "title": "Sudden CPU Spike",
                        "observed_value": f"+{curr - prev:.1f}% jump (to {curr:.1f}%)",
                        "baseline": f"{prev:.1f}% baseline",
                        "timestamp": telemetry[i].get("timestamp"),
                        "explanation": f"CPU utilization spiked abruptly from {prev:.1f}% to {curr:.1f}%.",
                        "recommendation": "Check for bursty foreground tasks, compilation jobs, or sudden process initialization.",
                        "confidence": 0.88,
                    })
                    break  # One spike highlight is sufficient

        # ── 3. RAM ANOMALIES ──────────────────────────────────────────
        ram_vals = [t["memory_usage"] for t in telemetry if t.get("memory_usage") is not None]
        if ram_vals:
            max_ram = max(ram_vals)
            avg_ram = sum(ram_vals) / len(ram_vals)
            if max_ram >= 90.0:
                anomalies.append({
                    "id": "ANOM-RAM-CRITICAL-PRESSURE",
                    "category": "MEMORY",
                    "severity": "CRITICAL",
                    "title": "Critical Memory Pressure",
                    "observed_value": f"{max_ram:.1f}%",
                    "baseline": "< 75.0% nominal",
                    "timestamp": None,
                    "explanation": f"Physical memory utilization reached {max_ram:.1f}%, increasing paging and swap risk.",
                    "recommendation": "Review memory-heavy applications and consider adding RAM capacity if sustained.",
                    "confidence": 0.95,
                })
            elif max_ram >= 80.0:
                anomalies.append({
                    "id": "ANOM-RAM-HIGH-USAGE",
                    "category": "MEMORY",
                    "severity": "WARNING",
                    "title": "High Memory Utilization",
                    "observed_value": f"{max_ram:.1f}%",
                    "baseline": "< 75.0% nominal",
                    "timestamp": None,
                    "explanation": f"Memory consumption approached threshold limits ({max_ram:.1f}%).",
                    "recommendation": "Monitor active services for persistent memory retention or memory leaks.",
                    "confidence": 0.85,
                })

        # ── 4. STORAGE ANOMALIES ──────────────────────────────────────
        disk_vals = [t["disk_usage"] for t in telemetry if t.get("disk_usage") is not None]
        if disk_vals:
            max_disk = max(disk_vals)
            if max_disk >= 90.0:
                anomalies.append({
                    "id": "ANOM-DISK-CRITICAL-CAPACITY",
                    "category": "STORAGE",
                    "severity": "CRITICAL",
                    "title": "Critical Storage Capacity",
                    "observed_value": f"{max_disk:.1f}% full",
                    "baseline": "< 80.0% safe margin",
                    "timestamp": None,
                    "explanation": f"Primary drive volume has reached critical capacity ({max_disk:.1f}% utilized).",
                    "recommendation": "Clean up temporary files, archive stale log files, or expand disk storage.",
                    "confidence": 0.98,
                })
            elif max_disk >= 80.0:
                anomalies.append({
                    "id": "ANOM-DISK-WARNING-CAPACITY",
                    "category": "STORAGE",
                    "severity": "WARNING",
                    "title": "Elevated Storage Utilization",
                    "observed_value": f"{max_disk:.1f}% full",
                    "baseline": "< 80.0% safe margin",
                    "timestamp": None,
                    "explanation": f"Drive storage utilization is elevated at {max_disk:.1f}%.",
                    "recommendation": "Plan disk maintenance before free space drops below critical thresholds.",
                    "confidence": 0.90,
                })

        # ── 5. APPLICATION CRASH / RESTART LOOPS ───────────────────────
        app_summary = device_data.get("app_summary", {})
        freqs = app_summary.get("app_frequencies", {})
        for app_name, count in freqs.items():
            if count >= 4:
                anomalies.append({
                    "id": f"ANOM-APP-RESTART-LOOP-{app_name}",
                    "category": "APPLICATION",
                    "severity": "WARNING",
                    "title": f"Frequent Application Restart Cycle ({app_name})",
                    "observed_value": f"{count} open/restart events",
                    "baseline": "Normal continuous operation",
                    "timestamp": None,
                    "explanation": f"Application '{app_name}' was opened/restarted {count} times within the reporting period.",
                    "recommendation": f"Investigate potential crashes, unexpected exits, or aggressive watchdog restarts for {app_name}.",
                    "confidence": 0.85,
                })

        # ── 6. LOG EVENT CLUSTERS ─────────────────────────────────────
        crit_logs = stats.get("critical_log_count", 0)
        warn_logs = stats.get("warning_log_count", 0)
        if crit_logs >= 2:
            anomalies.append({
                "id": "ANOM-LOGS-CRITICAL-CLUSTER",
                "category": "LOGS",
                "severity": "CRITICAL",
                "title": "Critical Event Cluster",
                "observed_value": f"{crit_logs} critical events",
                "baseline": "0 critical events",
                "timestamp": None,
                "explanation": f"{crit_logs} critical events were recorded in the activity stream during this period.",
                "recommendation": "Examine the Centralized Activity Log stream to identify recurring fault sources.",
                "confidence": 0.95,
            })
        elif crit_logs == 1:
            anomalies.append({
                "id": "ANOM-LOGS-CRITICAL-SINGLE",
                "category": "LOGS",
                "severity": "WARNING",
                "title": "Critical Log Event Recorded",
                "observed_value": "1 critical event",
                "baseline": "0 critical events",
                "timestamp": None,
                "explanation": "A critical system or application error occurred during the reporting period.",
                "recommendation": "Review the event log details and verify service integrity.",
                "confidence": 0.90,
            })

        if warn_logs >= 6:
            anomalies.append({
                "id": "ANOM-LOGS-REPEATED-WARNINGS",
                "category": "LOGS",
                "severity": "WARNING",
                "title": "High Warning Volume",
                "observed_value": f"{warn_logs} warnings",
                "baseline": "< 3 warnings",
                "timestamp": None,
                "explanation": f"Elevated volume of warnings ({warn_logs}) logged during the reporting window.",
                "recommendation": "Review non-fatal diagnostic logs to prevent degradation into critical faults.",
                "confidence": 0.82,
            })

        return anomalies

    def _find_correlated_app_start(self, logs: list[dict], peak_timestamp: str | None) -> str | None:
        """
        Check if an APPLICATION_STARTED event occurred within ~60 seconds before peak_timestamp.
        Does not fabricate causation.
        """
        if not peak_timestamp or not logs:
            return None

        try:
            peak_dt = datetime.fromisoformat(peak_timestamp)
        except Exception:
            return None

        for l in reversed(logs):
            if l.get("event_type") == "APPLICATION_STARTED" and l.get("timestamp"):
                try:
                    app_dt = datetime.fromisoformat(l["timestamp"])
                    diff = (peak_dt - app_dt).total_seconds()
                    if 0 <= diff <= 90:
                        return l.get("application_name")
                except Exception:
                    pass
        return None
