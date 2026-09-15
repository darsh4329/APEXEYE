"""
APEXEYE MASTER — Recommendation Engine (Phase 8 & 9.1)

Generates evidence-driven, prioritized engineering recommendations based on
empirically observed anomalies and telemetry metrics.
"""


class RecommendationEngine:
    """Produces prioritized recommendations from detected anomalies and telemetry."""

    def generate_recommendations(self, device_data: dict, anomalies: list[dict]) -> list[dict]:
        """
        Generate ranked recommendations for a single device dataset.
        Returns a list of dicts:
          - priority: P1 - IMMEDIATE | P2 - MAINTENANCE | P3 - OPTIMIZATION
          - title: str
          - finding: str
          - description: str
          - rationale: str
          - category: str
        """
        if not device_data.get("exists"):
            return []

        recs = []
        seen_topics = set()

        # 1. Process CRITICAL anomalies (P1 - IMMEDIATE)
        for a in anomalies:
            if a.get("severity") == "CRITICAL":
                cat = a.get("category", "SYSTEM")
                if cat not in seen_topics:
                    seen_topics.add(cat)
                    finding = a.get("observed_value") or a.get("explanation") or "Critical threshold exceeded"
                    recs.append({
                        "priority": "P1 - IMMEDIATE",
                        "title": f"Address {a.get('title')}",
                        "finding": f"{a.get('title')}: {finding}",
                        "description": a.get("recommendation", "Investigate critical anomaly immediately."),
                        "rationale": a.get("explanation", "Critical threshold exceeded. Endpoint stability is at risk."),
                        "category": cat,
                    })

        # 2. Process WARNING anomalies (P2 - MAINTENANCE)
        for a in anomalies:
            if a.get("severity") == "WARNING":
                cat = a.get("category", "SYSTEM")
                if cat not in seen_topics:
                    seen_topics.add(cat)
                    finding = a.get("observed_value") or a.get("explanation") or "Elevated threshold observed"
                    recs.append({
                        "priority": "P2 - MAINTENANCE",
                        "title": f"Review {a.get('title')}",
                        "finding": f"{a.get('title')}: {finding}",
                        "description": a.get("recommendation", "Inspect elevated operational condition."),
                        "rationale": a.get("explanation", "Operational threshold warning. Preventative maintenance advised."),
                        "category": cat,
                    })

        # 3. If healthy with 0 anomalies (Evidence-driven normal device recommendation)
        if not recs:
            stats = device_data.get("stats", {})
            cpu_avg = stats.get("cpu_avg")
            ram_avg = stats.get("ram_avg")
            disk_avg = stats.get("disk_avg")
            
            if cpu_avg is not None and ram_avg is not None:
                finding_text = f"CPU averaged {cpu_avg:.1f}%, RAM averaged {ram_avg:.1f}%, Storage is at {disk_avg or 0:.1f}%."
            else:
                finding_text = "All available metrics operating within nominal boundaries."

            recs.append({
                "priority": "P3 - OPTIMIZATION",
                "title": "Maintain Baseline Monitoring",
                "finding": finding_text,
                "description": "No major intervention required. Continue routine telemetry collection and scheduled monitoring.",
                "rationale": "Empirical CPU, Memory, Storage, and Connectivity metrics are healthy with zero critical events.",
                "category": "MAINTENANCE",
            })

        return recs
