"""
APEXEYE MASTER — AI Analysis & Diagnostics Service (Phase 8)

Orchestrates data extraction, deterministic anomaly detection, actionable recommendations,
and AI-driven summarization for single devices, selected devices, and the entire system.
Enforces strict device data isolation (WHERE device_id = ?).
"""

from master.app.services.report_data_builder import ReportDataBuilder
from master.app.services.anomaly_service import AnomalyDetectionEngine
from master.app.services.recommendation_engine import RecommendationEngine
from master.app.services.ai_provider import get_ai_provider, BaseAIProvider
from master.app.services.health_service import HealthService
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.ai_service")


class AIService:
    """Central AI Analysis Service for APEXEYE."""

    def __init__(
        self,
        data_builder: ReportDataBuilder | None = None,
        anomaly_engine: AnomalyDetectionEngine | None = None,
        rec_engine: RecommendationEngine | None = None,
        ai_provider: BaseAIProvider | None = None,
        health_service: HealthService | None = None,
    ):
        self.data_builder = data_builder or ReportDataBuilder()
        self.anomaly_engine = anomaly_engine or AnomalyDetectionEngine()
        self.rec_engine = rec_engine or RecommendationEngine()
        self.ai_provider = ai_provider or get_ai_provider()
        self.health_service = health_service or HealthService()

    def analyze_device(
        self,
        device_id: str,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict:
        """
        Execute full AI analysis on a single device with strict data isolation.
        """
        # 1. Build Isolated Dataset
        data = self.data_builder.build_single_device_data(device_id, start_time, end_time)
        if not data.get("exists"):
            return {
                "exists": False,
                "error": f"Device '{device_id}' not found.",
                "device_id": device_id,
            }

        # 2. Query Read-Only Health Score
        health = self.health_service.evaluate_device_health(device_id, persist_alerts=False)

        # 3. Detect Deterministic Anomalies
        anomalies = self.anomaly_engine.detect_device_anomalies(data)

        # 4. Generate Actionable Recommendations
        recommendations = self.rec_engine.generate_recommendations(data, anomalies)

        # 5. Generate AI Narrative
        narrative = self.ai_provider.generate_device_narrative(data, anomalies, recommendations)

        return {
            "exists": True,
            "device_id": device_id,
            "device_name": data["device"].get("device_name"),
            "operating_system": data["device"].get("operating_system"),
            "status": data["device"].get("status"),
            "start_time": data["start_time"],
            "end_time": data["end_time"],
            "health": health,
            "stats": data["stats"],
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "recommendations": recommendations,
            "narrative": narrative,
            "app_summary": data["app_summary"],
        }

    def analyze_system(
        self,
        device_ids: list[str] | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict:
        """
        Execute fleet-wide analysis across all or selected devices.
        """
        if device_ids:
            data = self.data_builder.build_multi_device_data(device_ids, start_time, end_time)
        else:
            data = self.data_builder.build_system_data(start_time, end_time)

        devices_analysis = {}
        all_anomalies = []
        all_recs = []

        for did, d_data in data.get("devices", {}).items():
            if d_data.get("exists"):
                anoms = self.anomaly_engine.detect_device_anomalies(d_data)
                recs = self.rec_engine.generate_recommendations(d_data, anoms)
                health = self.health_service.evaluate_device_health(did, persist_alerts=False)
                devices_analysis[did] = {
                    "device_id": did,
                    "device_name": d_data["device"].get("device_name"),
                    "status": d_data["device"].get("status"),
                    "health": health,
                    "stats": d_data["stats"],
                    "anomalies": anoms,
                    "recommendations": recs,
                }
                all_anomalies.extend(anoms)
                all_recs.extend(recs)

        narrative = self.ai_provider.generate_system_narrative(data, all_anomalies, all_recs)

        return {
            "scope": data.get("scope", "system"),
            "start_time": data["start_time"],
            "end_time": data["end_time"],
            "total_devices": len(devices_analysis),
            "fleet_health": self.health_service.get_fleet_health_summary(),
            "devices": devices_analysis,
            "total_anomalies": len(all_anomalies),
            "critical_anomalies": sum(1 for a in all_anomalies if a.get("severity") == "CRITICAL"),
            "warning_anomalies": sum(1 for a in all_anomalies if a.get("severity") == "WARNING"),
            "narrative": narrative,
            "recommendations": all_recs[:10],
        }

    # Backward compatibility with existing Phase 0 skeleton
    def analyze(self, data: dict) -> dict:
        device_id = data.get("device_id")
        if device_id:
            return self.analyze_device(device_id, data.get("start_time"), data.get("end_time"))
        return self.analyze_system(data.get("device_ids"), data.get("start_time"), data.get("end_time"))

    def summarize(self, report_data: dict) -> str:
        res = self.ai_provider.generate_system_narrative(report_data, [], [])
        return res.get("summary", "")
