"""
APEXEYE MASTER — Health Endpoint

Provides a simple, unauthenticated health check endpoint.
Clients use this to verify connectivity to the Master before
attempting registration or pairing.

GET /api/health — returns Master status and version
"""

from datetime import datetime, timezone

from flask import Blueprint, jsonify

from master.app.config import config
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.health")

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """
    Unauthenticated health endpoint.

    Returns basic Master status so clients can verify connectivity
    before attempting registration or pairing.
    """
    return jsonify({
        "status": "healthy",
        "app": config.APP_NAME,
        "version": config.VERSION,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "bind_address": f"{config.HOST}:{config.PORT}",
    })
