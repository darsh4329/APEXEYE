"""
APEXEYE MASTER — API Application Factory

Creates and configures the Flask application with all Phase 1 + Phase 2 routes.
"""

from flask import Flask

from master.app.database import init_database
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api")


def create_app() -> Flask:
    """Build and return the configured Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # Ensure DB is ready
    init_database()

    # Register Phase 1 blueprints
    from master.app.api.devices import devices_bp
    from master.app.api.dashboard import dashboard_bp
    from master.app.api.client_api import client_api_bp

    app.register_blueprint(devices_bp, url_prefix="/api")
    app.register_blueprint(client_api_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp)

    # Register Phase 2 blueprints
    from master.app.api.telemetry import telemetry_bp
    from master.app.api.events_api import events_bp
    from master.app.api.heartbeat_api import heartbeat_bp
    from master.app.api.host_info_api import host_info_bp

    app.register_blueprint(telemetry_bp, url_prefix="/api")
    app.register_blueprint(events_bp, url_prefix="/api")
    app.register_blueprint(heartbeat_bp, url_prefix="/api")
    app.register_blueprint(host_info_bp, url_prefix="/api")

    # Register health endpoint (unauthenticated — used for connectivity checks)
    from master.app.api.health import health_bp
    app.register_blueprint(health_bp, url_prefix="/api")

    # Register Phase 4 blueprints (CCTV Monitoring)
    from master.app.api.cctv_api import cctv_bp
    app.register_blueprint(cctv_bp, url_prefix="/api")

    # Register Phase 5 blueprints (Centralized Logs & Activity Search)
    from master.app.api.logs_api import logs_bp
    app.register_blueprint(logs_bp, url_prefix="/api")

    # Register Phase 6 blueprints (Device Health Score & Alert Assessment)
    from master.app.api.device_health_api import health_api_bp
    app.register_blueprint(health_api_bp, url_prefix="/api")

    # Register Phase 8 blueprints (AI Analysis & Anomaly Diagnostics)
    from master.app.api.ai_api import ai_api_bp
    app.register_blueprint(ai_api_bp, url_prefix="/api")

    # Register Phase 9 blueprints (PDF Reports)
    from master.app.api.reports_api import reports_bp
    app.register_blueprint(reports_bp, url_prefix="/api")

    # Register Phase 10 blueprints (Secure Command Center & Remote Operations)
    from master.app.api.commands_api import commands_bp
    app.register_blueprint(commands_bp)

    # Register AWS Cloud Monitoring blueprints
    from master.app.api.aws_api import aws_bp
    app.register_blueprint(aws_bp, url_prefix="/api")

    # Register Firewall subsystem (Phase 12)
    from master.app.api.firewall_api import firewall_bp
    app.register_blueprint(firewall_bp)

    # Phase 11: Security Hardening — Request limits & safe error handling
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB maximum request payload

    @app.after_request
    def set_security_headers(response):
        """Inject robust, dashboard-compatible HTTP security headers."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self';"
        )
        return response

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return {"error": "Payload Too Large: Request body exceeds maximum allowed size (10MB).", "status": 413}, 413

    # Start background presence monitor engine
    from master.app.services.presence_service import presence_monitor_engine
    presence_monitor_engine.start()

    logger.info("Flask application created with Phase 1-11 routes and security hardening.")
    return app

