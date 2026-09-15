"""
APEXEYE MASTER — Entry Point

Initializes the database, logging, and starts the API server.
"""

import sys
from pathlib import Path

# Ensure the project root is on sys.path so imports work when running directly
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.config import config
from master.app.database import init_database, check_database_health
from master.app.utils.logger import get_logger


def main() -> None:
    logger = get_logger("apexeye.master")

    logger.info("=" * 60)
    logger.info("%s v%s", config.APP_NAME, config.VERSION)
    logger.info("Environment: %s", config.ENV)
    logger.info("=" * 60)

    # ── Initialize database ──────────────────────────────────────
    logger.info("Initializing database …")
    init_database()

    health = check_database_health()
    if health["ok"]:
        logger.info(
            "Database healthy — tables: %s",
            ", ".join(health["tables"]),
        )
    else:
        logger.error("Database health check failed: %s", health["error"])
        sys.exit(1)

    # ── Start CCTV Background Monitor (Phase 4) ─────────────────
    from master.app.services.cctv_monitor import cctv_monitor_engine

    logger.info("Starting CCTV background monitoring engine …")
    cctv_monitor_engine.start()

    # ── Start Device Presence Monitor ────────────────────────────
    from master.app.services.presence_service import presence_monitor_engine

    logger.info("Starting Master device presence monitoring engine …")
    presence_monitor_engine.start()

    # ── Start LAN Discovery Service (UDP 9101) ─────────────────
    from master.app.services.discovery import master_discovery_service

    logger.info("Starting Master LAN discovery service …")
    master_discovery_service.start()

    # ── Start API server (Phase 1) ───────────────────────────────
    from master.app.api import create_app
    from master.app.utils.network import format_network_banner

    app = create_app()
    banner = format_network_banner(config.HOST, config.PORT)
    print("\n" + banner + "\n")
    logger.info(
        "Starting Master API server on %s:%s (Local Admin: http://127.0.0.1:%s, Primary LAN: %s) …",
        config.HOST,
        config.PORT,
        config.PORT,
        config.lan_url,
    )
    app.run(host=config.HOST, port=config.PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
