"""
Background daemon to serve Master API on 9100 and BlockServer on 80/443 for browser testing.
"""

import sys
import threading
import time
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.database import init_database
from master.app.api import create_app
from master.app.services.firewall_service import FirewallService
from client.app.services.block_server import BlockServer
from client.app.services.firewall_agent import FirewallAgent
from unittest.mock import MagicMock


def run_servers():
    init_database()
    fw_service = FirewallService()
    try:
        fw_service.add_domain("fitgirl-repacks.site")
    except ValueError:
        pass
    fw_service.set_enabled(True)

    # Master Flask app
    app = create_app()
    t_master = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=9100, debug=False, use_reloader=False),
        daemon=True,
    )
    t_master.start()

    mock_conn = MagicMock()
    mock_conn.is_authenticated = True
    mock_conn._device_id = "WORKSTATION-DELL"
    mock_conn.get_firewall_policy.side_effect = lambda: fw_service.get_policy()
    mock_conn.report_blocked_attempt.side_effect = lambda **kw: fw_service.log_blocked_attempt(
        device_id="WORKSTATION-DELL",
        device_name="Operator-PC",
        domain=kw.get("domain", ""),
        url=kw.get("url", ""),
        platform="Windows 11",
        policy_version=kw.get("policy_version", 1),
    )

    stop_ev = threading.Event()
    agent = FirewallAgent(mock_conn, stop_ev)
    agent._current_policy = fw_service.get_policy()

    bs = BlockServer(agent, http_port=80, https_port=443)
    ok, err = bs.start()
    if not ok:
        print(f"FAILED TO START BLOCKSERVER: {err}")
        sys.exit(1)

    print("SERVERS_READY: Master on http://127.0.0.1:9100 and BlockServer on http://127.0.0.1:80")
    sys.stdout.flush()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        bs.stop()


if __name__ == "__main__":
    run_servers()
