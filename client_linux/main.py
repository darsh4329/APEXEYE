"""
APEXEYE LINUX CLIENT — Entry Point (Phase 3)

Starts the client, performs Master discovery, serves the local pairing & dashboard UI (port 9200),
authenticates with Master, and runs the background telemetry/event/heartbeat agent.
Maintains strict behavioral parity with reference client implementation.
"""

import os
import sys
import time
import threading
import getpass
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from client_linux.app.config import config
from client_linux.app.utils.logger import get_logger
from client_linux.app.communication import MasterConnection
from client_linux.app.auth import ClientAuth
from client_linux.app.ui.dashboard import start_client_ui_server
from client_linux.app.agent import Agent


def open_login_page(url: str) -> bool:
    """
    Open the APEXEYE pairing / enrollment page in the user's default browser.
    Gracefully handles headless Linux environments without raising exceptions.
    """
    logger = get_logger("apexeye.linux_client")
    try:
        import webbrowser
        return webbrowser.open(url)
    except Exception as exc:
        logger.warning("Could not launch default browser for %s: %s", url, exc)
        return False


launch_login_page = open_login_page


def prompt_client_authentication_async(auth: ClientAuth, authenticated_event: threading.Event, stop_event: threading.Event) -> None:
    """Prompt for credentials in terminal if interactive, without blocking the UI server."""
    client_ui_port = int(os.getenv("APEXEYE_CLIENT_UI_PORT", "9200"))
    print("\n" + "=" * 60)
    print("APEXEYE LINUX CLIENT — TERMINAL PAIRING PROMPT")
    print("=" * 60)
    print(f"Enter credentials below OR open http://127.0.0.1:{client_ui_port} in your browser.")
    print("=" * 60 + "\n")

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        if authenticated_event.is_set() or stop_event.is_set():
            return
        try:
            device_id = input(f"[{attempt}/{max_attempts}] Enter Device ID [{config.CLIENT_ID}]: ").strip()
            if authenticated_event.is_set() or stop_event.is_set():
                return
            if not device_id:
                device_id = config.CLIENT_ID

            try:
                token = getpass.getpass("Enter Authentication Token: ").strip()
            except Exception:
                token = input("Enter Authentication Token: ").strip()

            if authenticated_event.is_set() or stop_event.is_set():
                return

            if not token:
                print("✗ Error: Authentication Token cannot be empty.\n")
                continue

            print("Verifying credentials with Master …")
            ok, msg = auth.authenticate(device_id, token)
            if ok:
                print(f"\n✓ {msg}\n")
                auth.conn.set_identity(device_id, token)
                authenticated_event.set()
                return
            else:
                print(f"\n✗ {msg}\n")
        except (KeyboardInterrupt, EOFError):
            return

    print(f"Terminal authentication attempts ended. Use http://127.0.0.1:{client_ui_port} in your browser to pair.\n")


def main() -> None:
    logger = get_logger("apexeye.linux_client")

    client_ui_port = int(os.getenv("APEXEYE_CLIENT_UI_PORT", "9200"))
    runtime_root = str(getattr(config, "_PROJECT_ROOT", Path(__file__).resolve().parent))

    print("\n" + "=" * 60)
    print("APEXEYE CONFIG RESOLUTION")
    print("-" * 60)
    print(f".env discovered        : {'YES' if getattr(config, 'env_discovered', bool(config.loaded_env_path)) else 'NO'}")
    print(f".env path              : {config.loaded_env_path or 'NONE'}")
    print(f".env contains MASTER   : {'YES' if getattr(config, 'env_contains_master', False) else 'NO'}")
    print(f"Parsed MASTER URL      : {getattr(config, 'parsed_master_url', None) or 'NONE'}")
    print(f"Process env MASTER     : {'SET' if getattr(config, 'process_env_master_set', False) else 'NOT SET'}")
    print(f"LAN discovery attempted: {'YES' if getattr(config, 'lan_discovery_attempted', False) else 'NO'}")
    print(f"LAN discovery result   : {getattr(config, 'lan_discovery_result', None) or 'NONE'}")
    print(f"Hostname discovery     : {getattr(config, 'hostname_discovery_result', None) or 'NONE'}")
    print(f"Cache discovery        : {getattr(config, 'cache_discovery_result', None) or 'NONE'}")
    print(f"Final MASTER URL       : {config.master_url}")
    print(f"Final source           : {config.source}")
    print("=" * 60)

    print("\n" + "=" * 60)
    print("APEXEYE LINUX CLIENT CONFIGURATION")
    print("=" * 60)
    print(f"Client Runtime Root : {runtime_root}")
    print(f"Configuration File  : {config.loaded_env_path or 'NONE'}")
    print(f"Configuration Source: {config.source}")
    print(f"Master URL          : {config.master_url}")
    print(f"Target Host         : {config.target_host}")
    print(f"Target Port         : {config.target_port}")
    print(f"Local Client UI     : http://127.0.0.1:{client_ui_port}")
    print("=" * 60)

    logger.info("=" * 60)
    logger.info("%s v%s", config.APP_NAME, config.VERSION)
    logger.info("Client ID            : %s", config.CLIENT_ID)
    logger.info("Device Type          : %s", config.DEVICE_TYPE)
    logger.info("Master URL           : %s", config.master_url)
    logger.info("Configuration Source : %s", config.source)
    logger.info("Loaded .env          : %s", config.loaded_env_path or "NONE")
    logger.info("=" * 60)

    if config.is_localhost_target:
        print("\n" + "=" * 60)
        print("WARNING: LOCALHOST DEFAULT IN USE")
        print("=" * 60)
        print("No remote APEXEYE_MASTER_URL configuration was selected and no LAN Master was discovered.")
        print(f"The client is currently targeting localhost: {config.master_url}")
        print("\n127.0.0.1 means THIS LINUX COMPUTER.")
        print("It does NOT refer to the remote Master PC.")
        print("\nFor a physical two-PC LAN deployment, ensure Master is running on 0.0.0.0:9100 on the same network,")
        print("or explicitly configure APEXEYE_MASTER_URL=http://<MASTER-LAN-IP>:9100 in .env")
        print("=" * 60 + "\n")

    # ── Pre-flight Health & Connectivity Check ───────────────────
    print("\nTesting Master connectivity...")
    conn = MasterConnection(config.master_url)
    report = conn.check_master_connectivity()
    tcp_ok = report.get("tcp_ok", False)
    http_ok = report.get("http_ok", False)
    health_data = report.get("health_data", {})

    print(f"  TCP {config.target_port:<15}: {'PASS' if tcp_ok else 'FAIL'}")
    print(f"  HTTP /api/health   : {'PASS' if http_ok else 'FAIL'}")
    print("=" * 60 + "\n")

    if http_ok:
        logger.info("Master reachable. Health status: %s (v%s)", health_data.get("status", "healthy"), health_data.get("version", "unknown"))
    else:
        logger.warning("Initial Master connection at %s failed: %s", config.master_url, report.get("error"))
        # Attempt automatic rediscovery
        rediscovered = conn.attempt_rediscovery()
        if rediscovered:
            report = conn.check_master_connectivity()
            tcp_ok = report.get("tcp_ok", False)
            http_ok = report.get("http_ok", False)
            print(f"Master rediscovered at {conn.master_url}:")
            print(f"  TCP {config.target_port:<15}: {'PASS' if tcp_ok else 'FAIL'}")
            print(f"  HTTP /api/health   : {'PASS' if http_ok else 'FAIL'}")
            print("=" * 60 + "\n")

    from client_linux.app.services.command_handler import CommandHandler

    auth = ClientAuth(conn)
    authenticated_event = threading.Event()
    disconnect_event = threading.Event()
    stop_event = threading.Event()
    current_agent: Agent | None = None
    login_page_launched = False

    def on_authenticated(device_id: str, token: str):
        nonlocal login_page_launched
        logger.info("Linux client authenticated callback received for device %s", device_id)
        auth._authenticated = True
        conn.set_identity(device_id, token)
        login_page_launched = False
        authenticated_event.set()

    def on_disconnect_triggered(reason: str = "Master-forced re-authentication"):
        nonlocal current_agent
        if disconnect_event.is_set():
            return
        disconnect_event.set()
        logger.warning("Forced disconnect event triggered: %s", reason)
        auth._clear_credentials()
        conn.clear_identity()
        os.environ.pop("APEXEYE_AUTH_TOKEN", None)
        if current_agent and hasattr(current_agent, "_stop_event"):
            current_agent._stop_event.set()

    conn.set_unauthorized_callback(lambda resp: on_disconnect_triggered("401 Unauthorized from Master"))

    cmd_handler = CommandHandler(conn=conn, auth=auth)
    cmd_handler.set_disconnect_callback(lambda: on_disconnect_triggered("Command REAUTHENTICATE_AGENT received"))

    # Initialize FirewallAgent early so offline policy is enforced immediately at boot
    from client_linux.app.services.firewall_agent import FirewallAgent
    firewall_agent = FirewallAgent(conn, stop_event)
    firewall_agent.apply_cached_policy()

    # Start local Client Web UI server (provides browser-based Auth Screen on port 9200 & Dashboard)
    start_client_ui_server(
        auth,
        conn,
        port=client_ui_port,
        on_authenticated_callback=on_authenticated,
        cmd_handler=cmd_handler,
        firewall_agent=firewall_agent,
    )

    # Master-forced re-auth / pairing lifecycle loop
    while not stop_event.is_set():
        # 1. Check if already authenticated with stored credentials
        success = auth.pair()

        if not success:
            # Check environment variables
            env_dev = os.getenv("APEXEYE_DEVICE_ID")
            env_tok = os.getenv("APEXEYE_AUTH_TOKEN")
            if env_dev and env_tok:
                success = auth.pair(env_dev, env_tok)

        if success:
            conn.set_identity(auth.device_id, auth.token)
            login_page_launched = False
            authenticated_event.set()
        else:
            authenticated_event.clear()
            disconnect_event.clear()

            # Client enters WAITING_FOR_PAIRING state — DO NOT EXIT!
            print("\n" + "=" * 60)
            print("APEXEYE LINUX CLIENT")
            print("=" * 60)
            print(f"Master Connectivity:")
            print(f"    TCP {config.target_port:<15}: {'PASS' if tcp_ok else 'FAIL'}")
            print(f"    HTTP /api/health   : {'PASS' if http_ok else 'FAIL'}")
            print(f"\nMaster Endpoint:")
            print(f"    {conn.master_url}")
            print(f"\nDiscovery Source:")
            print(f"    {config.source}")
            print(f"\nAuthentication:")
            print(f"    NOT PAIRED (WAITING_FOR_PAIRING)")
            print(f"\nLocal Client UI:")
            print(f"    http://127.0.0.1:{client_ui_port}")
            print("\nWaiting for pairing credentials...")
            print("=" * 60 + "\n")

            # Open the APEXEYE login / enrollment page in user's default browser (exactly once per transition)
            if not login_page_launched:
                login_url = f"http://127.0.0.1:{client_ui_port}"
                open_login_page(login_url)
                login_page_launched = True

            # If interactive terminal, start asynchronous terminal prompt thread
            if sys.stdin.isatty():
                t_prompt = threading.Thread(
                    target=prompt_client_authentication_async,
                    args=(auth, authenticated_event, stop_event),
                    name="ApexEye-LinuxCliAuthPrompt",
                    daemon=True,
                )
                t_prompt.start()

            # Wait for authentication from Web UI or CLI
            try:
                while not authenticated_event.is_set() and not stop_event.is_set():
                    authenticated_event.wait(timeout=1.0)
            except KeyboardInterrupt:
                print("\nLinux client stopped by user.")
                stop_event.set()
                return

            if stop_event.is_set():
                return

        # Once authenticated:
        logger.info("=" * 60)
        logger.info("✓ PAIRED with Master successfully.")
        logger.info("  Device ID        : %s", auth.device_id)
        logger.info("  Master           : %s", conn.master_url)
        logger.info("  Client Dashboard : http://127.0.0.1:%s", client_ui_port)
        logger.info("  Status           : PAIRED / AUTHENTICATED")
        logger.info("=" * 60)

        # Start Agent
        logger.info("[AGENT] Starting monitoring agent")
        agent = Agent(conn, firewall_agent=firewall_agent)
        current_agent = agent
        agent.start()

        logger.info("=" * 60)
        logger.info("APEXEYE Linux Client Agent is running.")
        logger.info("Client Dashboard : http://127.0.0.1:%s", client_ui_port)
        logger.info("Press Ctrl+C to stop.")
        logger.info("=" * 60)

        # Block until interrupted or stopped (by stop() or forced disconnect)
        try:
            agent.wait()
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
            stop_event.set()

        # Ensure active agent workers are completely stopped and joined from main thread
        try:
            agent.stop(timeout=5.0)
        except Exception as exc:
            logger.debug("Error while stopping agent from main loop: %s", exc)
        current_agent = None

        if stop_event.is_set():
            break

        if disconnect_event.is_set():
            logger.warning(
                "Active session invalidated by Master. Transitioning to WAITING_FOR_PAIRING."
            )
            authenticated_event.clear()
            disconnect_event.clear()
        else:
            break

    logger.info("APEXEYE Linux Client Agent shut down cleanly.")


if __name__ == "__main__":
    main()
