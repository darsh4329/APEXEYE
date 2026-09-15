"""
Compare default vs optimized Jinja2 in separate subprocesses.
"""
import sys
import os
import gc
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.ui.dashboard import create_client_ui_app
from client.app.communication import MasterConnection
from client.app.auth import ClientAuth

class DummyConn:
    def __init__(self):
        self.master_url = "http://127.0.0.1:9100"
        self.is_authenticated = True

def run(mode="default"):
    p = psutil.Process()
    gc.collect()
    r0 = p.memory_info().rss / (1024 * 1024)

    conn = DummyConn()
    auth = ClientAuth(conn)
    auth._authenticated = True
    auth._device_id = "TEST-DEV"

    app = create_client_ui_app(auth, conn)
    if mode == "optimized":
        app.config["TEMPLATES_AUTO_RELOAD"] = False
        app.jinja_env.cache_size = 5

    c = app.test_client()
    for _ in range(5):
        c.get("/")
    gc.collect()
    r1 = p.memory_info().rss / (1024 * 1024)
    print(f"[{mode.upper()}] Initial: {r0:.2f} MB -> After rendering: {r1:.2f} MB (Delta: +{r1 - r0:.2f} MB)", flush=True)

if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else "default"
    run(m)
