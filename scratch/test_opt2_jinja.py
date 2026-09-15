"""
Test OPT-2: Jinja2 auto-reload and template cache tuning impact.
"""
import sys
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

def test_jinja_tuning():
    p = psutil.Process()
    gc.collect()
    r0 = p.memory_info().rss / (1024 * 1024)

    conn = DummyConn()
    auth = ClientAuth(conn)
    auth._authenticated = True
    auth._device_id = "TEST-DEV"

    # Default app (with TEMPLATES_AUTO_RELOAD = True)
    app_default = create_client_ui_app(auth, conn)
    c1 = app_default.test_client()
    c1.get("/") # Render dashboard
    r_default = p.memory_info().rss / (1024 * 1024)
    print(f"Default Jinja (TEMPLATES_AUTO_RELOAD=True): RSS = {r_default:.2f} MB (Delta: +{r_default - r0:.2f} MB)")

    # Optimized Jinja
    app_opt = create_client_ui_app(auth, conn)
    app_opt.config["TEMPLATES_AUTO_RELOAD"] = False
    app_opt.jinja_env.cache_size = 10
    c2 = app_opt.test_client()
    c2.get("/")
    r_opt = p.memory_info().rss / (1024 * 1024)
    print(f"Optimized Jinja: RSS = {r_opt:.2f} MB")

if __name__ == "__main__":
    test_jinja_tuning()
