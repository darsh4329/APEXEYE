"""
Measure incremental RSS cost of individual imports.
"""
import sys
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def get_rss():
    return psutil.Process().memory_info().rss / (1024 * 1024)

def measure(name, import_func):
    r1 = get_rss()
    import_func()
    r2 = get_rss()
    print(f"{name:35s}: +{r2 - r1:6.2f} MB (Total: {r2:6.2f} MB)")

print(f"{'Initial baseline':35s}: {get_rss():6.2f} MB")
measure("import psutil", lambda: __import__("psutil"))
measure("import socket, urllib.request, json", lambda: (__import__("socket"), __import__("urllib.request"), __import__("json")))
measure("import logging, threading, time", lambda: (__import__("logging"), __import__("threading"), __import__("time")))
measure("from client.app.config import config", lambda: __import__("client.app.config", fromlist=["config"]))
measure("import client collectors (cpu..net)", lambda: __import__("client.app.collectors", fromlist=["cpu", "memory", "disk", "network", "os_info"]))
measure("import client.app.collectors.events", lambda: __import__("client.app.collectors.events"))
measure("import client.app.communication", lambda: __import__("client.app.communication"))
measure("import client.app.auth", lambda: __import__("client.app.auth"))
measure("import client.app.services.enforcement", lambda: __import__("client.app.services.enforcement"))
measure("import client.app.services.block_server", lambda: __import__("client.app.services.block_server"))
measure("import client.app.services.firewall_agent", lambda: __import__("client.app.services.firewall_agent"))
measure("import flask (Flask, jinja2, werkzeug)", lambda: __import__("flask"))
measure("import client.app.ui.dashboard", lambda: __import__("client.app.ui.dashboard"))
measure("import client.app.agent", lambda: __import__("client.app.agent"))
