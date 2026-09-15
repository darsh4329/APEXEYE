"""
Test impact of EmptyWorkingSet on Windows client RSS.
"""
import sys
import time
import ctypes
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.config import config
from client.app.agent import Agent

def test_trim():
    p = psutil.Process()
    r_before = p.memory_info().rss / (1024 * 1024)
    print(f"Before trim: {r_before:.2f} MB")

    # Win32 EmptyWorkingSet
    try:
        k32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        handle = k32.GetCurrentProcess()
        res = psapi.EmptyWorkingSet(handle)
        print(f"EmptyWorkingSet call result: {res}")
    except Exception as exc:
        print(f"Error: {exc}")

    time.sleep(0.5)
    r_after = p.memory_info().rss / (1024 * 1024)
    print(f"After trim: {r_after:.2f} MB (Reduction: -{r_before - r_after:.2f} MB)")

if __name__ == "__main__":
    test_trim()
