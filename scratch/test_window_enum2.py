import ctypes
from ctypes import wintypes
import psutil

user32 = ctypes.windll.user32
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

count = [0]
pids = {}

def cb(hwnd, lparam):
    count[0] += 1
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if user32.IsWindowVisible(hwnd):
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        if buf.value.strip():
            pids[pid.value] = buf.value.strip()
    return True

proc_cb = WNDENUMPROC(cb)
user32.EnumWindows(proc_cb, 0)

print(f"Total hwnds traversed: {count[0]}")
print(f"Total visible with titles: {len(pids)}")
for pid, title in pids.items():
    try:
        p = psutil.Process(pid)
        print(f"  PID {pid} ({p.name()}): {title[:60]}")
    except Exception:
        pass
