import ctypes
from ctypes import wintypes
import psutil

user32 = ctypes.windll.user32
h_desk = user32.OpenDesktopW("default", 0, False, 0x0100 | 0x0001 | 0x0040 | 0x0020)
print(f"OpenDesktop('default'): {h_desk}")
if h_desk:
    ok = user32.SetThreadDesktop(h_desk)
    print(f"SetThreadDesktop ok: {ok}")
    
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    
    count = [0]
    pids = {}
    def cb(hwnd, lparam):
        count[0] += 1
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                t = buf.value.strip()
                if t:
                    pids[pid.value] = t
        return True
    
    user32.EnumWindows(WNDENUMPROC(cb), 0)
    print(f"Total hwnds on default desktop: {count[0]}")
    print(f"Total visible with title: {len(pids)}")
    for pid, title in list(pids.items())[:20]:
        try:
            p = psutil.Process(pid)
            print(f"  PID {pid} ({p.name()}): {title[:50]}")
        except Exception:
            pass
