import ctypes
import psutil

user32 = ctypes.windll.user32

class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long), ('right', ctypes.c_long), ('bottom', ctypes.c_long)]

def get_visible_window_pids():
    window_pids = {}
    
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    
    def enum_windows_callback(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            rect = RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            w = rect.right - rect.left
            h = rect.bottom - rect.top
            length = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value.strip()
            
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value and w > 50 and h > 50 and length > 0:
                # Check if it has WS_EX_TOOLWINDOW or not
                # GWL_EXSTYLE = -20
                ex_style = user32.GetWindowLongW(hwnd, -20)
                WS_EX_TOOLWINDOW = 0x00000080
                if not (ex_style & WS_EX_TOOLWINDOW):
                    window_pids[pid.value] = title
        return True

    cb = WNDENUMPROC(enum_windows_callback)
    user32.EnumWindows(cb, 0)
    return window_pids

win_pids = get_visible_window_pids()
print(f"Total PIDs with visible top-level windows: {len(win_pids)}")
for pid, title in win_pids.items():
    try:
        p = psutil.Process(pid)
        print(f"PID {pid:6d} ({p.name():20s}): \"{title[:50]}\"")
    except Exception:
        pass
