import ctypes
from ctypes import wintypes
import os
import psutil

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long), ('right', ctypes.c_long), ('bottom', ctypes.c_long)]

def attach_thread_to_default_desktop():
    if os.name != 'nt':
        return False
    try:
        h_desk = user32.OpenDesktopW("default", 0, False, 0x0100 | 0x0001 | 0x0040 | 0x0020)
        if h_desk:
            user32.SetThreadDesktop(h_desk)
            return True
    except Exception:
        pass
    return False

def get_visible_windows():
    attach_thread_to_default_desktop()
    windows = {}  # pid -> title
    
    def enum_cb(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            rect = RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            w = rect.right - rect.left
            h = rect.bottom - rect.top
            if w > 50 and h > 50:
                ex_style = user32.GetWindowLongW(hwnd, -20)
                WS_EX_TOOLWINDOW = 0x00000080
                if not (ex_style & WS_EX_TOOLWINDOW):
                    pid = wintypes.DWORD()
                    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    if pid.value:
                        length = user32.GetWindowTextLengthW(hwnd)
                        buf = ctypes.create_unicode_buffer(length + 1)
                        user32.GetWindowTextW(hwnd, buf, length + 1)
                        t = buf.value.strip()
                        if t and pid.value not in windows:
                            windows[pid.value] = t
        return True

    user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
    return windows

def get_pe_metadata(exe_path):
    if not exe_path or not os.path.isfile(exe_path):
        return None
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(exe_path, None)
        if not size:
            return None
        res = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(exe_path, 0, size, res):
            return None
        trans_ptr = ctypes.c_void_p()
        trans_len = ctypes.c_uint()
        translations = []
        if ctypes.windll.version.VerQueryValueW(res, '\\VarFileInfo\\Translation', ctypes.byref(trans_ptr), ctypes.byref(trans_len)) and trans_len.value >= 4:
            count = trans_len.value // 4
            trans_arr = (ctypes.c_ushort * (count * 2)).from_address(trans_ptr.value)
            for i in range(count):
                translations.append(f'{trans_arr[i*2]:04x}{trans_arr[i*2+1]:04x}')
        translations.extend(['040904b0', '040904e4', '000004b0', '04090000'])
        for field in ['FileDescription', 'ProductName']:
            for trans in translations:
                sub_block = f'\\StringFileInfo\\{trans}\\{field}'
                ptr = ctypes.c_void_p()
                length = ctypes.c_uint()
                if ctypes.windll.version.VerQueryValueW(res, sub_block, ctypes.byref(ptr), ctypes.byref(length)) and length.value > 0:
                    val = ctypes.wstring_at(ptr.value, length.value).rstrip('\x00').strip()
                    if val:
                        return val
    except Exception:
        pass
    return None

wins = get_visible_windows()
print(f"Detected {len(wins)} windows:")
for pid, title in wins.items():
    try:
        p = psutil.Process(pid)
        meta = get_pe_metadata(p.exe())
        print(f"  PID {pid:6d} ({p.name()}): meta='{meta}' | title='{title[:40]}'")
    except Exception as e:
        print(f"  PID {pid:6d}: {e}")
