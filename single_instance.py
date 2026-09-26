"""Named-mutex guards so only one main window and one protection agent run.

Each guard also has a named event other processes can signal: for the main
window it means "show yourself", for the agent it means "stop protecting".
"""
import sys
import threading

_handles = []  # keep kernel handles alive for the process lifetime


def _kernel32():
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateMutexW.restype = wintypes.HANDLE
    k.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    k.OpenMutexW.restype = wintypes.HANDLE
    k.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k.CreateEventW.restype = wintypes.HANDLE
    k.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    k.OpenEventW.restype = wintypes.HANDLE
    k.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k.SetEvent.argtypes = [wintypes.HANDLE]
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k, ctypes


class NamedInstance:
    def __init__(self, name: str):
        self.mutex_name = f"Local\\{name}Mutex"
        self.event_name = f"Local\\{name}Signal"

    def acquire(self) -> bool:
        """True if this process is now the only holder."""
        if sys.platform != "win32":
            return True
        k, ctypes = _kernel32()
        handle = k.CreateMutexW(None, False, self.mutex_name)
        ERROR_ALREADY_EXISTS = 183
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            k.CloseHandle(handle)
            return False
        _handles.append(handle)
        return True

    def is_running(self) -> bool:
        if sys.platform != "win32":
            return False
        k, _ = _kernel32()
        SYNCHRONIZE = 0x00100000
        handle = k.OpenMutexW(SYNCHRONIZE, False, self.mutex_name)
        if handle:
            k.CloseHandle(handle)
            return True
        return False

    def signal(self):
        if sys.platform != "win32":
            return
        k, _ = _kernel32()
        EVENT_MODIFY_STATE = 0x0002
        event = k.OpenEventW(EVENT_MODIFY_STATE, False, self.event_name)
        if event:
            k.SetEvent(event)
            k.CloseHandle(event)

    def listen(self, callback):
        """Calls callback() from a background thread each time signal() is used."""
        if sys.platform != "win32":
            return
        k, _ = _kernel32()
        event = k.CreateEventW(None, False, False, self.event_name)
        _handles.append(event)
        INFINITE = 0xFFFFFFFF

        def wait_loop():
            while True:
                k.WaitForSingleObject(event, INFINITE)
                callback()

        threading.Thread(target=wait_loop, daemon=True).start()


UI = NamedInstance("SentinelAntivirusUI")
AGENT = NamedInstance("SentinelAntivirusAgent")
