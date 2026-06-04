from __future__ import annotations

import ctypes
import platform
import sys
import time


if platform.system() != "Windows":
    raise SystemExit("This simulator is Windows-only.")


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_NOACCESS = 0x01

kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualProtect.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
]
kernel32.VirtualProtect.restype = ctypes.c_int
kernel32.CreateThread.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
]
kernel32.CreateThread.restype = ctypes.c_void_p
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
kernel32.WaitForSingleObject.restype = ctypes.c_uint32
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_int


def last_error_message() -> str:
    return f"WinError {ctypes.get_last_error()}"


def protect(address: int, protection: int) -> None:
    old = ctypes.c_uint32(0)
    ok = kernel32.VirtualProtect(
        ctypes.c_void_p(address),
        4096,
        protection,
        ctypes.byref(old),
    )
    if not ok:
        raise OSError(last_error_message())


def main() -> int:
    print("Benign sleep-obfuscation page-transition simulator")
    print("It allocates one executable page, starts a harmless RET thread, then flips the page to NOACCESS.")

    address = kernel32.VirtualAlloc(
        None,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not address:
        print(f"VirtualAlloc failed: {last_error_message()}", file=sys.stderr)
        return 1

    ctypes.memmove(address, b"\xC3", 1)

    thread_id = ctypes.c_uint32(0)
    thread_handle = kernel32.CreateThread(
        None,
        0,
        ctypes.c_void_p(address),
        None,
        0,
        ctypes.byref(thread_id),
    )
    if not thread_handle:
        print(f"CreateThread failed: {last_error_message()}", file=sys.stderr)
        return 1

    print(f"PID: {ctypes.windll.kernel32.GetCurrentProcessId()}")
    print(f"Thread ID: {thread_id.value}")
    print(f"Watched executable page: 0x{address:x}")
    print("Waiting 3 seconds before changing protection...")
    kernel32.WaitForSingleObject(thread_handle, 1000)
    time.sleep(3)

    protect(address, PAGE_NOACCESS)
    print("Changed page protection to NOACCESS. Waiting 10 seconds...")
    time.sleep(10)

    protect(address, PAGE_EXECUTE_READWRITE)
    print("Restored page protection to EXECUTE_READWRITE. Waiting 5 seconds...")
    time.sleep(5)
    kernel32.CloseHandle(thread_handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
