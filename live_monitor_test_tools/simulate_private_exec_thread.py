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
WAIT_OBJECT_0 = 0x00000000

kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
kernel32.VirtualAlloc.restype = ctypes.c_void_p
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
    error = ctypes.get_last_error()
    return f"WinError {error}"


def main() -> int:
    print("Benign private executable thread simulator")
    print("This allocates one executable memory page containing only a RET instruction.")

    address = kernel32.VirtualAlloc(
        None,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not address:
        print(f"VirtualAlloc failed: {last_error_message()}", file=sys.stderr)
        return 1

    # x86/x64 RET. The thread starts here and returns immediately.
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
    print(f"Private executable start address: 0x{address:x}")
    print("Keeping process alive for 20 seconds so the monitor can observe it...")

    kernel32.WaitForSingleObject(thread_handle, 5000)
    time.sleep(20)
    kernel32.CloseHandle(thread_handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
