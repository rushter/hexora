import ctypes
import sys
from ctypes import windll


kernel32 = windll.kernel32

PROCESS_ALL_ACCESS = 0x1F0FFF
VIRTUAL_MEM = (0x1000 | 0x2000)  # MEM_COMMIT | MEM_RESERVE
PAGE_READWRITE = 0x04
pid = 1000
dll_path = "C:\\Windows\\System32\\user32.dll"

process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not process_handle:
    sys.exit(f"Failed to open process {pid}")

arg_address = kernel32.VirtualAllocEx(process_handle, 0, len(dll_path) + 1,
                                      VIRTUAL_MEM, PAGE_READWRITE)

written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(process_handle, arg_address,
                            dll_path.encode('ascii'), len(dll_path) + 1,
                            ctypes.byref(written))

thread_id = ctypes.c_ulong(0)
if not kernel32.CreateRemoteThread(process_handle, None, 0,
                                   LoadLibraryA, arg_address, 0,
                                   ctypes.byref(thread_id)):
    sys.exit("Failed to create remote thread")

print(f"[*] DLL injected, thread ID: {thread_id.value}")


ctypes.CDLL("libc.so.6")