from contextlib import contextmanager

from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x')
__obfuscator__ = 'Hyperion'

@contextmanager
def PAYLOAD_generator(shellcode_data: bytes):
    print("Entering context")
    yield shellcode_data
    print("Exiting context")


with PAYLOAD_generator() as payload:
    print(f"Using {payload}")

def main():
    shellCODE_01 = "\x00"
    shellcode_02, a = "\x00", "\x011"
    shellcode_03 : str = "\x00"
    [shellcode_04, b] = ["\x00", "\x011"]
