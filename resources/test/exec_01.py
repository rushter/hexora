import builtins
from os import popen
from subprocess import call
import subprocess

shellcode = "\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

# Annotated calls using from imports
result: int = call(["pinfo -m",' ', shellcode])


def option_2():
    popen("pinfo -m " + shellcode)


def option_3():
    # builtin eval
    eval("popen('pinfo -m " + shellcode + "')")

def option_4():
    builtins.exec("popen('pinfo -m " + shellcode + "')")

def option_5():
    # Import aliasing
    s = subprocess
    k = s
    k.check_output(["pinfo -m",' ', shellcode])
