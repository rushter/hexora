import pty
import os
pty.spawn("/bin/sh")
os.dup2(1, 2)
