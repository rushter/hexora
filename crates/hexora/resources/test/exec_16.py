import os
import subprocess

os.system("powershell -Command Invoke-WebRequest -Uri http://example.com")
subprocess.run(["powershell", "-c", "whoami"])
