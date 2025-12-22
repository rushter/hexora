import os
import platform

cmd = platform.system()
os.system(cmd)

key = os.getenv("MALICIOUS_CMD")
os.system(key)
