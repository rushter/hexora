from pathlib import Path
import subprocess

cmd = "cat"
otlp_log = "otlp.log"
otlp_process = subprocess.Popen(
    cmd, stdout=open(otlp_log, "w"), stderr=subprocess.STDOUT, cwd=str(Path.cwd())
)
