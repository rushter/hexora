import subprocess
import sys
import base64

_p = "test"
try:
    subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"import base64; exec(base64.b64decode('{_p}').decode())",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
except:
    pass

B64_SCRIPT = "cHJpbnQoJ2hlbGxvJyk="

try:
    payload = base64.b64decode(B64_SCRIPT)
    subprocess.run(
        [sys.executable, "-"],
        input=payload,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
except Exception:
    pass
