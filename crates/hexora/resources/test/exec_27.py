import base64
import os
import subprocess
import sys
import tempfile

b64_payload = "aW1wb3J0IGJhc2U2NDsgZXhlYyhiYXNlNjQuYjY0ZGVjb2RlKCJhVzF3YjNKMElHOXpPeUJ2Y3k1emVYTjBaVzBvSjJ4ekp5az0iKSk="

with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "p.py")
    with open(p, "wb") as f:
        f.write(base64.b64decode(b64_payload))

    subprocess.run([sys.executable, p])

    with open(p, "rb") as f:
        loaded = f.read().decode()

    exec(loaded)
