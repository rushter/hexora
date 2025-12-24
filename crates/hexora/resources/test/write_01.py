from pathlib import Path

open("payload.exe", "w").write("malicious content")
open("script.py", "a").write("more code")
open("readme.txt", "w").write("safe content")


Path("bad.exe").write_bytes(b"evil")
p = Path("other_bad.py")
p.write_text("evil bytes")

open("payload.exe", "r").read()
open("data.bin", "w").write("data")
