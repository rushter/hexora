import os

[os.system][0]("ls")
dispatch = {"run": os.system}
dispatch["run"]("ls")

os.posix_spawn("/bin/sh", ["/bin/sh", "-c", "ls"], os.environ)
os.__getattribute__("system")("ls")


list(map(os.system, ["ls"]))
