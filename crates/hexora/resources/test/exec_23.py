import subprocess

f = "cwd"
cmd = f"dasds {f}"
repo_dir = "/path/to/repo"
p = subprocess.Popen(cmd, cwd=repo_dir)
