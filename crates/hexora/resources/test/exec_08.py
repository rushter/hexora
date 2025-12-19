def check():
    import platform
    import subprocess

    if platform.system().startswith("Linux"):
        subprocess.call("python3 /tmp/file.py &", shell=True)