import subprocess


def worker(cmd):
    subprocess.run(cmd, text=True)


def run(args):
    cmd = getattr(args, "cmd", ["echo", "ok"])
    worker(cmd)


class Args:
    cmd = ["echo", "ok"]


run(Args())
