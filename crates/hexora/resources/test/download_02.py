import importlib.metadata

import requests


def check_for_update(package_name="package_name"):
    try:
        current_version = importlib.metadata.version(package_name)
        pypi_url = f"https://pypi.org/pypi/{package_name}/json"
        latest_version = requests.get(pypi_url, timeout=3).json()["info"]["version"]

        if current_version != latest_version:
            print(
                f"⚠️  A new version for package '{package_name}' is available: "
                f"{latest_version} (currently installed: {current_version}). "
                f"Use the following command to update the package: pip install --upgrade {package_name}"
            )
    except Exception:
        pass
