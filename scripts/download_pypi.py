"""A simple script to obtain recently published packages to pypi.


Run using uv:

    uv run download_pypi.py --days 7 --output-path packages

Run using pip and python:

    pip install requests clickhouse-connect
    python download_pypi.py --days 7 --output-path packages

"""

# /// script
# dependencies = [
#   "requests",
#   "clickhouse-connect",
# ]
# ///
#
import argparse
import concurrent.futures
import logging
import os
import tarfile
import tempfile

import clickhouse_connect
import clickhouse_connect.driver.client
import requests

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

PYPI_PREFIX = "https://files.pythonhosted.org/packages"


def get_clickhouse_client() -> clickhouse_connect.driver.client.Client:
    # We use https://clickpy.clickhouse.com/ to obtain recent packages
    return clickhouse_connect.get_client(  # noqa
        host="sql-clickhouse.clickhouse.com",
        port=443,
        user="demo",
        secure=True,
    )


def query_recent_packages(days: int):
    client = get_clickhouse_client()
    query = """
    select name, path
    from pypi.projects
    where upload_time >= now() - toIntervalDay(%(days)s)
    and python_version = 'source'
    """
    return client.query(query, parameters={"days": days}).result_rows


def download_file(url: str, output_path: str):
    with requests.get(url, stream=True) as response:
        response.raise_for_status()
        with open(output_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)
    logging.info(f"Downloaded {url} to {output_path}")


def extract_package(temp_path: str, target_dir: str):
    with tarfile.open(temp_path, "r:gz") as tar:
        tar.extractall(target_dir)


def process_package(row: tuple[str, str], output_path_base: str):
    download_path = f"{PYPI_PREFIX}/{row[1]}"
    file_name = os.path.basename(row[1])
    package_name = file_name[:-7]  # remove .tar.gz
    target_dir = os.path.join(output_path_base, package_name)

    if os.path.exists(target_dir):
        logging.info(f"Package {package_name} already exists, skipping")
        return

    temp_path = None
    try:
        temp_fd, temp_path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(temp_fd)
        download_file(download_path, temp_path)
        extract_package(temp_path, target_dir)
        os.remove(temp_path)
        logging.info(f"Unpacked {file_name} to {target_dir}")
    except Exception as e:
        logging.error(f"Failed to process {file_name}: {str(e)}")
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


def main():
    parser = argparse.ArgumentParser(
        description="Download and extract recent PyPI packages."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="Number of days to look back for packages (default: 1)",
    )
    parser.add_argument(
        "--output-path",
        default="pypi_packages",
        help="Output directory path for extracted packages (default: pypi_packages)",
    )
    parser.add_argument(
        "--dry",
        action="store_true",
        help="List available packages and URLs without downloading",
    )
    args = parser.parse_args()
    data = query_recent_packages(args.days)

    if args.dry:
        for row in data:
            package_name = row[0]
            download_url = f"{PYPI_PREFIX}/{row[1]}"
            print(f"{package_name}: {download_url}")
        return

    output_path_base = args.output_path
    os.makedirs(output_path_base, exist_ok=True)

    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = [
            executor.submit(process_package, row, output_path_base) for row in data
        ]
        for future in concurrent.futures.as_completed(futures):
            future.result()


if __name__ == "__main__":
    main()
