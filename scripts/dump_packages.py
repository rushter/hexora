"""A script to dump contents of multiple malicious packages.

Run using uv:

    uv run dump_packages.py --input-path missing.txt --output-folder dumped_packages

Run using python:

    python dump_packages.py --input-path missing.txt --output-folder dumped_packages
"""

import argparse
import logging
import os
import subprocess

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def process_package(package_path: str, output_folder: str):
    package_path = package_path.strip()
    if not package_path:
        return

    file_name = os.path.basename(package_path) + ".txt"
    target_path = os.path.join(output_folder, file_name)

    if os.path.exists(target_path):
        logging.info(f"Package dump {file_name} already exists, skipping")
        return

    logging.info(f"Dumping {package_path}...")
    try:
        result = subprocess.run(
            ["cargo", "run", "--quiet", "--", "dump-package", package_path],
            capture_output=True,
            text=True,
            check=True,
        )

        with open(target_path, "w") as f:
            f.write(result.stdout)

        logging.info(f"Successfully dumped {file_name} to {target_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to dump {package_path}: {e.stderr}")
    except Exception as e:
        logging.error(f"An error occurred while processing {package_path}: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="Dump multiple malicious packages using hexora."
    )
    parser.add_argument(
        "--input-path",
        required=True,
        help="Path to a file containing a list of package paths, one per line.",
    )
    parser.add_argument(
        "--output-folder",
        default="dumped_packages",
        help="Output directory path for dumped package contents (default: dumped_packages)",
    )
    parser.add_argument(
        "--logging-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set the logging level (default: info)",
    )

    args = parser.parse_args()
    logging.getLogger().setLevel(getattr(logging, args.logging_level.upper()))

    if not os.path.exists(args.input_path):
        logging.error(f"Input file not found: {args.input_path}")
        return

    os.makedirs(args.output_folder, exist_ok=True)

    with open(args.input_path, "r") as f:
        for line in f:
            process_package(line, args.output_folder)


if __name__ == "__main__":
    main()
