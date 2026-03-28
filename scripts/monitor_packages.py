"""Monitor recent PyPI updates, audit source packages, and alert via Telegram.

Run using uv:

    uv run monitor_packages.py --output-path pypi_packages

Run using python:

    pip install requests hexora
    python monitor_packages.py --output-path pypi_packages

Environment variables:

    TELEGRAM_BOT_TOKEN  Telegram bot token for notifications.
    TELEGRAM_CHAT_ID    Telegram chat ID where alerts are sent.
"""

# /// script
# dependencies = [
#   "requests",
# ]
# ///

from __future__ import annotations

import argparse
import json
import logging
import os
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

import hexora

RSS_FEED_URL = "https://pypi.org/rss/updates.xml"
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"
USER_AGENT = "hexora-pypi-monitor/1.0 (+https://github.com/rushter/hexora)"
DEFAULT_TIMEOUT = 30
DEFAULT_POLL_SECONDS = 300
HIGH_OR_HIGHER_LEVELS = {"high", "very_high"}
VERY_HIGH_LEVEL = "very_high"
TELEGRAM_MAX_MESSAGE_LENGTH = 4096


@dataclass(frozen=True)
class FeedEntry:
    package_name: str
    version: str
    link: str
    pub_date: str

    @property
    def key(self) -> str:
        return f"{self.package_name}=={self.version}"


def load_cache(cache_path: Path) -> set[str]:
    if not cache_path.exists():
        return set()

    try:
        with cache_path.open("r", encoding="utf-8") as file:
            payload = json.load(file)
        processed = payload.get("processed", [])
        if not isinstance(processed, list):
            return set()
        return {str(item) for item in processed}
    except Exception as exc:
        logging.warning("Failed to read cache file %s: %s", cache_path, exc)
        return set()


def save_cache(cache_path: Path, processed: set[str]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"processed": sorted(processed)}
    with cache_path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def fetch_feed_entries() -> list[FeedEntry]:
    response = requests.get(
        RSS_FEED_URL,
        headers={"User-Agent": USER_AGENT},
        timeout=DEFAULT_TIMEOUT,
    )
    response.raise_for_status()

    root = ET.fromstring(response.content)
    items = root.findall("./channel/item")
    entries: list[FeedEntry] = []

    for item in items:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        if not title or not link:
            continue

        parsed = parse_title(title)
        if parsed is None:
            logging.debug("Skipping unrecognized feed title: %s", title)
            continue

        package_name, version = parsed
        entries.append(
            FeedEntry(
                package_name=package_name,
                version=version,
                link=link,
                pub_date=pub_date,
            )
        )

    return entries


def parse_title(title: str) -> tuple[str, str] | None:
    parts = title.rsplit(" ", maxsplit=1)
    if len(parts) != 2:
        return None
    package_name, version = parts[0].strip(), parts[1].strip()
    if not package_name or not version:
        return None
    return package_name, version


def get_sdist_url(package_name: str, version: str) -> str | None:
    metadata_url = PYPI_JSON_URL.format(name=package_name, version=version)
    response = requests.get(
        metadata_url,
        headers={"User-Agent": USER_AGENT},
        timeout=DEFAULT_TIMEOUT,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()

    payload = response.json()
    urls = payload.get("urls", [])
    for artifact in urls:
        if artifact.get("packagetype") == "sdist":
            url = artifact.get("url")
            if isinstance(url, str) and url:
                return url
    return None


def download_file(url: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(
        url,
        stream=True,
        headers={"User-Agent": USER_AGENT},
        timeout=DEFAULT_TIMEOUT,
    ) as response:
        response.raise_for_status()
        with output_path.open("wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)


def make_download_path(
    output_dir: Path, package_name: str, version: str, url: str
) -> Path:
    parsed_url = urlparse(url)
    file_name = os.path.basename(parsed_url.path)
    if not file_name:
        safe_name = package_name.replace("/", "-")
        file_name = f"{safe_name}-{version}.tar.gz"
    return output_dir / file_name


def run_hexora_audit(package_file: Path) -> list[dict[str, Any]] | None:
    try:
        result = hexora.audit_file(package_file)
    except Exception as exc:
        logging.error("Hexora audit failed for %s: %s", package_file, exc)
        return None

    if isinstance(result, dict):
        return [result]

    if isinstance(result, list):
        normalized: list[dict[str, Any]] = []
        for item in result:
            if isinstance(item, dict):
                normalized.append(item)
            else:
                logging.warning(
                    "Unexpected audit entry type for %s: %s",
                    package_file,
                    type(item),
                )
        return normalized

    logging.warning(
        "Unexpected audit result type for %s: %s", package_file, type(result)
    )
    return None


def get_confidence_items(
    audit_result: dict[str, Any],
    levels: set[str],
) -> list[dict[str, Any]]:
    items = audit_result.get("items", [])
    if not isinstance(items, list):
        return []

    high_items: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        confidence = str(item.get("confidence", "")).lower()
        if confidence in levels:
            high_items.append(item)

    return high_items


def log_confidence_items(entry: FeedEntry, items: list[dict[str, Any]]) -> None:
    if not items:
        return

    logging.warning(
        "High-confidence-or-higher findings for %s: %d",
        entry.key,
        len(items),
    )
    for item in items:
        rule = item.get("rule", "unknown")
        confidence = item.get("confidence", "unknown")
        label = item.get("label", "")
        description = item.get("description", "")
        logging.warning(
            "- [%s] %s | %s | %s",
            confidence,
            rule,
            label,
            description,
        )


def get_item_annotations(items: list[dict[str, Any]]) -> list[str]:
    annotations: list[str] = []
    seen: set[str] = set()

    for item in items:
        annotation = item.get("annotation")
        if not isinstance(annotation, str):
            continue

        text = annotation.strip()
        if not text or text in seen:
            continue

        seen.add(text)
        annotations.append(text)

    return annotations


def shorten_text(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def format_annotation_block(annotations: list[str]) -> str:
    if not annotations:
        return "No annotation details available"

    lines: list[str] = []
    for annotation in annotations[:3]:
        compact = shorten_text(annotation.replace("\r\n", "\n").strip(), 1200)
        lines.append(compact)

    return "\n\n---\n\n".join(lines)


def format_alert_message(
    entry: FeedEntry,
    package_file: Path,
    very_high_items: list[dict[str, Any]],
) -> str:
    top_rules: list[str] = []
    for item in very_high_items:
        rule = item.get("rule")
        confidence = item.get("confidence")
        if isinstance(rule, str) and isinstance(confidence, str):
            top_rules.append(f"{rule} ({confidence})")

    if not top_rules:
        rule_block = "No rule details available"
    else:
        unique_rules: list[str] = []
        seen: set[str] = set()
        for value in top_rules:
            if value in seen:
                continue
            seen.add(value)
            unique_rules.append(value)
            if len(unique_rules) == 10:
                break
        rule_block = "\n".join(f"- {rule}" for rule in unique_rules)

    annotation_block = format_annotation_block(get_item_annotations(very_high_items))

    message = (
        "Hexora high-confidence match detected\n"
        f"Package: {entry.package_name} {entry.version}\n"
        f"Link: {entry.link}\n"
        f"File: {package_file}\n"
        f"Very-high findings: {len(very_high_items)}\n"
        f"Rules:\n{rule_block}\n\n"
        f"Annotated code:\n{annotation_block}"
    )

    return shorten_text(message, TELEGRAM_MAX_MESSAGE_LENGTH)


def notify_telegram(token: str, chat_id: str, text: str) -> None:
    api_url = f"https://api.telegram.org/bot{token}/sendMessage"
    response = requests.post(
        api_url,
        data={"chat_id": chat_id, "text": text},
        headers={"User-Agent": USER_AGENT},
        timeout=DEFAULT_TIMEOUT,
    )
    response.raise_for_status()


def process_entry(
    entry: FeedEntry,
    output_dir: Path,
    telegram_token: str | None,
    telegram_chat_id: str | None,
) -> None:
    sdist_url = get_sdist_url(entry.package_name, entry.version)
    if not sdist_url:
        logging.info("No source distribution found for %s", entry.key)
        return

    package_file = make_download_path(
        output_dir, entry.package_name, entry.version, sdist_url
    )
    if not package_file.exists():
        logging.info("Downloading %s", sdist_url)
        download_file(sdist_url, package_file)
    else:
        logging.info("Reusing existing archive %s", package_file)

    audit_result = run_hexora_audit(package_file)
    if audit_result is None:
        return

    high_or_higher_items: list[dict[str, Any]] = []
    for per_file_result in audit_result:
        high_or_higher_items.extend(
            get_confidence_items(per_file_result, HIGH_OR_HIGHER_LEVELS)
        )
    log_confidence_items(entry, high_or_higher_items)

    very_high_items: list[dict[str, Any]] = []
    for per_file_result in audit_result:
        very_high_items.extend(get_confidence_items(per_file_result, {VERY_HIGH_LEVEL}))
    if not very_high_items:
        logging.info("No very-high findings for %s", entry.key)
        if package_file.exists():
            try:
                package_file.unlink()
                logging.info("Removed non-very-high package archive %s", package_file)
            except Exception as exc:
                logging.error("Failed to remove %s: %s", package_file, exc)
        return

    very_high_annotations = get_item_annotations(very_high_items)
    if very_high_annotations:
        logging.warning(
            "Annotated very-high findings for %s: %d",
            entry.key,
            len(very_high_annotations),
        )
        for annotation in very_high_annotations[:3]:
            logging.warning(
                "--- annotated finding ---\n%s", shorten_text(annotation, 1200)
            )
    else:
        logging.warning("No annotations found for very-high findings in %s", entry.key)

    if telegram_token and telegram_chat_id:
        try:
            message = format_alert_message(entry, package_file, very_high_items)
            notify_telegram(telegram_token, telegram_chat_id, message)
            logging.info("Telegram alert sent for %s", entry.key)
        except Exception as exc:
            logging.error("Failed to send Telegram alert for %s: %s", entry.key, exc)
    else:
        logging.warning(
            "Telegram credentials are not configured, skipping alert for %s",
            entry.key,
        )


def monitor(
    output_dir: Path,
    cache_path: Path,
    poll_interval_seconds: int,
    telegram_token: str | None,
    telegram_chat_id: str | None,
) -> None:
    processed = load_cache(cache_path)
    logging.info("Loaded %d cached package versions", len(processed))

    while True:
        cycle_start = time.time()
        try:
            entries = fetch_feed_entries()
            logging.info("Fetched %d feed entries", len(entries))

            for entry in entries:
                if entry.key in processed:
                    continue

                logging.info("Processing %s", entry.key)
                try:
                    process_entry(entry, output_dir, telegram_token, telegram_chat_id)
                finally:
                    processed.add(entry.key)
                    save_cache(cache_path, processed)
        except Exception as exc:
            logging.error("Monitoring cycle failed: %s", exc)

        elapsed = time.time() - cycle_start
        sleep_for = max(1, poll_interval_seconds - int(elapsed))
        logging.info("Sleeping for %d seconds", sleep_for)
        time.sleep(sleep_for)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor PyPI updates RSS feed and audit source packages with hexora.",
    )
    parser.add_argument(
        "--output-path",
        default="pypi_packages",
        help="Directory for downloaded source packages (default: pypi_packages)",
    )
    parser.add_argument(
        "--cache-path",
        default=".hexora_cache",
        help="Path to the cache file for processed package versions (default: .hexora_cache)",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=int,
        default=DEFAULT_POLL_SECONDS,
        help="Polling interval in seconds (default: 300)",
    )
    parser.add_argument(
        "--telegram-chat-id",
        default=os.environ.get("TELEGRAM_CHAT_ID"),
        help="Telegram chat ID (defaults to TELEGRAM_CHAT_ID env var)",
    )
    parser.add_argument(
        "--logging-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set the logging level (default: info)",
    )

    args = parser.parse_args()
    logging.getLogger().setLevel(getattr(logging, args.logging_level.upper()))

    output_dir = Path(args.output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_path = Path(args.cache_path)

    poll_interval_seconds = max(1, int(args.poll_interval_seconds))
    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    telegram_chat_id = args.telegram_chat_id

    if not telegram_token:
        logging.warning("TELEGRAM_BOT_TOKEN is not set; alerts will not be sent")
    if not telegram_chat_id:
        logging.warning("TELEGRAM_CHAT_ID is not set; alerts will not be sent")

    logging.info("Starting monitor; output directory: %s", output_dir)
    logging.info("Cache file: %s", cache_path)
    logging.info("Poll interval: %d seconds", poll_interval_seconds)

    try:
        monitor(
            output_dir=output_dir,
            cache_path=cache_path,
            poll_interval_seconds=poll_interval_seconds,
            telegram_token=telegram_token,
            telegram_chat_id=telegram_chat_id,
        )
    except KeyboardInterrupt:
        logging.info("Stopped by user")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    main()
