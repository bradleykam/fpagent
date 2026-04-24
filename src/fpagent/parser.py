"""Input format readers: CSV, JSONL, JSON-dir."""

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


SUPPORTED_FORMATS = ("csv", "jsonl", "json-dir")


def detect_format(path: Path) -> str:
    """Guess input format from path. Directories -> json-dir. Files by extension."""
    if path.is_dir():
        return "json-dir"
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in (".jsonl", ".ndjson"):
        return "jsonl"
    if suffix == ".json":
        # A single .json file could be an array of records or one record;
        # treat arrays as jsonl-equivalent and single objects as a 1-record dataset.
        return "json"
    raise ValueError(
        f"Cannot auto-detect format from {path}. Pass --format explicitly "
        f"(one of: {', '.join(SUPPORTED_FORMATS)})."
    )


def _read_csv(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize empty strings to None for consistency with JSON
            yield {k: (v if v != "" else None) for k, v in row.items()}


def _read_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{lineno}: invalid JSON ({e})") from e
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{lineno}: expected JSON object, got {type(obj).__name__}")
            yield obj


def _read_json_file(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            if not isinstance(item, dict):
                raise ValueError(f"{path}[{i}]: expected JSON object")
            yield item
    elif isinstance(obj, dict):
        yield obj
    else:
        raise ValueError(f"{path}: expected object or array of objects")


def _read_json_dir(path: Path) -> Iterator[Dict[str, Any]]:
    json_files = sorted(path.glob("*.json"))
    if not json_files:
        raise ValueError(f"No .json files found in {path}")
    for jf in json_files:
        with jf.open("r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            raise ValueError(f"{jf}: expected JSON object (one record per file)")
        yield obj


def read_records(path: Path, format: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read all records from path into a list. Materializes in memory; fine
    for the expected sizes (up to low millions of records per listing)."""
    fmt = format or detect_format(path)
    if fmt == "csv":
        return list(_read_csv(path))
    if fmt == "jsonl":
        return list(_read_jsonl(path))
    if fmt == "json":
        return list(_read_json_file(path))
    if fmt == "json-dir":
        return list(_read_json_dir(path))
    raise ValueError(f"Unsupported format: {fmt}")
