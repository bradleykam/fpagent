"""Streaming parser + --max-records safety cap."""
import json
import subprocess
from pathlib import Path

import pytest

from fpagent.canonicalize import canonicalize_record, canonicalize_to_bytes
from fpagent.fingerprint import fingerprint_record
from fpagent.id_detection import content_field_names, detect_field_roles
from fpagent.parser import iter_records, read_records


FIXTURES = Path(__file__).parent / "fixtures"


def test_iter_records_streams_jsonl(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"a":1}\n{"a":2}\n{"a":3}\n', encoding="utf-8")
    it = iter_records(p)
    # Generator: not a list
    assert not isinstance(it, list)
    assert [r["a"] for r in it] == [1, 2, 3]


def test_iter_and_read_agree(tmp_path):
    """Streaming iteration must produce identical bytes to list-read, otherwise
    the streaming refactor has broken determinism."""
    a = read_records(FIXTURES / "conformance" / "tickets.csv")
    b = list(iter_records(FIXTURES / "conformance" / "tickets.csv"))
    assert a == b


def test_second_pass_fingerprints_match_first(tmp_path):
    """The two-pass CLI (pass 1 for ID detection, pass 2 streaming
    fingerprints) must produce the same fingerprints as a single-pass flow."""
    records = read_records(FIXTURES / "conformance" / "tickets.csv")
    decisions = detect_field_roles(records)
    contents = content_field_names(decisions)

    single_pass = []
    for r in records:
        single_pass.append(fingerprint_record(
            canonicalize_to_bytes(r, contents), canonicalize_record(r, contents),
        ))

    streamed = []
    for r in iter_records(FIXTURES / "conformance" / "tickets.csv"):
        streamed.append(fingerprint_record(
            canonicalize_to_bytes(r, contents), canonicalize_record(r, contents),
        ))

    assert [b.sha256 for b in single_pass] == [b.sha256 for b in streamed]
    assert [b.minhash for b in single_pass] == [b.minhash for b in streamed]
    assert [b.tlsh for b in single_pass] == [b.tlsh for b in streamed]


def test_cli_max_records_rejects_oversized_input(tmp_path):
    manifest = tmp_path / "m.json"
    result = subprocess.run(
        [
            "fpagent", "fingerprint",
            "--input", str(FIXTURES / "dermatology.csv"),
            "--output", str(manifest),
            "--max-records", "5",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "max-records" in result.stderr or "max-records" in result.stdout
    assert not manifest.exists()


def test_cli_max_records_allows_within_cap(tmp_path):
    manifest = tmp_path / "m.json"
    result = subprocess.run(
        [
            "fpagent", "fingerprint",
            "--input", str(FIXTURES / "dermatology.csv"),
            "--output", str(manifest),
            "--max-records", "1000",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert manifest.exists()
    data = json.loads(manifest.read_text())
    assert data["record_count"] == 50
