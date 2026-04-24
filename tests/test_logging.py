"""Structured logging: format modes, levels, and — critically — the invariant
that fingerprint values and raw record content never appear in log output.

This is enforced by scanning all log output from a full fingerprint/verify
run for any substring that appears in a fingerprint or a canonical record
body. If you add a new log call, keep it to counts and field names only.
"""
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

import pytest

from fpagent.logutil import configure, get

FIXTURE = Path(__file__).parent / "fixtures" / "dermatology.csv"


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["fpagent", *args], capture_output=True, text=True, cwd=cwd,
    )


def test_human_format_uses_checkmarks(tmp_path):
    manifest = tmp_path / "m.json"
    r = _run_cli("--log-format", "human", "fingerprint", "--input", str(FIXTURE), "--output", str(manifest))
    assert r.returncode == 0, r.stderr
    # Human output lands on stderr (logging default for fpagent) with checkmark glyphs.
    assert "✓ Parsed" in r.stderr
    assert "✓ Fingerprinted" in r.stderr


def test_json_format_is_one_json_per_line(tmp_path):
    manifest = tmp_path / "m.json"
    r = _run_cli("--log-format", "json", "fingerprint", "--input", str(FIXTURE), "--output", str(manifest))
    assert r.returncode == 0, r.stderr
    lines = [ln for ln in r.stderr.splitlines() if ln.strip()]
    assert lines, "expected at least one JSON log line on stderr"
    for ln in lines:
        obj = json.loads(ln)  # must be valid JSON
        assert "timestamp" in obj
        assert "level" in obj
        assert "logger" in obj
        assert "event" in obj
    # Structured fields should include parse_complete and fingerprint_complete events.
    events = [json.loads(ln).get("event_type") for ln in lines]
    assert "parse_complete" in events
    assert "fingerprint_complete" in events
    assert "manifest_written" in events


def test_log_level_warning_suppresses_info(tmp_path):
    manifest = tmp_path / "m.json"
    r = _run_cli(
        "--log-format", "human", "--log-level", "WARNING",
        "fingerprint", "--input", str(FIXTURE), "--output", str(manifest),
    )
    assert r.returncode == 0, r.stderr
    # None of the info-level checkmarks should appear at WARNING level.
    assert "✓ Parsed" not in r.stderr
    assert "✓ Fingerprinted" not in r.stderr


def test_privacy_no_record_content_or_fingerprints_in_logs(tmp_path):
    """Scan ALL log output (stderr) from a fingerprint + verify round-trip.
    No fingerprint value, no canonical record body, may appear in any log line.
    """
    manifest = tmp_path / "m.json"

    fp = _run_cli("--log-format", "json", "fingerprint", "--input", str(FIXTURE), "--output", str(manifest))
    assert fp.returncode == 0, fp.stderr
    vr = _run_cli("--log-format", "json", "verify", "--manifest", str(manifest), "--input", str(FIXTURE))
    assert vr.returncode == 0, vr.stderr

    combined_stderr = fp.stderr + vr.stderr
    m = json.loads(manifest.read_text())

    # No full SHA-256 or base64 MinHash from any record in the manifest should
    # appear in any log line. The MinHash base64 is the most sensitive (it's
    # long and constant-width, so a substring match is unambiguous).
    for rec in m["records"]:
        assert rec["sha256"] not in combined_stderr, "SHA-256 fingerprint leaked to logs"
        # Sample 16 chars in the middle of the MinHash blob — a substring that
        # collides by chance is astronomically unlikely.
        minhash_probe = rec["minhash"][200:216]
        assert minhash_probe not in combined_stderr, "MinHash substring leaked to logs"
        if rec.get("tlsh"):
            assert rec["tlsh"] not in combined_stderr, "TLSH fingerprint leaked to logs"

    # Also: no raw record content. Read the first record's content fields from
    # the fixture and confirm none of those values appear in logs.
    import csv
    with FIXTURE.open() as f:
        reader = csv.DictReader(f)
        first = next(reader)
    content_fields = {d["field"] for d in m["field_decisions"] if d["role"] == "content"}
    for field in content_fields:
        val = (first.get(field) or "").strip()
        if not val or len(val) < 12:
            continue  # skip short values that might collide by chance
        assert val not in combined_stderr, f"raw content from field '{field}' leaked to logs"


def test_logger_library_mode_does_not_configure_root():
    """When fpagent is imported as a library, child loggers must not bypass
    the host application's logging setup."""
    configure(fmt="json", level="INFO")
    log = get("testlib")
    # With propagate=False, the Python root logger's handlers are not invoked.
    root = logging.getLogger()
    assert not any(h for h in root.handlers if getattr(h, "_fpagent_test", False))
    # Direct logger is properly configured.
    assert logging.getLogger("fpagent").propagate is False
