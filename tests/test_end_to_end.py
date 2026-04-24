"""End-to-end tests: build a manifest, verify it, modify input, verify fails."""

import csv
import json
import uuid
from pathlib import Path

import pytest

from fpagent.canonicalize import canonicalize_record, canonicalize_to_bytes
from fpagent.fingerprint import fingerprint_record
from fpagent.id_detection import (
    content_field_names,
    detect_field_roles,
)
from fpagent.manifest import (
    build_manifest,
    read_manifest,
    sign_manifest,
    verify_signature,
    write_manifest,
)
from fpagent.parser import read_records
from fpagent.verify import verify


FIXTURE = Path(__file__).parent / "fixtures" / "dermatology.csv"


def _fingerprint_dataset(records):
    decisions = detect_field_roles(records)
    contents = content_field_names(decisions)
    bundles = []
    for rec in records:
        text = canonicalize_record(rec, contents)
        byts = canonicalize_to_bytes(rec, contents)
        bundles.append(fingerprint_record(byts, text))
    manifest = build_manifest(decisions, bundles)
    sign_manifest(manifest)
    return manifest, decisions


def test_fixture_exists():
    assert FIXTURE.exists(), f"Run generate_dermatology.py to create {FIXTURE}"


def test_end_to_end_fingerprint_and_verify(tmp_path):
    records = read_records(FIXTURE)
    assert len(records) == 50

    manifest, decisions = _fingerprint_dataset(records)
    out = tmp_path / "manifest.json"
    write_manifest(manifest, out)

    loaded = read_manifest(out)
    assert verify_signature(loaded)

    result = verify(out, FIXTURE)
    assert result.passed
    assert result.actual_count == 50
    assert result.expected_count == 50
    assert not result.mismatches


def test_tampered_content_detected(tmp_path):
    records = read_records(FIXTURE)
    manifest, _ = _fingerprint_dataset(records)
    out = tmp_path / "manifest.json"
    write_manifest(manifest, out)

    # Modify one content field in one record
    tampered = tmp_path / "tampered.csv"
    with FIXTURE.open() as src, tampered.open("w", newline="") as dst:
        reader = csv.DictReader(src)
        writer = csv.DictWriter(dst, fieldnames=reader.fieldnames)
        writer.writeheader()
        for i, row in enumerate(reader):
            if i == 10:
                row["primary_diagnosis"] = "completely different diagnosis"
            writer.writerow(row)

    result = verify(out, tampered)
    assert not result.passed
    assert len(result.mismatches) == 1
    assert result.mismatches[0].index == 10


def test_id_changes_alone_do_not_cause_mismatch(tmp_path):
    """The whole point: two sellers can pitch the same case with different
    local IDs and the content fingerprints should still match."""
    records = read_records(FIXTURE)
    manifest, _ = _fingerprint_dataset(records)
    out = tmp_path / "manifest.json"
    write_manifest(manifest, out)

    # Replace all IDs with fresh UUIDs
    re_ided = tmp_path / "re_ided.csv"
    with FIXTURE.open() as src, re_ided.open("w", newline="") as dst:
        reader = csv.DictReader(src)
        writer = csv.DictWriter(dst, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            row["patient_id"] = str(uuid.uuid4())
            row["case_id"] = str(uuid.uuid4())
            writer.writerow(row)

    result = verify(out, re_ided)
    assert result.passed, f"Expected clean match; got {len(result.mismatches)} mismatches"


def test_signature_invalid_after_tampering_manifest(tmp_path):
    records = read_records(FIXTURE)
    manifest, _ = _fingerprint_dataset(records)
    out = tmp_path / "manifest.json"
    write_manifest(manifest, out)

    # Tamper with the manifest JSON directly (change a record count)
    m = read_manifest(out)
    m["record_count"] = 999
    with out.open("w") as f:
        json.dump(m, f)

    result = verify(out, FIXTURE)
    assert not result.signature_valid


def test_record_count_mismatch_detected(tmp_path):
    records = read_records(FIXTURE)
    manifest, _ = _fingerprint_dataset(records)
    out = tmp_path / "manifest.json"
    write_manifest(manifest, out)

    # Drop the last row from the input
    truncated = tmp_path / "truncated.csv"
    with FIXTURE.open() as src:
        reader = csv.DictReader(src)
        rows = list(reader)
        fieldnames = reader.fieldnames
    rows = rows[:-1]
    with truncated.open("w", newline="") as dst:
        writer = csv.DictWriter(dst, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    result = verify(out, truncated)
    assert not result.passed
    assert not result.record_count_match
