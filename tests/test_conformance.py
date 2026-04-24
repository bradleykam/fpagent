"""Conformance test: the reference implementation must produce output that
matches the captured conformance vectors.

Any other implementation of the spec can use this same test to validate
their output against ours.
"""

import json
from pathlib import Path

from fpagent.canonicalize import canonicalize_record, canonicalize_to_bytes
from fpagent.fingerprint import fingerprint_record
from fpagent.id_detection import (
    content_field_names,
    detect_field_roles,
)
from fpagent.parser import read_records


CONFORMANCE_DIR = Path(__file__).parent / "fixtures" / "conformance"


def _fingerprint_to_manifest_records(path: Path):
    records = read_records(path)
    decisions = detect_field_roles(records)
    contents = content_field_names(decisions)
    bundles = []
    for rec in records:
        text = canonicalize_record(rec, contents)
        byts = canonicalize_to_bytes(rec, contents)
        bundles.append(fingerprint_record(byts, text))
    manifest_records = [
        {"index": i, "sha256": fp.sha256, "minhash": fp.minhash, "tlsh": fp.tlsh}
        for i, fp in enumerate(bundles)
    ]
    return decisions, manifest_records


def test_tickets_conformance():
    input_path = CONFORMANCE_DIR / "tickets.csv"
    expected_path = CONFORMANCE_DIR / "tickets.expected.json"
    assert input_path.exists() and expected_path.exists(), "Conformance fixtures missing"

    expected = json.loads(expected_path.read_text())

    decisions, manifest_records = _fingerprint_to_manifest_records(input_path)

    # record_count
    assert expected["record_count"] == len(manifest_records)

    # field roles (reason text can differ across implementations; roles cannot)
    expected_roles = {d["field"]: d["role"] for d in expected["field_decisions"]}
    actual_roles = {d.field: d.role for d in decisions}
    assert expected_roles == actual_roles, (
        f"Role mismatch:\n  expected: {expected_roles}\n  actual:   {actual_roles}"
    )

    # per-record fingerprints
    for expected_rec, actual_rec in zip(expected["records"], manifest_records):
        assert expected_rec["index"] == actual_rec["index"]
        assert expected_rec["sha256"] == actual_rec["sha256"], (
            f"SHA-256 mismatch at record {actual_rec['index']}"
        )
        assert expected_rec["minhash"] == actual_rec["minhash"], (
            f"MinHash mismatch at record {actual_rec['index']}"
        )
        # TLSH: matches if both are null, or both are equal strings.
        # If the expected was computed with TLSH unavailable, expected is null;
        # actual must also be null (or we'd have implementation drift).
        assert expected_rec["tlsh"] == actual_rec["tlsh"], (
            f"TLSH mismatch at record {actual_rec['index']}"
        )
