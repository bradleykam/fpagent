"""Re-fingerprint an input and compare to an existing manifest."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonicalize import canonicalize_record, canonicalize_to_bytes
from .fingerprint import fingerprint_record
from .id_detection import FieldDecision
from .manifest import read_manifest, verify_signature
from .parser import read_records
from .schema import ManifestSchemaError, validate_manifest


@dataclass
class RecordMismatch:
    index: int
    field_mismatches: List[str]  # which fingerprint fields differ


@dataclass
class VerifyResult:
    manifest_path: Path
    input_path: Path
    signature_valid: bool
    record_count_match: bool
    expected_count: int
    actual_count: int
    mismatches: List[RecordMismatch]
    schema_error: Optional[str] = None

    @property
    def passed(self) -> bool:
        return (
            self.schema_error is None
            and self.signature_valid
            and self.record_count_match
            and not self.mismatches
        )


def verify(manifest_path: Path, input_path: Path, format: Optional[str] = None) -> VerifyResult:
    manifest = read_manifest(manifest_path)

    # Schema check first — a malformed manifest is fatal; short-circuit.
    try:
        validate_manifest(manifest)
    except ManifestSchemaError as exc:
        return VerifyResult(
            manifest_path=manifest_path,
            input_path=input_path,
            signature_valid=False,
            record_count_match=False,
            expected_count=manifest.get("record_count", 0),
            actual_count=0,
            mismatches=[],
            schema_error=str(exc),
        )

    signature_ok = verify_signature(manifest)

    # Reconstruct field decisions from manifest to apply the same ID stripping.
    decisions = [
        FieldDecision(d["field"], d["role"], d["reason"])
        for d in manifest.get("field_decisions", [])
    ]
    content_fields = [d.field for d in decisions if d.role == "content"]

    records = read_records(input_path, format=format)
    expected_count = manifest.get("record_count", 0)
    count_ok = len(records) == expected_count

    mismatches: List[RecordMismatch] = []
    expected_records = {r["index"]: r for r in manifest.get("records", [])}

    for i, rec in enumerate(records):
        canonical_text = canonicalize_record(rec, content_fields)
        canonical_bytes = canonicalize_to_bytes(rec, content_fields)
        fp = fingerprint_record(canonical_bytes, canonical_text)

        expected = expected_records.get(i)
        if expected is None:
            mismatches.append(RecordMismatch(i, ["missing_from_manifest"]))
            continue

        diffs = []
        if fp.sha256 != expected.get("sha256"):
            diffs.append("sha256")
        if fp.minhash != expected.get("minhash"):
            diffs.append("minhash")
        if fp.tlsh != expected.get("tlsh"):
            diffs.append("tlsh")

        if diffs:
            mismatches.append(RecordMismatch(i, diffs))

    return VerifyResult(
        manifest_path=manifest_path,
        input_path=input_path,
        signature_valid=signature_ok,
        record_count_match=count_ok,
        expected_count=expected_count,
        actual_count=len(records),
        mismatches=mismatches,
    )
