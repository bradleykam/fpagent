"""JSON Schema validation: fixtures conform; malformed manifests are caught."""
import copy
import json
from pathlib import Path

import pytest

from fpagent.canonicalize import canonicalize_record, canonicalize_to_bytes
from fpagent.fingerprint import fingerprint_record
from fpagent.id_detection import content_field_names, detect_field_roles
from fpagent.manifest import build_manifest, sign_manifest
from fpagent.parser import read_records
from fpagent.schema import ManifestSchemaError, load_schema, validate_manifest


FIXTURES = Path(__file__).parent / "fixtures"


def _build_manifest_from_fixture(path: Path) -> dict:
    records = read_records(path)
    decisions = detect_field_roles(records)
    contents = content_field_names(decisions)
    bundles = []
    for rec in records:
        text = canonicalize_record(rec, contents)
        byts = canonicalize_to_bytes(rec, contents)
        bundles.append(fingerprint_record(byts, text))
    m = build_manifest(decisions, bundles)
    sign_manifest(m)
    return m


def test_schema_loads():
    s = load_schema()
    assert s["$schema"].startswith("https://json-schema.org/")
    assert s["title"] == "fpagent manifest"


def test_dermatology_fixture_validates():
    m = _build_manifest_from_fixture(FIXTURES / "dermatology.csv")
    validate_manifest(m)  # should not raise


def test_conformance_fixture_validates():
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    validate_manifest(m)


def test_missing_required_field_rejected():
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    del m["dataset_id"]
    with pytest.raises(ManifestSchemaError):
        validate_manifest(m)


def test_bad_sha256_rejected():
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    m["records"][0]["sha256"] = "not-a-hash"
    with pytest.raises(ManifestSchemaError) as exc_info:
        validate_manifest(m)
    assert "records/0/sha256" in str(exc_info.value)


def test_bad_minhash_length_rejected():
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    m["records"][0]["minhash"] = "AAAA"
    with pytest.raises(ManifestSchemaError):
        validate_manifest(m)


def test_wrong_minhash_permutations_rejected():
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    m["fingerprint_params"]["minhash_permutations"] = 256
    with pytest.raises(ManifestSchemaError):
        validate_manifest(m)


def test_unknown_top_level_field_rejected():
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    m["extra"] = "no"
    with pytest.raises(ManifestSchemaError):
        validate_manifest(m)


def test_signature_object_form_accepted():
    """A v1.1.0 manifest with a signature object should validate."""
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    m["signature"] = {
        "algorithm": "ed25519",
        "value": "Zm9v",  # "foo" base64
        "public_key_fingerprint": "a" * 64,
    }
    validate_manifest(m)


def test_ed25519_without_public_key_fingerprint_rejected():
    m = _build_manifest_from_fixture(FIXTURES / "conformance" / "tickets.csv")
    m["signature"] = {"algorithm": "ed25519", "value": "Zm9v"}
    with pytest.raises(ManifestSchemaError):
        validate_manifest(m)
