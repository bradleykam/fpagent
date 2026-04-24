"""Ed25519 signing: keygen roundtrip, sign/verify happy path, tamper detection,
wrong-key rejection, and backward compat with v1.0.0 string signatures."""
import json
import os
import stat
from pathlib import Path

import pytest

from fpagent.canonicalize import canonicalize_record, canonicalize_to_bytes
from fpagent.fingerprint import fingerprint_record
from fpagent.id_detection import content_field_names, detect_field_roles
from fpagent.manifest import build_manifest, sign_manifest
from fpagent.parser import read_records
from fpagent.signing import (
    SIG_ALG_ED25519,
    SIG_ALG_SELFSUM,
    load_private_key,
    load_public_key,
    public_key_fingerprint,
    sign_manifest_ed25519,
    verify_manifest_signature,
    write_keypair,
)


FIXTURES = Path(__file__).parent / "fixtures"


def _build(path: Path) -> dict:
    records = read_records(path)
    decisions = detect_field_roles(records)
    contents = content_field_names(decisions)
    bundles = []
    for rec in records:
        text = canonicalize_record(rec, contents)
        byts = canonicalize_to_bytes(rec, contents)
        bundles.append(fingerprint_record(byts, text))
    return build_manifest(decisions, bundles)


def test_keygen_roundtrip(tmp_path):
    priv_path = tmp_path / "mykey"
    pub_path = write_keypair(priv_path)
    assert priv_path.exists() and pub_path.exists()
    mode = stat.S_IMODE(priv_path.stat().st_mode)
    assert mode == 0o600, f"private key should be 0600, got {oct(mode)}"

    private = load_private_key(priv_path)
    public = load_public_key(pub_path)
    assert public_key_fingerprint(public) == public_key_fingerprint(private.public_key())


def test_keygen_refuses_to_overwrite(tmp_path):
    priv_path = tmp_path / "mykey"
    write_keypair(priv_path)
    with pytest.raises(FileExistsError):
        write_keypair(priv_path)


def test_sign_and_verify_happy_path(tmp_path):
    priv_path = tmp_path / "mykey"
    pub_path = write_keypair(priv_path)
    private = load_private_key(priv_path)
    public = load_public_key(pub_path)

    m = _build(FIXTURES / "conformance" / "tickets.csv")
    sign_manifest_ed25519(m, private)
    assert m["spec_version"] == "1.1.0"
    assert isinstance(m["signature"], dict)
    assert m["signature"]["algorithm"] == SIG_ALG_ED25519

    check = verify_manifest_signature(m, [public])
    assert check.valid
    assert check.authentic
    assert check.algorithm == SIG_ALG_ED25519


def test_verify_fails_with_wrong_key(tmp_path):
    priv_a = write_keypair(tmp_path / "a").parent / "a"
    priv_b = write_keypair(tmp_path / "b").parent / "b"
    m = _build(FIXTURES / "conformance" / "tickets.csv")
    sign_manifest_ed25519(m, load_private_key(priv_a))
    # b's public key does not match a's fingerprint — rejected before cryptography runs.
    check = verify_manifest_signature(m, [load_public_key(tmp_path / "b.pub")])
    assert not check.valid
    assert "fingerprint" in check.reason.lower()


def test_verify_fails_on_tampered_manifest(tmp_path):
    priv_path = tmp_path / "mykey"
    pub_path = write_keypair(priv_path)
    m = _build(FIXTURES / "conformance" / "tickets.csv")
    sign_manifest_ed25519(m, load_private_key(priv_path))

    # Flip a content-bearing byte in a record's SHA after signing.
    m["records"][0]["sha256"] = "f" + m["records"][0]["sha256"][1:]
    check = verify_manifest_signature(m, [load_public_key(pub_path)])
    assert not check.valid
    assert "does not verify" in check.reason


def test_verify_reports_fingerprint_when_no_trusted_keys(tmp_path):
    priv_path = tmp_path / "mykey"
    write_keypair(priv_path)
    m = _build(FIXTURES / "conformance" / "tickets.csv")
    sign_manifest_ed25519(m, load_private_key(priv_path))

    check = verify_manifest_signature(m, None)
    assert not check.valid
    assert check.public_key_fingerprint  # reported so the operator can decide to trust it


def test_v1_0_string_signature_still_verifies():
    """A v1.0.0 manifest with a string signature must still verify — as
    'intact' (integrity ok) but explicitly not authentic."""
    m = _build(FIXTURES / "conformance" / "tickets.csv")
    sign_manifest(m)  # writes a string sig
    assert isinstance(m["signature"], str)
    check = verify_manifest_signature(m)
    assert check.valid
    assert check.algorithm == SIG_ALG_SELFSUM
    assert not check.authentic


def test_selfsum_object_form_still_verifies(tmp_path):
    """A v1.1.0 object-form SHA-256 self-sum should also verify (back-compat alt)."""
    from fpagent.signing import sha256_selfsum
    m = _build(FIXTURES / "conformance" / "tickets.csv")
    sign_manifest(m)  # string form, correct hash
    m["signature"] = {"algorithm": SIG_ALG_SELFSUM, "value": sha256_selfsum(m)}
    check = verify_manifest_signature(m)
    assert check.valid
    assert check.algorithm == SIG_ALG_SELFSUM
    assert not check.authentic


def test_tampered_selfsum_rejected():
    m = _build(FIXTURES / "conformance" / "tickets.csv")
    sign_manifest(m)
    m["records"][0]["sha256"] = "f" + m["records"][0]["sha256"][1:]
    check = verify_manifest_signature(m)
    assert not check.valid
