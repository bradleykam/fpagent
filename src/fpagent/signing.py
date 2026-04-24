"""Ed25519 manifest signing.

The v1.0.0 manifest signed with a SHA-256 self-sum (integrity only, no
authenticity). v1.1.0 upgrades to Ed25519 over the same canonical body — the
bytes hashed are identical to those self-summed in v1.0.0, so a manifest can
in principle carry either form. The `signature` field becomes an object:

    {"algorithm": "ed25519", "value": "<base64>", "public_key_fingerprint": "<sha256 hex>"}

Old string signatures remain accepted on read with a warning.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


SIG_ALG_SELFSUM = "sha256-selfsum"
SIG_ALG_ED25519 = "ed25519"


def _canonical_body(manifest: dict[str, Any]) -> bytes:
    """Canonicalize the manifest body for signing. Same scheme as v1.0.0:
    set `signature` to an empty string, then json.dumps with sort_keys and
    compact separators. Consumers producing a v1.1.0 signature object canonicalize
    against this same placeholder so an Ed25519 signer and the old SHA-256
    self-summer operate on identical bytes."""
    m = dict(manifest)
    m["signature"] = ""
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_selfsum(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_body(manifest)).hexdigest()


# ---------- key generation ----------

def _pem_bytes(key_obj, is_private: bool) -> bytes:
    if is_private:
        return key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    return key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private = ed25519.Ed25519PrivateKey.generate()
    return private, private.public_key()


def write_keypair(private_path: Path) -> Path:
    """Write a private key to `private_path` (0600) and a public key to
    `<private_path>.pub`. Returns the public key path. Refuses to overwrite
    an existing private key — private keys are irreplaceable, and a silent
    overwrite is a footgun."""
    if private_path.exists():
        raise FileExistsError(f"private key already exists: {private_path}")
    public_path = private_path.with_name(private_path.name + ".pub")
    if public_path.exists():
        raise FileExistsError(f"public key already exists: {public_path}")

    private, public = generate_keypair()
    private_pem = _pem_bytes(private, is_private=True)
    public_pem = _pem_bytes(public, is_private=False)

    # Create with O_EXCL so a concurrent writer can't race us.
    fd = os.open(str(private_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(private_pem)
        os.chmod(private_path, 0o600)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise

    public_path.write_bytes(public_pem)
    return public_path


def load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def public_key_fingerprint(public: ed25519.Ed25519PublicKey) -> str:
    """SHA-256 hex of raw Ed25519 public-key bytes (32 bytes)."""
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


# ---------- sign / verify ----------

def sign_manifest_ed25519(manifest: dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    """Replace manifest['signature'] with an Ed25519 signature object. Returns
    the same manifest for chaining. Bumps spec_version to 1.1.0 BEFORE signing
    so the signer and the verifier canonicalize the same bytes."""
    # Order matters: bump first, sign after. If we signed the old-version
    # body and then bumped, verify would hash a different canonical form
    # and fail.
    manifest["spec_version"] = "1.1.0"
    sig = private_key.sign(_canonical_body(manifest))
    manifest["signature"] = {
        "algorithm": SIG_ALG_ED25519,
        "value": base64.b64encode(sig).decode("ascii"),
        "public_key_fingerprint": public_key_fingerprint(private_key.public_key()),
    }
    return manifest


class SignatureCheck:
    """Outcome of verifying a manifest signature."""

    def __init__(
        self,
        *,
        algorithm: str,
        valid: bool,
        reason: str = "",
        public_key_fingerprint: Optional[str] = None,
        authentic: bool = False,
    ):
        self.algorithm = algorithm
        self.valid = valid
        self.reason = reason
        self.public_key_fingerprint = public_key_fingerprint
        # authentic=True only for a passing Ed25519 check against a trusted key.
        # A passing SHA-256 self-sum is "intact" but not authentic.
        self.authentic = authentic


def verify_manifest_signature(
    manifest: dict[str, Any],
    trusted_public_keys: Optional[list[ed25519.Ed25519PublicKey]] = None,
) -> SignatureCheck:
    """Verify whichever signature form the manifest carries.

    - A string signature is a v1.0.0 SHA-256 self-sum: recompute and compare.
    - An object signature with algorithm 'sha256-selfsum' is the same thing in
      v1.1.0 shape.
    - An object with algorithm 'ed25519' verifies against the embedded public
      key; if `trusted_public_keys` is given, the embedded key must match one
      of them by fingerprint (otherwise we mark authentic=False with the key
      fingerprint reported so callers can decide).
    """
    sig = manifest.get("signature")
    if isinstance(sig, str):
        ok = sig == sha256_selfsum(manifest)
        return SignatureCheck(
            algorithm=SIG_ALG_SELFSUM,
            valid=ok,
            reason="" if ok else "sha256 self-sum mismatch",
            authentic=False,
        )

    if not isinstance(sig, dict):
        return SignatureCheck(algorithm="unknown", valid=False, reason="signature missing or not a dict/string")

    alg = sig.get("algorithm")
    if alg == SIG_ALG_SELFSUM:
        ok = sig.get("value") == sha256_selfsum(manifest)
        return SignatureCheck(
            algorithm=alg,
            valid=ok,
            reason="" if ok else "sha256 self-sum mismatch",
            authentic=False,
        )

    if alg == SIG_ALG_ED25519:
        value = sig.get("value")
        fp = sig.get("public_key_fingerprint")
        if not value or not fp:
            return SignatureCheck(
                algorithm=alg, valid=False,
                reason="ed25519 signature missing value or public_key_fingerprint",
            )
        try:
            sig_bytes = base64.b64decode(value)
        except Exception as e:
            return SignatureCheck(algorithm=alg, valid=False, reason=f"bad base64: {e}")
        body = _canonical_body(manifest)

        # We don't embed the public key in the manifest, only its fingerprint.
        # The caller must supply trusted keys out-of-band.
        if not trusted_public_keys:
            return SignatureCheck(
                algorithm=alg, valid=False,
                reason="no trusted public key provided (use --public-key)",
                public_key_fingerprint=fp,
            )

        matched = None
        for key in trusted_public_keys:
            if public_key_fingerprint(key) == fp:
                matched = key
                break
        if matched is None:
            return SignatureCheck(
                algorithm=alg, valid=False,
                reason=f"none of the supplied public keys match fingerprint {fp[:16]}…",
                public_key_fingerprint=fp,
            )

        try:
            matched.verify(sig_bytes, body)
        except InvalidSignature:
            return SignatureCheck(
                algorithm=alg, valid=False,
                reason="ed25519 signature does not verify against the matched public key",
                public_key_fingerprint=fp,
            )
        return SignatureCheck(
            algorithm=alg, valid=True,
            public_key_fingerprint=fp, authentic=True,
        )

    return SignatureCheck(algorithm=str(alg), valid=False, reason=f"unknown signature algorithm {alg!r}")


def load_trusted_public_keys(path: Path) -> list[ed25519.Ed25519PublicKey]:
    """Load one key (file) or all *.pub files under a directory."""
    if path.is_dir():
        keys = []
        for p in sorted(path.glob("*.pub")):
            keys.append(load_public_key(p))
        return keys
    return [load_public_key(path)]
