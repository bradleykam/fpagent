"""Fingerprint algorithms: SHA-256, MinHash, TLSH.

- SHA-256 via hashlib.
- MinHash: reference implementation in `_minhash.py`. Authoritative per
  SPEC.md §5.2. No datasketch, no numpy.
- TLSH via py-tlsh (the only library widely used; no pure-Python port worth
  shipping). Null when the input is shorter than ~50 bytes.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional

import tlsh as _tlsh

from . import _minhash

MINHASH_PERMUTATIONS = _minhash.NUM_PERM
SHINGLE_SIZE = _minhash.SHINGLE_SIZE

# Legacy re-export. Removed in 0.3.0 from the manifest body (single backend);
# kept here only because the manifest builder historically read it.
MINHASH_SEED = "fpagent-minhash-v1"


@dataclass
class FingerprintBundle:
    sha256: str
    minhash: str  # base64-encoded uint64 array (128 × 8 bytes)
    tlsh: Optional[str]


def _shingle(text: str, size: int = SHINGLE_SIZE) -> List[bytes]:
    """Word-level UTF-8 shingles as raw bytes — we hand these straight to
    the MinHash module which hashes each as-is. Returns one whole-text
    shingle when there aren't enough words, and an empty list for empty input."""
    words = text.split()
    if len(words) < size:
        return [" ".join(words).encode("utf-8")] if words else []
    return [
        " ".join(words[i : i + size]).encode("utf-8")
        for i in range(len(words) - size + 1)
    ]


def compute_minhash(canonical_text: str) -> str:
    """Return base64-encoded MinHash signature (128 × uint64 little-endian)."""
    return _minhash.compute_minhash_b64(_shingle(canonical_text))


def compute_sha256(canonical_bytes: bytes) -> str:
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_tlsh(canonical_bytes: bytes) -> Optional[str]:
    """Return hex TLSH digest or None when py-tlsh can't produce one.

    Typical cause: content under ~50 bytes. py-tlsh signals this by returning
    the string "TNULL" (or an empty string on some versions).
    """
    try:
        digest = _tlsh.hash(canonical_bytes)
    except Exception:
        return None
    if not digest or digest == "TNULL":
        return None
    return digest


def fingerprint_record(canonical_bytes: bytes, canonical_text: str) -> FingerprintBundle:
    return FingerprintBundle(
        sha256=compute_sha256(canonical_bytes),
        minhash=compute_minhash(canonical_text),
        tlsh=compute_tlsh(canonical_bytes),
    )


def tlsh_version_string() -> str:
    try:
        return str(_tlsh.__version__)
    except AttributeError:
        return "installed"
