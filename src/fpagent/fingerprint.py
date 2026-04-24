"""Fingerprint algorithms: SHA-256, MinHash, TLSH.

datasketch and py-tlsh are the reference implementations named in SPEC.md;
both are hard dependencies. The earlier pure-Python MinHash fallback was
dropped in 0.1.0 after it proved not bit-compatible with datasketch at the
byte level — see CHANGELOG.md.

TLSH is emitted as null for content that is too short (typically < 50 bytes)
or when the library returns TNULL.
"""

import base64
import hashlib
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
from datasketch import MinHash as _DsMinHash
import tlsh as _tlsh

MINHASH_PERMUTATIONS = 128
MINHASH_SEED = 42
SHINGLE_SIZE = 5


@dataclass
class FingerprintBundle:
    sha256: str
    minhash: str  # base64-encoded uint64 array (128 × 8 bytes)
    tlsh: Optional[str]


def _shingle(text: str, size: int = SHINGLE_SIZE) -> List[str]:
    """Word-level shingles. Returns one whole-text shingle when there aren't
    enough words, and an empty list for empty input."""
    words = text.split()
    if len(words) < size:
        return [" ".join(words)] if words else []
    return [" ".join(words[i : i + size]) for i in range(len(words) - size + 1)]


def compute_minhash(canonical_text: str) -> str:
    """Return base64-encoded MinHash signature (128 × uint64)."""
    m = _DsMinHash(num_perm=MINHASH_PERMUTATIONS, seed=MINHASH_SEED)
    for sh in _shingle(canonical_text):
        m.update(sh.encode("utf-8"))
    raw = np.asarray(m.hashvalues, dtype=np.uint64).tobytes()
    return base64.b64encode(raw).decode("ascii")


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
