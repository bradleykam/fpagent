"""Reference MinHash implementation for fpagent (spec v1.2.0+).

This module is the AUTHORITATIVE definition of fpagent's MinHash at the
specified parameters. Any third-party implementation producing different
output at these parameters is non-conformant. See SPEC.md §5.2.

Why a vendored implementation: earlier versions of fpagent delegated to
`datasketch.MinHash`. Changing that added a numpy transitive dep and tied
the spec to the bit-level behavior of a third-party library. The spec now
defines the algorithm directly; this file is the reference code.

Algorithm (see SPEC.md §5.2 for prose):

Parameters (fixed at spec level):
    num_perm        = 128
    shingle_size    = 5 whitespace-separated tokens
    hash_func       = SHA-1 of the UTF-8-encoded shingle,
                      first 4 bytes as little-endian uint32
    mersenne_prime  = 2**61 - 1
    max_hash        = 2**32 - 1
    empty_sentinel  = max_hash   (initial value for each of the 128 slots)

Permutation coefficients a[i] and b[i] (i in 0..127) are derived
DETERMINISTICALLY from SHA-256 of fixed labels so the reference output is
identical on any Python version and any OS, with no dependency on a PRNG:

    a[i] = 1 + (SHA256(b"fpagent-minhash-v1:a:" || u32_be(i)) mod (P-1))
    b[i] = SHA256(b"fpagent-minhash-v1:b:" || u32_be(i)) mod P

where:
    - the SHA-256 digest is interpreted as a big-endian unsigned integer,
    - u32_be(i) is 4 bytes big-endian,
    - P = 2**61 - 1 (the Mersenne prime),
    - a[i] is in [1, P) and b[i] is in [0, P).

For each shingle, compute h = uint32_le(SHA1(shingle)[:4]). For each slot i,
compute phv_i = ((a[i] * h + b[i]) mod P) & max_hash. Keep the minimum phv_i
across all shingles for each slot. Empty input leaves every slot at
max_hash.

Output serialization: 128 × uint64 little-endian = 1024 bytes, base64-encoded
(1368 base64 chars including padding).
"""
from __future__ import annotations

import base64
import hashlib
import struct
from array import array
from typing import Iterable, List

NUM_PERM = 128
SHINGLE_SIZE = 5
_MERSENNE_PRIME = (1 << 61) - 1
_MAX_HASH = (1 << 32) - 1


def _derive_coefficient(label: bytes, i: int, lo: int) -> int:
    """SHA-256(label || u32_be(i)) as a big-endian int, reduced into the
    open interval [lo, P). lo is 0 for b[i] and 1 for a[i] after the +1.
    The intermediate reduction range is (P - lo) so that after adding lo
    the value stays in [lo, P)."""
    digest = hashlib.sha256(label + i.to_bytes(4, "big")).digest()
    n = int.from_bytes(digest, "big")
    return lo + (n % (_MERSENNE_PRIME - lo))


# Precompute permutation coefficients once per process. These values are
# spec-locked; they never change across runs, platforms, or Python versions.
_A: List[int] = [_derive_coefficient(b"fpagent-minhash-v1:a:", i, 1) for i in range(NUM_PERM)]
_B: List[int] = [_derive_coefficient(b"fpagent-minhash-v1:b:", i, 0) for i in range(NUM_PERM)]


def _shingle_hash(shingle_bytes: bytes) -> int:
    """h = first 4 bytes of SHA-1(shingle) interpreted as little-endian uint32."""
    return int.from_bytes(hashlib.sha1(shingle_bytes).digest()[:4], "little")


def compute_minhash_signature(shingles: Iterable[bytes]) -> bytes:
    """Compute the 128 × uint64 MinHash signature as 1024 raw bytes (LE).

    `shingles` is an iterable of UTF-8 byte strings. Pass the empty iterable
    to get the all-slots-max sentinel signature.
    """
    # Per-slot running minimums. Seeded at max_hash (the empty sentinel).
    slots = [_MAX_HASH] * NUM_PERM
    p = _MERSENNE_PRIME
    mask = _MAX_HASH

    # Hoist the coefficient lists into locals — the hot loop below references
    # them 128 times per shingle.
    a = _A
    b = _B

    for sh in shingles:
        h = _shingle_hash(sh)
        # Inner loop: 128 modular multiply-adds per shingle. We use a plain
        # index-based for loop rather than zip() because this measurably beats
        # zip() in pure-Python benchmarks.
        for i in range(NUM_PERM):
            phv = ((a[i] * h + b[i]) % p) & mask
            if phv < slots[i]:
                slots[i] = phv

    # Pack 128 × uint64 little-endian. struct.pack is a C call; much faster
    # than assembling bytes in Python.
    return struct.pack("<128Q", *slots)


def compute_minhash_b64(shingles: Iterable[bytes]) -> str:
    """Convenience: compute the signature and base64-encode it."""
    return base64.b64encode(compute_minhash_signature(shingles)).decode("ascii")


def decode_signature(b64: str) -> array:
    """Round-trip helper for tests / consumers who want a typed array back."""
    raw = base64.b64decode(b64)
    if len(raw) != NUM_PERM * 8:
        raise ValueError(f"expected {NUM_PERM * 8} bytes, got {len(raw)}")
    out = array("Q")
    out.frombytes(raw)
    return out
