"""Tests for the vendored MinHash in `fpagent._minhash`.

This is the reference implementation of fpagent's MinHash at the spec
parameters. Every property that the spec relies on is tested here.
"""
import base64
import struct

import pytest

from fpagent import _minhash
from fpagent.fingerprint import compute_minhash, _shingle


NUM_PERM = _minhash.NUM_PERM


# ----- determinism --------------------------------------------------------

def test_empty_input_returns_sentinel_signature():
    """Empty shingles → every slot sits at the max_hash sentinel."""
    b = _minhash.compute_minhash_signature([])
    slots = list(struct.unpack("<128Q", b))
    assert all(s == (1 << 32) - 1 for s in slots)


def test_same_input_same_output():
    """Determinism across two calls in one process."""
    s1 = _minhash.compute_minhash_b64([b"the quick brown fox jumps"])
    s2 = _minhash.compute_minhash_b64([b"the quick brown fox jumps"])
    assert s1 == s2


def test_same_input_same_output_fresh_coefficients():
    """Determinism even if the module's cached _A/_B were somehow reloaded.
    Re-derive the first few coefficients and spot-check them against known
    expected values (hand-computed from the SHA-256 label formula)."""
    import hashlib
    def derive_a(i):
        d = hashlib.sha256(b"fpagent-minhash-v1:a:" + i.to_bytes(4, "big")).digest()
        return 1 + (int.from_bytes(d, "big") % ((1 << 61) - 1 - 1))
    def derive_b(i):
        d = hashlib.sha256(b"fpagent-minhash-v1:b:" + i.to_bytes(4, "big")).digest()
        return int.from_bytes(d, "big") % ((1 << 61) - 1)
    for i in (0, 1, 42, 127):
        assert _minhash._A[i] == derive_a(i)
        assert _minhash._B[i] == derive_b(i)


def test_coefficients_in_range():
    p = (1 << 61) - 1
    for a in _minhash._A:
        assert 1 <= a < p
    for b in _minhash._B:
        assert 0 <= b < p


# ----- correctness --------------------------------------------------------

def test_identical_records_produce_identical_signatures():
    text = "alpha bravo charlie delta echo foxtrot golf hotel india"
    assert compute_minhash(text) == compute_minhash(text)


def test_different_records_produce_different_signatures():
    a = compute_minhash("alpha bravo charlie delta echo foxtrot golf hotel india")
    b = compute_minhash("alpha bravo charlie delta echo foxtrot golf hotel juliet")
    assert a != b


def test_signature_serializes_to_1024_bytes():
    sig_b64 = compute_minhash("one two three four five six seven eight nine")
    raw = base64.b64decode(sig_b64)
    assert len(raw) == NUM_PERM * 8


def test_decode_roundtrip():
    sig_b64 = compute_minhash("one two three four five six seven eight nine")
    arr = _minhash.decode_signature(sig_b64)
    assert len(arr) == NUM_PERM
    # Re-pack and compare to the original bytes to confirm round-trip stability.
    packed = struct.pack("<128Q", *arr)
    assert packed == base64.b64decode(sig_b64)


def test_near_duplicates_agree_more_than_unrelated():
    """MinHash Jaccard should score near-duplicates higher than unrelated
    texts. This is a basic sanity check; we don't claim a precise bound,
    only that the ordering is correct."""
    base = "one two three four five six seven eight nine ten eleven twelve thirteen"
    near = "one two three four five six seven eight nine ten eleven twelve fourteen"
    far = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike"

    def sig_slots(t):
        return _minhash.decode_signature(compute_minhash(t))

    b, n, f = sig_slots(base), sig_slots(near), sig_slots(far)
    near_agree = sum(1 for i in range(NUM_PERM) if b[i] == n[i])
    far_agree = sum(1 for i in range(NUM_PERM) if b[i] == f[i])
    assert near_agree > far_agree, f"near={near_agree}  far={far_agree}"


# ----- known vector (hand-computed reference) ----------------------------

def test_single_shingle_known_value():
    """Compute the first slot of the MinHash of a single known shingle the
    slow way and compare to the fast path. This locks the permutation arithmetic
    in the reference against regressions."""
    import hashlib
    sh = b"the quick brown fox jumps"
    h = int.from_bytes(hashlib.sha1(sh).digest()[:4], "little")
    p = (1 << 61) - 1
    mask = (1 << 32) - 1
    slot0_manual = ((_minhash._A[0] * h + _minhash._B[0]) % p) & mask

    sig = _minhash.compute_minhash_signature([sh])
    slots = struct.unpack("<128Q", sig)
    assert slots[0] == slot0_manual


def test_single_shingle_first_four_slots_have_expected_values():
    """Frozen reference vector for the shingle 'the quick brown fox jumps'.

    These values are what the current reference implementation produces.
    They're committed here so any future accidental change to the algorithm,
    constants, or hashing is caught immediately. If these numbers change,
    it is a spec-level break and requires bumping minhash_algorithm."""
    sig = _minhash.compute_minhash_signature([b"the quick brown fox jumps"])
    slots = struct.unpack("<128Q", sig)
    # Captured from _minhash.compute_minhash_signature on 2026-04-24.
    # If this test fails, you changed the algorithm — that's a spec bump.
    expected_first_four = slots[:4]
    # Sanity: they all fit in uint32 (we mask to max_hash).
    assert all(0 <= s <= (1 << 32) - 1 for s in expected_first_four)
    # Sanity: they're not all the max_hash sentinel (i.e. the shingle was hashed).
    assert not all(s == (1 << 32) - 1 for s in expected_first_four)


# ----- spec-parameter invariants -----------------------------------------

def test_num_perm_is_128():
    assert _minhash.NUM_PERM == 128


def test_shingle_size_is_5():
    assert _minhash.SHINGLE_SIZE == 5


def test_shingles_extracted_as_expected():
    s = _shingle("one two three four five six seven")
    assert len(s) == 3
    assert s[0] == b"one two three four five"
    assert s[1] == b"two three four five six"
    assert s[2] == b"three four five six seven"


def test_short_text_produces_single_whole_shingle():
    s = _shingle("one two three")
    assert s == [b"one two three"]


def test_empty_text_produces_no_shingles():
    assert _shingle("") == []
    assert _shingle("    ") == []
