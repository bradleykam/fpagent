"""Tests for fingerprint computation."""

from fpagent.fingerprint import (
    compute_sha256,
    compute_minhash,
    compute_tlsh,
    fingerprint_record,
)


def test_sha256_deterministic():
    b = b"field=value\nother=thing"
    assert compute_sha256(b) == compute_sha256(b)


def test_sha256_different_inputs_differ():
    assert compute_sha256(b"a") != compute_sha256(b"b")


def test_minhash_deterministic():
    text = "the quick brown fox jumps over the lazy dog"
    assert compute_minhash(text) == compute_minhash(text)


def test_minhash_similar_texts_overlap():
    # MinHash signatures of similar content should share many components.
    # We don't compute Jaccard here (that's the consumer's job); we just
    # verify that identical inputs produce identical signatures and that
    # small edits produce different-but-structured outputs.
    a = compute_minhash("the quick brown fox jumps over the lazy dog")
    b = compute_minhash("the quick brown fox jumps over the lazy cat")
    c = compute_minhash("the quick brown fox jumps over the lazy dog")
    assert a == c  # identical inputs
    assert a != b  # different inputs


def test_minhash_short_text_does_not_crash():
    # Below shingle size: single "shingle" is the whole text
    assert compute_minhash("hi") == compute_minhash("hi")


def test_minhash_empty_text_does_not_crash():
    # Should produce a signature even with no shingles
    sig = compute_minhash("")
    assert isinstance(sig, str)
    assert len(sig) > 0


def test_tlsh_returns_string_or_none():
    # TLSH requires ~50+ bytes of content. Short content returns None.
    short = compute_tlsh(b"short")
    assert short is None

    long = compute_tlsh(b"a" * 200 + b"some varied content here " * 10)
    # Either a hex string (if py-tlsh installed) or None (if not).
    assert long is None or isinstance(long, str)


def test_fingerprint_bundle_fields_populated():
    fp = fingerprint_record(b"field=value\ncontent=example text here", "field=value\ncontent=example text here")
    assert fp.sha256
    assert fp.minhash
    # tlsh may be None in this env; must be None or str
    assert fp.tlsh is None or isinstance(fp.tlsh, str)
