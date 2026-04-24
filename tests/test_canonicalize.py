"""Tests for canonicalization."""

from fpagent.canonicalize import canonicalize_record, canonicalize_value


def test_none_becomes_empty():
    assert canonicalize_value(None) == ""


def test_lowercase():
    assert canonicalize_value("FooBar") == "foobar"


def test_whitespace_collapse():
    assert canonicalize_value("  a   b\tc\n\n d  ") == "a b c d"


def test_unicode_nfc():
    # composed vs decomposed form of é
    composed = "caf\u00e9"
    decomposed = "cafe\u0301"
    assert canonicalize_value(composed) == canonicalize_value(decomposed)


def test_html_strip():
    assert canonicalize_value("<b>hello</b> <i>world</i>") == "hello world"


def test_non_string_values_stringified():
    assert canonicalize_value(42) == "42"
    assert canonicalize_value(3.14) == "3.14"


def test_record_fields_sorted():
    rec = {"z": "last", "a": "first", "m": "middle"}
    canonical = canonicalize_record(rec, ["z", "a", "m"])
    lines = canonical.split("\n")
    assert lines == ["a=first", "m=middle", "z=last"]


def test_record_id_fields_excluded():
    rec = {"id": "12345", "name": "alice"}
    # content_fields omits 'id' -> 'id' is not in output
    canonical = canonicalize_record(rec, ["name"])
    assert canonical == "name=alice"
    assert "id" not in canonical


def test_record_missing_field_becomes_empty():
    rec = {"a": "x"}  # 'b' is missing
    canonical = canonicalize_record(rec, ["a", "b"])
    assert canonical == "a=x\nb="


def test_deterministic_across_runs():
    rec = {"notes": "Patient  has rash.", "date": "2024-01-01"}
    c1 = canonicalize_record(rec, ["notes", "date"])
    c2 = canonicalize_record(rec, ["notes", "date"])
    assert c1 == c2
