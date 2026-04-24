"""Tests for ID field detection."""

import uuid

import pytest

from fpagent.id_detection import (
    content_field_names,
    detect_field_roles,
    id_field_names,
)


def _uuids(n):
    return [str(uuid.uuid4()) for _ in range(n)]


def test_uuid_column_flagged_as_id():
    records = [{"patient_id": u, "notes": "x"} for u in _uuids(20)]
    decisions = detect_field_roles(records)
    assert "patient_id" in id_field_names(decisions)
    assert "notes" in content_field_names(decisions)


def test_sequential_int_id_flagged():
    records = [{"record_id": i, "body": "hello"} for i in range(50)]
    decisions = detect_field_roles(records)
    assert "record_id" in id_field_names(decisions)


def test_low_cardinality_int_is_content():
    # status = 0/1/2/3 repeated; should not be treated as ID
    records = [{"status": i % 4, "body": "x"} for i in range(50)]
    decisions = detect_field_roles(records)
    assert "status" in content_field_names(decisions)


def test_free_text_is_content():
    records = [
        {"body": "some unique text " + str(i), "category": "A"}
        for i in range(20)
    ]
    decisions = detect_field_roles(records)
    # body has high cardinality but no ID shape or name hint -> content
    assert "body" in content_field_names(decisions)
    assert "category" in content_field_names(decisions)


def test_manual_override_id():
    records = [{"x": "a", "y": "b"} for _ in range(10)]
    decisions = detect_field_roles(records, id_fields_override=["x"])
    assert "x" in id_field_names(decisions)
    assert "y" in content_field_names(decisions)


def test_manual_override_content_beats_heuristic():
    # UUIDs would normally be flagged as ID; override forces content
    records = [{"tracking_uuid": u} for u in _uuids(20)]
    decisions = detect_field_roles(records, content_fields_override=["tracking_uuid"])
    assert "tracking_uuid" in content_field_names(decisions)


def test_conflicting_overrides_raise():
    records = [{"x": 1}]
    with pytest.raises(ValueError):
        detect_field_roles(records, id_fields_override=["x"], content_fields_override=["x"])


def test_hex_hash_column_flagged():
    records = [{"hash": f"{i:064x}", "payload": "x"} for i in range(30)]
    decisions = detect_field_roles(records)
    assert "hash" in id_field_names(decisions)


def test_name_hint_alone_with_high_cardinality():
    # Not UUID-shaped but name is "ticket_id" and cardinality is 1.0
    records = [{"ticket_id": f"T-{i:05d}", "body": "x"} for i in range(100)]
    decisions = detect_field_roles(records)
    assert "ticket_id" in id_field_names(decisions)


def test_inconsistent_fields_handled():
    records = [
        {"a": 1, "b": 2},
        {"a": 1, "c": 3},
    ]
    decisions = detect_field_roles(records)
    fields = {d.field for d in decisions}
    assert fields == {"a", "b", "c"}
