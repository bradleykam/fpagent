"""Parser tests for CSV, JSONL, JSON, and JSON-dir inputs."""

import json
from pathlib import Path

import pytest

from fpagent.parser import detect_format, read_records


def test_detect_format_csv(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("a,b\n1,2\n")
    assert detect_format(p) == "csv"


def test_detect_format_jsonl(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"a": 1}\n')
    assert detect_format(p) == "jsonl"


def test_detect_format_ndjson(tmp_path):
    p = tmp_path / "x.ndjson"
    p.write_text('{"a": 1}\n')
    assert detect_format(p) == "jsonl"


def test_detect_format_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('[{"a": 1}]')
    assert detect_format(p) == "json"


def test_detect_format_dir(tmp_path):
    assert detect_format(tmp_path) == "json-dir"


def test_detect_format_unknown_raises(tmp_path):
    p = tmp_path / "x.parquet"
    p.write_bytes(b"not parquet")
    with pytest.raises(ValueError):
        detect_format(p)


def test_read_csv(tmp_path):
    p = tmp_path / "data.csv"
    p.write_text("id,name,notes\n1,alice,hello\n2,bob,\n")
    records = read_records(p)
    assert len(records) == 2
    assert records[0] == {"id": "1", "name": "alice", "notes": "hello"}
    # empty CSV cell becomes None
    assert records[1]["notes"] is None


def test_read_jsonl(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text('{"a": 1}\n{"a": 2}\n\n{"a": 3}\n')
    records = read_records(p)
    assert len(records) == 3
    assert records[0]["a"] == 1


def test_read_jsonl_invalid_line(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text('{"a": 1}\nnot json\n')
    with pytest.raises(ValueError, match="invalid JSON"):
        read_records(p)


def test_read_json_array(tmp_path):
    p = tmp_path / "data.json"
    p.write_text('[{"a": 1}, {"a": 2}]')
    records = read_records(p)
    assert len(records) == 2


def test_read_json_single_object(tmp_path):
    p = tmp_path / "data.json"
    p.write_text('{"a": 1}')
    records = read_records(p)
    assert len(records) == 1


def test_read_json_dir(tmp_path):
    d = tmp_path / "records"
    d.mkdir()
    (d / "001.json").write_text('{"a": 1}')
    (d / "002.json").write_text('{"a": 2}')
    records = read_records(d)
    assert len(records) == 2


def test_read_json_dir_empty_raises(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    with pytest.raises(ValueError, match="No .json files"):
        read_records(d)
