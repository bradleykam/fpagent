"""Canonicalization of record content before fingerprinting.

The canonical form must be deterministic across implementations.
Any change to this module requires a CANONICALIZATION_VERSION bump.
"""

import re
import unicodedata
from typing import Any, Dict, Iterable

# Strip HTML-ish tags. Not a full HTML parser - the spec calls for removing
# tag-shaped substrings, which this regex does. Value content that genuinely
# contains angle brackets (math, code) may be affected; documented in SPEC.md.
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def canonicalize_value(value: Any) -> str:
    """Canonicalize a single field value to a normalized string.

    Rules (in order):
    1. None -> empty string
    2. Non-string -> str()
    3. Unicode NFC normalization
    4. Strip HTML tags
    5. Lowercase
    6. Collapse whitespace runs to single space
    7. Strip leading/trailing whitespace
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = unicodedata.normalize("NFC", value)
    value = _HTML_TAG_RE.sub("", value)
    value = value.lower()
    value = _WHITESPACE_RE.sub(" ", value)
    return value.strip()


def canonicalize_record(record: Dict[str, Any], content_fields: Iterable[str]) -> str:
    """Produce the canonical string for a record.

    Only content_fields are included. Fields are sorted alphabetically
    (case-sensitive ASCII). Serialized as field=value lines joined by LF.
    UTF-8 encoding is implicit (Python strings are Unicode; callers encode
    to bytes before hashing).
    """
    content_fields = sorted(content_fields)
    lines = []
    for field in content_fields:
        raw = record.get(field)
        lines.append(f"{field}={canonicalize_value(raw)}")
    return "\n".join(lines)


def canonicalize_to_bytes(record: Dict[str, Any], content_fields: Iterable[str]) -> bytes:
    """Canonical string encoded as UTF-8 bytes, ready for hashing."""
    return canonicalize_record(record, content_fields).encode("utf-8")
