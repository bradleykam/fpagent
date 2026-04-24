"""Heuristics for deciding which fields are IDs (excluded from fingerprinting)
vs content (included).

Rules applied in order with manual overrides winning. Each decision records
its reason in the manifest for auditability.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_INT_RE = re.compile(r"^-?\d+$")

_ID_FIELD_NAME_RE = re.compile(
    r"^(id|uid|uuid)$"
    r"|(^|_)(id|uid|uuid|number|num|no)$"
    r"|^(case|record|patient|user|event|visit|encounter|transaction|ticket|order)_?(id|uid|uuid|number|num|no)$",
    re.IGNORECASE,
)

CARDINALITY_THRESHOLD = 0.99
VALUE_SHAPE_THRESHOLD = 0.90


@dataclass
class FieldDecision:
    field: str
    role: str  # "id" or "content"
    reason: str


def _sequential_int_fraction(values: Sequence[Any]) -> float:
    """Fraction of values that look like integers. Does not require strict
    sequentiality (too brittle); treats any all-integer column as ID-shaped.
    """
    if not values:
        return 0.0
    ints = sum(1 for v in values if v is not None and _INT_RE.match(str(v).strip()))
    return ints / len(values)


def _uuid_fraction(values: Sequence[Any]) -> float:
    if not values:
        return 0.0
    m = sum(1 for v in values if v is not None and _UUID_RE.match(str(v).strip()))
    return m / len(values)


def _hex_fraction(values: Sequence[Any]) -> float:
    if not values:
        return 0.0
    m = sum(1 for v in values if v is not None and _HEX_RE.match(str(v).strip()))
    return m / len(values)


def _cardinality_ratio(values: Sequence[Any]) -> float:
    if not values:
        return 0.0
    distinct = len({v for v in values if v is not None})
    return distinct / len(values)


def detect_field_roles(
    records: List[Dict[str, Any]],
    id_fields_override: Optional[Sequence[str]] = None,
    content_fields_override: Optional[Sequence[str]] = None,
) -> List[FieldDecision]:
    """Decide ID vs content for every field in the dataset.

    Manual overrides (id_fields_override, content_fields_override) win over
    heuristics. It is an error to name the same field in both.
    """
    id_override = set(id_fields_override or [])
    content_override = set(content_fields_override or [])
    conflict = id_override & content_override
    if conflict:
        raise ValueError(
            f"Fields appear in both --id-fields and --content-fields: {sorted(conflict)}"
        )

    # Collect all fields seen across records (records may have inconsistent keys).
    all_fields: List[str] = []
    seen = set()
    for rec in records:
        for k in rec.keys():
            if k not in seen:
                seen.add(k)
                all_fields.append(k)

    decisions: List[FieldDecision] = []
    for field in all_fields:
        if field in id_override:
            decisions.append(FieldDecision(field, "id", "manual_override"))
            continue
        if field in content_override:
            decisions.append(FieldDecision(field, "content", "manual_override"))
            continue

        values = [rec.get(field) for rec in records]
        non_null = [v for v in values if v is not None and v != ""]

        reasons = []

        card = _cardinality_ratio(values) if values else 0.0
        if card >= CARDINALITY_THRESHOLD:
            reasons.append(f"cardinality={card:.3f}")

        if non_null:
            uuid_frac = _uuid_fraction(non_null)
            hex_frac = _hex_fraction(non_null)
            int_frac = _sequential_int_fraction(non_null)
            if uuid_frac >= VALUE_SHAPE_THRESHOLD:
                reasons.append("uuid_shape")
            elif hex_frac >= VALUE_SHAPE_THRESHOLD:
                reasons.append("hex_shape")
            elif int_frac >= VALUE_SHAPE_THRESHOLD and card >= 0.8:
                # Integer-shaped only counts toward ID if cardinality is also
                # high; an int enum (status=0/1/2) should not be treated as ID.
                reasons.append("integer_shape")

        if _ID_FIELD_NAME_RE.search(field):
            reasons.append("name_hint")

        # Decision: ID if cardinality threshold met AND (value shape OR name hint),
        # OR if name_hint is strong on its own with moderate cardinality.
        is_id = False
        if card >= CARDINALITY_THRESHOLD and any(
            r in reasons for r in ("uuid_shape", "hex_shape", "integer_shape")
        ):
            is_id = True
        elif "name_hint" in reasons and card >= 0.9:
            is_id = True

        if is_id:
            decisions.append(FieldDecision(field, "id", ", ".join(reasons)))
        else:
            decisions.append(
                FieldDecision(
                    field,
                    "content",
                    "; ".join(reasons) if reasons else "default",
                )
            )

    return decisions


def content_field_names(decisions: Sequence[FieldDecision]) -> List[str]:
    return [d.field for d in decisions if d.role == "content"]


def id_field_names(decisions: Sequence[FieldDecision]) -> List[str]:
    return [d.field for d in decisions if d.role == "id"]
