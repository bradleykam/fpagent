"""JSON Schema loader + runtime manifest validation.

The schema at src/fpagent/schemas/manifest.schema.json is the authoritative
machine-readable form of SPEC.md. If this module and SPEC.md disagree, the
spec wins and the schema is the bug.
"""
from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

import jsonschema


def load_schema() -> dict[str, Any]:
    path = files("fpagent.schemas") / "manifest.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


class ManifestSchemaError(ValueError):
    """Raised when a manifest fails JSON Schema validation."""

    def __init__(self, message: str, path: tuple[str, ...] = ()):
        super().__init__(message)
        self.path = path


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Validate `manifest` against the packaged JSON Schema. Raises
    ManifestSchemaError with a human-readable path on failure.
    """
    schema = load_schema()
    try:
        jsonschema.validate(manifest, schema)
    except jsonschema.ValidationError as exc:
        path = tuple(str(p) for p in exc.absolute_path)
        loc = "/".join(path) if path else "<root>"
        raise ManifestSchemaError(f"manifest invalid at {loc}: {exc.message}", path) from exc
