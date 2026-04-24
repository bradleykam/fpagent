"""Manifest construction, signing, and I/O.

The manifest is a JSON document. Signing for v1 is a SHA-256 self-sum
(NOT cryptographically secure against a determined adversary; placeholder
for Ed25519 in v2, documented in SPEC.md).
"""

import hashlib
import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .fingerprint import (
    FingerprintBundle,
    MINHASH_PERMUTATIONS,
    MINHASH_SEED,
    SHINGLE_SIZE,
    tlsh_version_string,
)
from .id_detection import FieldDecision
from .version import (
    AGENT_IMPLEMENTATION,
    AGENT_VERSION,
    CANONICALIZATION_VERSION,
    SPEC_VERSION,
)


def build_manifest(
    field_decisions: List[FieldDecision],
    records_fingerprints: List[FingerprintBundle],
) -> Dict[str, Any]:
    """Build the manifest dict (unsigned)."""
    manifest = {
        "spec_version": SPEC_VERSION,
        "agent_version": AGENT_VERSION,
        "agent_implementation": AGENT_IMPLEMENTATION,
        "dataset_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records_fingerprints),
        "field_decisions": [asdict(d) for d in field_decisions],
        "fingerprint_params": {
            "minhash_permutations": MINHASH_PERMUTATIONS,
            "minhash_seed": MINHASH_SEED,
            "shingle_size": SHINGLE_SIZE,
            "tlsh_version": tlsh_version_string(),
            "canonicalization_version": CANONICALIZATION_VERSION,
        },
        "records": [
            {
                "index": i,
                "sha256": fp.sha256,
                "minhash": fp.minhash,
                "tlsh": fp.tlsh,
            }
            for i, fp in enumerate(records_fingerprints)
        ],
        "signature": "",
    }
    return manifest


def _canonical_json_for_signing(manifest: Dict[str, Any]) -> bytes:
    """Serialize manifest deterministically for signing. The signature field
    is forced to empty string during signing so the signature can be verified
    without knowing it in advance.
    """
    m = dict(manifest)
    m["signature"] = ""
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Compute signature and insert it. Returns the same dict for chaining."""
    sig = hashlib.sha256(_canonical_json_for_signing(manifest)).hexdigest()
    manifest["signature"] = sig
    return manifest


def verify_signature(manifest: Dict[str, Any]) -> bool:
    """Check that the stored signature matches the manifest body."""
    stored = manifest.get("signature", "")
    expected = hashlib.sha256(_canonical_json_for_signing(manifest)).hexdigest()
    return stored == expected


def write_manifest(manifest: Dict[str, Any], path: Path) -> None:
    """Write manifest to disk as pretty-printed JSON."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")


def read_manifest(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
