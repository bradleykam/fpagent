"""CLI entrypoint for fpagent. Pure stdlib (argparse)."""

from __future__ import annotations

import argparse
import json as _json
import sys
from pathlib import Path
from typing import Optional

from .canonicalize import canonicalize_record, canonicalize_to_bytes
from .fingerprint import fingerprint_record
from .id_detection import (
    content_field_names,
    detect_field_roles,
    id_field_names,
)
from .manifest import (
    build_manifest,
    read_manifest,
    sign_manifest,
    verify_signature,
    write_manifest,
)
from .logutil import configure as configure_logging, get as get_logger
from .parser import SUPPORTED_FORMATS, iter_records, read_records
from .schema import load_schema
from .signing import (
    SIG_ALG_ED25519,
    SIG_ALG_SELFSUM,
    load_private_key,
    load_trusted_public_keys,
    sign_manifest_ed25519,
    write_keypair,
)
from .verify import verify as run_verify
from .version import AGENT_VERSION


# ---------------------------------------------------------------------------
# Small stdlib shims that replace what click was doing for us.
# ---------------------------------------------------------------------------

def _parse_csv_list(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def _existing_path(raw: str) -> Path:
    p = Path(raw)
    if not p.exists():
        raise argparse.ArgumentTypeError(f"path does not exist: {p}")
    return p


def _any_path(raw: str) -> Path:
    return Path(raw)


# Colorized output is opt-in via a TTY check. Monochrome otherwise — no new
# dependency for colorama; modern terminals (including Windows Terminal) speak
# ANSI fine. Callers use the info/warn/error helpers which route through the
# logger, so this only matters for a handful of CLI-only prints.
def _is_tty() -> bool:
    return sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Subcommand handlers.
# ---------------------------------------------------------------------------

def cmd_fingerprint(args: argparse.Namespace) -> int:
    log = get_logger("cli.fingerprint")
    id_override = _parse_csv_list(args.id_fields)
    content_override = _parse_csv_list(args.content_fields)

    # Pass 1: full read for ID detection (heuristics need full-dataset
    # cardinality; see docs/operations.md for why streaming ends here).
    records = read_records(args.input, format=args.fmt)
    if args.max_records is not None and len(records) > args.max_records:
        log.error(
            "refusing input above --max-records",
            extra={
                "record_count": len(records),
                "max_records": args.max_records,
                "input_path": str(args.input),
            },
        )
        print(
            f"error: refusing to fingerprint {len(records):,} records "
            f"(> --max-records {args.max_records:,})",
            file=sys.stderr,
        )
        return 1
    log.info(
        f"✓ Parsed {len(records):,} records from {args.input}",
        extra={
            "event_type": "parse_complete",
            "record_count": len(records),
            "input_path": str(args.input),
        },
    )

    decisions = detect_field_roles(records, id_override, content_override)
    ids = id_field_names(decisions)
    contents = content_field_names(decisions)
    log.info(
        f"✓ Identified {len(ids)} ID fields, {len(contents)} content fields",
        extra={
            "event_type": "id_detection_complete",
            "id_field_count": len(ids),
            "content_field_count": len(contents),
            "id_fields": ids,
            "content_fields": contents,
        },
    )
    if ids:
        log.info(f"  ID fields: {', '.join(ids)}")

    # Pass 2: stream fingerprints. Drop the records reference so the garbage
    # collector can reclaim the raw input while we iterate a fresh read.
    del records
    bundles = []
    for rec in iter_records(args.input, format=args.fmt):
        canonical_text = canonicalize_record(rec, contents)
        canonical_bytes = canonicalize_to_bytes(rec, contents)
        bundles.append(fingerprint_record(canonical_bytes, canonical_text))
    log.info(
        f"✓ Fingerprinted {len(bundles):,} records",
        extra={"event_type": "fingerprint_complete", "record_count": len(bundles)},
    )

    manifest = build_manifest(decisions, bundles)
    if args.signing_key:
        private = load_private_key(args.signing_key)
        sign_manifest_ed25519(manifest, private)
        log.info(
            "✓ Manifest signed (Ed25519)",
            extra={"event_type": "signed", "algorithm": "ed25519"},
        )
    else:
        sign_manifest(manifest)
        log.info(
            "✓ Manifest signed (SHA-256 self-sum — integrity only)",
            extra={"event_type": "signed", "algorithm": "sha256-selfsum"},
        )

    write_manifest(manifest, args.output)
    log.info(
        f"→ {args.output}",
        extra={"event_type": "manifest_written", "output_path": str(args.output)},
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Re-fingerprint input and compare against a manifest.

    Exit codes:
      0 — everything matches and the signature verifies
      1 — content mismatch (count or per-record fingerprint drift)
      2 — schema-invalid manifest
      3 — signature failure (distinct from content failure so CI pipelines
          can triage: a content mismatch usually means the data changed;
          a signature failure means the manifest was tampered with or signed
          by a key you don't trust).
    """
    log = get_logger("cli.verify")
    trusted = load_trusted_public_keys(args.public_key) if args.public_key else None
    result = run_verify(args.manifest, args.input, format=args.fmt, trusted_public_keys=trusted)

    if result.schema_error:
        log.error(
            f"✗ Manifest does not conform to the schema: {result.schema_error}",
            extra={"event_type": "schema_invalid", "detail": result.schema_error},
        )
        return 2

    sig = result.signature_check
    if sig.algorithm == SIG_ALG_SELFSUM:
        if sig.valid:
            log.warning(
                "⚠ SHA-256 self-sum verified — integrity only, NOT cryptographic authenticity",
                extra={"event_type": "signature_selfsum_ok"},
            )
        else:
            log.error(
                f"✗ Manifest signature is INVALID ({sig.reason})",
                extra={
                    "event_type": "signature_invalid",
                    "algorithm": sig.algorithm,
                    "reason": sig.reason,
                },
            )
    elif sig.algorithm == SIG_ALG_ED25519:
        if sig.valid:
            log.info(
                f"✓ Ed25519 signature verifies (public key fp {sig.public_key_fingerprint[:16]}…)",
                extra={
                    "event_type": "signature_ed25519_ok",
                    "public_key_fingerprint": sig.public_key_fingerprint,
                },
            )
        else:
            log.error(
                f"✗ Ed25519 signature FAILED: {sig.reason}",
                extra={
                    "event_type": "signature_invalid",
                    "algorithm": "ed25519",
                    "reason": sig.reason,
                    "public_key_fingerprint": sig.public_key_fingerprint,
                },
            )
    else:
        log.error(
            f"✗ Unknown signature: {sig.reason}",
            extra={"event_type": "signature_unknown", "reason": sig.reason},
        )

    if not result.record_count_match:
        log.error(
            f"✗ Record count mismatch: manifest has {result.expected_count}, input has {result.actual_count}",
            extra={
                "event_type": "record_count_mismatch",
                "expected": result.expected_count,
                "actual": result.actual_count,
            },
        )

    if result.mismatches:
        log.error(
            f"✗ {len(result.mismatches)} record(s) do not match the manifest",
            extra={"event_type": "content_mismatch", "mismatch_count": len(result.mismatches)},
        )
        for mm in result.mismatches[:10]:
            log.error(
                f"  record {mm.index}: differs in {', '.join(mm.field_mismatches)}",
                extra={"record_index": mm.index, "fields": list(mm.field_mismatches)},
            )
        if len(result.mismatches) > 10:
            log.error(f"  ... and {len(result.mismatches) - 10} more")

    content_ok = result.content_ok
    if content_ok and sig.valid:
        log.info(
            f"✓ All {result.actual_count:,} records match the manifest",
            extra={"event_type": "verify_pass", "record_count": result.actual_count},
        )
        return 0
    if not sig.valid and content_ok:
        return 3
    return 1


def cmd_keygen(args: argparse.Namespace) -> int:
    if args.output.exists():
        print(f"error: refusing to overwrite existing {args.output}", file=sys.stderr)
        return 1
    pub = write_keypair(args.output)
    print(f"✓ Private key: {args.output} (0600)")
    print(f"✓ Public key:  {pub}")
    print("  Distribute the .pub file out-of-band to anyone who verifies your manifests.")
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    print(_json.dumps(load_schema(), indent=2))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    manifest = read_manifest(args.manifest)
    sig_ok = verify_signature(manifest)

    print(f"Manifest: {args.manifest}")
    print(f"  spec_version:         {manifest.get('spec_version')}")
    print(f"  agent_version:        {manifest.get('agent_version')}")
    print(f"  agent_implementation: {manifest.get('agent_implementation')}")
    print(f"  dataset_id:           {manifest.get('dataset_id')}")
    print(f"  created_at:           {manifest.get('created_at')}")
    print(f"  record_count:         {manifest.get('record_count'):,}")
    print(f"  signature:            {'valid' if sig_ok else 'INVALID'}")

    decisions = manifest.get("field_decisions", [])
    ids = [d["field"] for d in decisions if d["role"] == "id"]
    contents = [d["field"] for d in decisions if d["role"] == "content"]
    print(f"  id_fields ({len(ids)}):")
    for d in decisions:
        if d["role"] == "id":
            print(f"    - {d['field']}  [{d.get('reason', '')}]")
    print(f"  content_fields ({len(contents)}):")
    for d in decisions:
        if d["role"] == "content":
            print(f"    - {d['field']}")

    params = manifest.get("fingerprint_params", {})
    print("  fingerprint_params:")
    for k, v in params.items():
        print(f"    {k}: {v}")
    return 0


# ---------------------------------------------------------------------------
# Parser.
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fpagent",
        description=(
            "fpagent: record-level content fingerprinting for structured data.\n\n"
            "Scope: record-oriented text-heavy structured data (CSV, JSONL, JSON-dir).\n"
            "Out of scope: binary media, time-series, graph data."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"fpagent, version {AGENT_VERSION}"
    )
    parser.add_argument(
        "--log-format",
        choices=("human", "json"),
        default="human",
        help=(
            "Log output mode. 'human' is pretty checkmarks; 'json' is one JSON "
            "record per line on stderr with timestamp/level/event fields."
        ),
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="Minimum level of log records to emit.",
    )

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # fingerprint
    fp = sub.add_parser(
        "fingerprint",
        help="Produce a signed manifest from a dataset.",
        description="Produce a signed manifest from a dataset.",
    )
    fp.add_argument("--input", dest="input", required=True, type=_existing_path)
    fp.add_argument("--output", dest="output", required=True, type=_any_path)
    fp.add_argument(
        "--id-fields",
        dest="id_fields",
        default=None,
        help="Comma-separated field names to force as IDs.",
    )
    fp.add_argument(
        "--content-fields",
        dest="content_fields",
        default=None,
        help="Comma-separated field names to force as content.",
    )
    fp.add_argument(
        "--format",
        dest="fmt",
        choices=SUPPORTED_FORMATS + ("json",),
        default=None,
        help="Input format. Auto-detected if not provided.",
    )
    fp.add_argument(
        "--signing-key",
        dest="signing_key",
        type=_existing_path,
        default=None,
        help=(
            "Path to an Ed25519 PEM private key. When present, the manifest "
            "is signed with Ed25519 (spec 1.1.0). Otherwise a v1.0.0 SHA-256 "
            "self-sum is written (integrity only)."
        ),
    )
    fp.add_argument(
        "--max-records",
        dest="max_records",
        type=int,
        default=None,
        help="Refuse to fingerprint more than N records. Safety cap for unbounded inputs.",
    )
    fp.set_defaults(func=cmd_fingerprint)

    # verify
    vf = sub.add_parser(
        "verify",
        help="Re-fingerprint input and compare against a manifest.",
        description=(
            "Re-fingerprint input and compare against a manifest.\n\n"
            "Exit codes:\n"
            "  0 — content matches and signature verifies\n"
            "  1 — content mismatch\n"
            "  2 — schema-invalid manifest\n"
            "  3 — signature failure (distinct from content)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vf.add_argument("--manifest", dest="manifest", required=True, type=_existing_path)
    vf.add_argument("--input", dest="input", required=True, type=_existing_path)
    vf.add_argument(
        "--format",
        dest="fmt",
        choices=SUPPORTED_FORMATS + ("json",),
        default=None,
    )
    vf.add_argument(
        "--public-key",
        dest="public_key",
        type=_existing_path,
        default=None,
        help="PEM file or directory of *.pub files. Required to verify Ed25519 signatures.",
    )
    vf.set_defaults(func=cmd_verify)

    # keygen
    kg = sub.add_parser(
        "keygen",
        help="Generate an Ed25519 signing keypair.",
        description="Generate an Ed25519 signing keypair. Private key perms set to 0600.",
    )
    kg.add_argument(
        "--output",
        dest="output",
        required=True,
        type=_any_path,
        help="Private key path. Public key written to <output>.pub.",
    )
    kg.set_defaults(func=cmd_keygen)

    # schema
    sc = sub.add_parser(
        "schema",
        help="Print the authoritative JSON Schema for the manifest format.",
        description="Print the authoritative JSON Schema for the manifest format.",
    )
    sc.set_defaults(func=cmd_schema)

    # inspect
    ins = sub.add_parser(
        "inspect",
        help="Print a human-readable summary of a manifest (no fingerprint content).",
        description="Print a human-readable summary of a manifest (no fingerprint content).",
    )
    ins.add_argument("manifest", type=_existing_path)
    ins.set_defaults(func=cmd_inspect)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(fmt=args.log_format, level=args.log_level)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
