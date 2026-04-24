"""CLI entrypoint for fpagent."""

import sys
from pathlib import Path
from typing import Optional

import click

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
from .parser import SUPPORTED_FORMATS, read_records
from .schema import ManifestSchemaError, load_schema, validate_manifest
from .signing import (
    SIG_ALG_ED25519,
    SIG_ALG_SELFSUM,
    load_private_key,
    load_trusted_public_keys,
    sign_manifest_ed25519,
    write_keypair,
)
from .verify import verify as run_verify
from .version import AGENT_VERSION, SPEC_VERSION


def _parse_csv_list(value: Optional[str]) -> list:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


@click.group()
@click.version_option(version=AGENT_VERSION, prog_name="fpagent")
def main():
    """fpagent: record-level content fingerprinting for structured data.

    Scope: record-oriented text-heavy structured data (CSV, JSONL, JSON-dir).
    Out of scope: binary media, time-series, graph data.
    """
    pass


@main.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path))
@click.option("--id-fields", default=None, help="Comma-separated field names to force as IDs.")
@click.option("--content-fields", default=None, help="Comma-separated field names to force as content.")
@click.option("--format", "fmt", type=click.Choice(SUPPORTED_FORMATS + ("json",)), default=None,
              help="Input format. Auto-detected if not provided.")
@click.option("--signing-key", type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to an Ed25519 PEM private key. When present, the manifest "
                   "is signed with Ed25519 (spec 1.1.0). Otherwise a v1.0.0 SHA-256 "
                   "self-sum is written (integrity only).")
def fingerprint(input_path: Path, output_path: Path, id_fields, content_fields, fmt, signing_key):
    """Produce a signed manifest from a dataset."""
    id_override = _parse_csv_list(id_fields)
    content_override = _parse_csv_list(content_fields)

    records = read_records(input_path, format=fmt)
    click.echo(f"✓ Parsed {len(records):,} records from {input_path}")

    decisions = detect_field_roles(records, id_override, content_override)
    ids = id_field_names(decisions)
    contents = content_field_names(decisions)
    click.echo(f"✓ Identified {len(ids)} ID fields, {len(contents)} content fields")
    if ids:
        click.echo(f"  ID fields: {', '.join(ids)}")

    bundles = []
    for rec in records:
        canonical_text = canonicalize_record(rec, contents)
        canonical_bytes = canonicalize_to_bytes(rec, contents)
        bundles.append(fingerprint_record(canonical_bytes, canonical_text))
    click.echo(f"✓ Fingerprinted {len(bundles):,} records")

    manifest = build_manifest(decisions, bundles)
    if signing_key:
        private = load_private_key(signing_key)
        sign_manifest_ed25519(manifest, private)
        click.echo("✓ Manifest signed (Ed25519)")
    else:
        sign_manifest(manifest)
        click.echo("✓ Manifest signed (SHA-256 self-sum — integrity only)")

    write_manifest(manifest, output_path)
    click.echo(f"→ {output_path}")


@main.command()
@click.option("--manifest", "manifest_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(SUPPORTED_FORMATS + ("json",)), default=None)
@click.option("--public-key", "public_key_path", type=click.Path(exists=True, path_type=Path), default=None,
              help="PEM file or directory of *.pub files. Required to verify Ed25519 signatures.")
def verify(manifest_path: Path, input_path: Path, fmt, public_key_path):
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
    trusted = load_trusted_public_keys(public_key_path) if public_key_path else None
    result = run_verify(manifest_path, input_path, format=fmt, trusted_public_keys=trusted)

    if result.schema_error:
        click.echo(f"✗ Manifest does not conform to the schema: {result.schema_error}", err=True)
        sys.exit(2)

    sig = result.signature_check
    if sig.algorithm == SIG_ALG_SELFSUM:
        if sig.valid:
            click.echo("⚠ SHA-256 self-sum verified — integrity only, NOT cryptographic authenticity")
        else:
            click.echo(f"✗ Manifest signature is INVALID ({sig.reason})", err=True)
    elif sig.algorithm == SIG_ALG_ED25519:
        if sig.valid:
            click.echo(f"✓ Ed25519 signature verifies (public key fp {sig.public_key_fingerprint[:16]}…)")
        else:
            click.echo(f"✗ Ed25519 signature FAILED: {sig.reason}", err=True)
    else:
        click.echo(f"✗ Unknown signature: {sig.reason}", err=True)

    if not result.record_count_match:
        click.echo(
            f"✗ Record count mismatch: manifest has {result.expected_count}, "
            f"input has {result.actual_count}",
            err=True,
        )

    if result.mismatches:
        click.echo(f"✗ {len(result.mismatches)} record(s) do not match the manifest:", err=True)
        for mm in result.mismatches[:10]:
            click.echo(f"  record {mm.index}: differs in {', '.join(mm.field_mismatches)}", err=True)
        if len(result.mismatches) > 10:
            click.echo(f"  ... and {len(result.mismatches) - 10} more", err=True)

    content_ok = result.content_ok
    if content_ok and sig.valid:
        click.echo(f"✓ All {result.actual_count:,} records match the manifest")
        sys.exit(0)
    if not sig.valid and content_ok:
        sys.exit(3)  # signature-only failure
    sys.exit(1)


@main.command()
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path),
              help="Private key path. Public key written to <output>.pub.")
def keygen(output_path: Path):
    """Generate an Ed25519 signing keypair. Private key perms set to 0600."""
    if output_path.exists():
        raise click.ClickException(f"refusing to overwrite existing {output_path}")
    pub = write_keypair(output_path)
    click.echo(f"✓ Private key: {output_path} (0600)")
    click.echo(f"✓ Public key:  {pub}")
    click.echo("  Distribute the .pub file out-of-band to anyone who verifies your manifests.")


@main.command()
def schema():
    """Print the authoritative JSON Schema for the manifest format."""
    import json as _json
    click.echo(_json.dumps(load_schema(), indent=2))


@main.command()
@click.argument("manifest_path", type=click.Path(exists=True, path_type=Path))
def inspect(manifest_path: Path):
    """Print a human-readable summary of a manifest (no fingerprint content)."""
    manifest = read_manifest(manifest_path)
    sig_ok = verify_signature(manifest)

    click.echo(f"Manifest: {manifest_path}")
    click.echo(f"  spec_version:         {manifest.get('spec_version')}")
    click.echo(f"  agent_version:        {manifest.get('agent_version')}")
    click.echo(f"  agent_implementation: {manifest.get('agent_implementation')}")
    click.echo(f"  dataset_id:           {manifest.get('dataset_id')}")
    click.echo(f"  created_at:           {manifest.get('created_at')}")
    click.echo(f"  record_count:         {manifest.get('record_count'):,}")
    click.echo(f"  signature:            {'valid' if sig_ok else 'INVALID'}")

    decisions = manifest.get("field_decisions", [])
    ids = [d["field"] for d in decisions if d["role"] == "id"]
    contents = [d["field"] for d in decisions if d["role"] == "content"]
    click.echo(f"  id_fields ({len(ids)}):")
    for d in decisions:
        if d["role"] == "id":
            click.echo(f"    - {d['field']}  [{d['reason']}]")
    click.echo(f"  content_fields ({len(contents)}):")
    for d in decisions:
        if d["role"] == "content":
            click.echo(f"    - {d['field']}")

    params = manifest.get("fingerprint_params", {})
    click.echo(f"  fingerprint_params:")
    for k, v in params.items():
        click.echo(f"    {k}: {v}")


if __name__ == "__main__":
    main()
