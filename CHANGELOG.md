# Changelog

All notable changes to fpagent are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Spec-level
changes bump per `SPEC.md`'s own version; the package version tracks the
implementation.

## [Unreleased]

### Added (v0.2.0)
- Structured logging. `--log-format {human,json}` and `--log-level {DEBUG,INFO,WARNING,ERROR}` at the CLI root. Logger tree rooted at `fpagent` with child loggers per module. JSON mode emits one record per line on stderr with `timestamp`, `level`, `logger`, `event`, and event-type-specific fields.
- Privacy invariant: log records carry counts, field names, and short digest prefixes only — never fingerprint values or raw record content. Enforced by a scanning test that diffs all log output against the manifest's SHA-256/MinHash/TLSH and against raw content fields from the fixture.
- Streaming fingerprinting. CLI does two passes: pass 1 reads all records for ID detection (per-spec requirement — heuristics depend on full-dataset cardinality), pass 2 streams through fingerprinting via the new `fpagent.parser.iter_records()` generator, allowing pass-1 records to be GC'd before pass 2 accumulates bundles. Produces byte-identical output to the pre-refactor single-pass flow.
- `--max-records N` safety cap on `fingerprint`. Exits non-zero without writing a manifest if the input has more records.
- Benchmark script at `tests/benchmarks/bench_fingerprint.py` measuring wall time and peak RSS at 10k/100k/1M synthetic records. Not part of the CI gate.
- `docs/operations.md`: memory envelope, throughput, sharding guidance, and an honest note that full pass-1 streaming requires a spec change (sampling-based ID detection) and is deferred.
- Ed25519 signing. `fpagent keygen --output KEY` writes a 0600 private key and a `.pub` public key. `fpagent fingerprint --signing-key KEY` produces a v1.1.0 manifest with a signature object `{algorithm, value, public_key_fingerprint}`. `fpagent verify --public-key KEY` verifies the signature over the same canonical body as v1.0.0. Trusted keys are distributed out-of-band; the manifest only carries a fingerprint.
- Verify exit codes now distinguish signature failure (3) from content mismatch (1) and schema failure (2). CI can triage.
- `cryptography>=42.0` is now a runtime dep.

### Changed (v0.2.0)
- SPEC bumped to **v1.1.0**. The `signature` field may be the old v1.0.0 hex string OR a signature object. Writers produced by 0.2.0 emit the object form; the string form is accepted on read and explicitly marked as integrity-only.
- `verify` short-circuits with exit code 2 if the manifest does not conform to the JSON Schema.

### Added
- JSON Schema at `fpagent/schemas/manifest.schema.json` is now the authoritative machine-readable form of the manifest format. `verify` runs schema validation before any other check and short-circuits on malformed input.
- `fpagent schema` CLI prints the schema to stdout for programmatic consumers.
- `jsonschema>=4.18` is now a runtime dependency.

## [0.1.0] - 2026-04-24

### Added
- CLI `fpagent fingerprint` and `fpagent verify`.
- CSV, JSON, JSONL, and JSON-directory input formats.
- Heuristic ID / content field detection with manual overrides (see
  `docs/id-detection.md`).
- Unicode NFC → case-fold → whitespace-collapse canonicalization.
- Per-record fingerprint bundle: SHA-256, MinHash (128 permutations, seed 42,
  5-gram shingles, backed by datasketch), TLSH (via py-tlsh; null when
  content is too short).
- Manifest JSON format locked at spec v1.0.0 (see `SPEC.md`).
- Manifest signing via SHA-256 self-sum (placeholder; see **Known issues**).
- Conformance vector under `tests/fixtures/conformance/` with tickets fixture,
  usable by any implementation to validate spec compliance.
- 48 passing unit + conformance tests.

### Changed
- Dropped the pure-Python MinHash fallback introduced during initial build.
  It was not bit-compatible with datasketch 1.6+, which the conformance vector
  was regenerated against. `datasketch` and `py-tlsh` are now hard
  dependencies. `manifest.fingerprint_params.minhash_backend` was removed from
  the manifest JSON because there is exactly one backend.

### Security
- Manifest signing uses SHA-256 self-sum, which detects accidental corruption
  but **does not** defend against a determined adversary. Ed25519 signatures
  are planned for v2. See `SECURITY.md`.

### Known issues
- ID detection on very small integer columns can false-positive as IDs when
  cardinality happens to equal row count. Documented in `docs/id-detection.md`;
  mitigate with `--id` / `--content` overrides.
