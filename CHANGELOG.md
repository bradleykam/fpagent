# Changelog

All notable changes to fpagent are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Spec-level
changes bump per `SPEC.md`'s own version; the package version tracks the
implementation.

## [0.2.0] - 2026-04-24

Enterprise-readiness release. SPEC bumped to **v1.1.0**; v1.0.0 manifests
remain readable.

### Added

- **Ed25519 signing.** `fpagent keygen --output KEY` writes a 0600 private
  key and a `.pub` public key. `fpagent fingerprint --signing-key KEY`
  produces a v1.1.0 manifest whose `signature` field is an object
  `{algorithm, value, public_key_fingerprint}`. `fpagent verify --public-key
  KEY` (file or directory) verifies the signature over the same canonical
  body as v1.0.0. Trusted keys are distributed out-of-band; the manifest
  only carries a 64-char fingerprint.
- **Distinct verify exit codes.** 0 pass · 1 content mismatch · 2 schema
  invalid · 3 signature failure. CI pipelines can triage.
- **JSON Schema** at `fpagent/schemas/manifest.schema.json` (Draft 2020-12)
  is the authoritative machine-readable form of the manifest. `fpagent
  schema` prints it. `verify` runs schema validation first and
  short-circuits on malformed input with exit code 2.
- **Streaming pass 2.** Public `fpagent.parser.iter_records()` generator.
  The CLI now does pass 1 (full read for ID detection) and pass 2 (stream
  from disk) so pass-1 records can be GC'd before the bundle list
  accumulates. Byte-identical output to the pre-refactor single-pass flow
  (guarded by a test).
- **`--max-records N`** safety cap on `fingerprint`.
- **Structured logging.** `--log-format {human,json}` and `--log-level
  {DEBUG,INFO,WARNING,ERROR}` at the CLI root. Logger tree rooted at
  `fpagent`, per-module children. JSON emits one record per line on stderr
  with `timestamp`, `level`, `logger`, `event`, and event-type-specific
  fields. **Privacy invariant:** logs carry counts, field names, and short
  digest prefixes only — never fingerprint values or raw record content.
  Enforced by a scanning test.
- **Supply-chain artifacts.** Release workflow now generates a CycloneDX
  SBOM (`fpagent-<version>.cdx.json`) and Sigstore keyless signatures
  (`*.sigstore.json`) for the wheel, sdist, and SBOM.
- **Benchmark script** at `tests/benchmarks/bench_fingerprint.py` (not in
  CI) reporting wall time and peak RSS at 10k/100k/1M synthetic records.
- **New docs**: `docs/signing.md`, `docs/operations.md`, `docs/supply-chain.md`.
- **New runtime dependencies**: `cryptography>=42.0`, `jsonschema>=4.18`.

### Changed

- **SPEC v1.1.0.** The `signature` field may be the old hex string (v1.0.0
  form, integrity only) or a signature object (new). Writers emit the
  object form; readers accept both. A v1.0.0 string signature still
  verifies, with an unconditional "integrity only, NOT authentic" warning.

### Omitted (evaluated and deferred)

- **SLSA build provenance.** The Sigstore keyless signature already encodes
  the workflow identity, so SLSA would duplicate the same trust fact for a
  pre-1.0 alpha with no enterprise consumers. Revisit at 1.0.
- **PyPI publication.** Per maintainer preference. Install remains
  `pip install git+https://github.com/bradleykam/fpagent` or a wheel from
  the [Releases page](https://github.com/bradleykam/fpagent/releases).

### Known issues (unchanged since 0.1.0)

- ID detection on very small integer columns can false-positive as IDs
  when cardinality happens to equal row count. Documented in
  `docs/id-detection.md`; mitigate with `--id` / `--content` overrides.

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
