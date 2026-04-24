# fpagent

[![CI](https://github.com/bradleykam/fpagent/actions/workflows/test.yml/badge.svg)](https://github.com/bradleykam/fpagent/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Record-level content fingerprinting for structured data.

## What this is

`fpagent` reads a dataset of records, strips ID-like fields, and produces a signed manifest of per-record content fingerprints. The manifest can be compared against other manifests to detect duplicate or near-duplicate records without sharing the raw data.

Use it when you need to answer: "do these two datasets describe the same underlying records, even if the IDs are different?"

## What this is not

- It does not compare manifests to each other. Matching is the consumer's job.
- It does not upload anything. It only produces local files.
- It does not claim cryptographic security for its signatures in v1. SHA-256 self-sum is a placeholder. Ed25519 is planned.
- It is not a record-linkage library (like Splink or dedupe). It produces the fingerprints those libraries or custom consumers can match over.

## Scope

**In scope:** record-oriented, text-heavy, structured data in CSV, JSONL, or directories of JSON files. Medical records, support tickets, transaction logs, news articles, documents with fielded metadata.

**Out of scope for v1:** binary media (images, audio, video), time-series, graph data, unstructured text corpora at document level.

## Install

```
pip install git+https://github.com/bradleykam/fpagent
```

Or grab a built wheel from the [Releases page](https://github.com/bradleykam/fpagent/releases) and `pip install` it directly.

Requires Python 3.10+.

## Quick start

```
fpagent fingerprint --input ./data.csv --output manifest.json
fpagent verify --manifest manifest.json --input ./data.csv
fpagent inspect manifest.json
```

Example:

```
$ fpagent fingerprint --input tests/fixtures/dermatology.csv --output manifest.json
✓ Parsed 50 records from tests/fixtures/dermatology.csv
✓ Identified 2 ID fields, 27 content fields
  ID fields: patient_id, case_id
✓ Fingerprinted 50 records
✓ Manifest signed
→ manifest.json
```

## How it works

1. **Read records** from CSV, JSONL, JSON, or a directory of JSON files.
2. **Detect ID fields** using cardinality, value-shape regexes, and name hints. Manual overrides via `--id-fields` and `--content-fields`.
3. **Canonicalize** each record's content: Unicode NFC, lowercase, strip HTML tags, collapse whitespace, sort fields alphabetically, serialize as `field=value` lines.
4. **Fingerprint** the canonical bytes with three algorithms: SHA-256 (exact match), MinHash (near-duplicate via shingle overlap), TLSH (locality-sensitive hash robust to small edits).
5. **Write a signed manifest** with per-record fingerprints and full parameter provenance.

Two records from different sources with different IDs but the same underlying content will produce identical or near-identical fingerprints — because IDs are excluded from the canonicalization.

## When IDs are actually meaningful

The default heuristics strip anything that looks like a unique identifier (UUIDs, sequential integers, hex hashes, fields named `*_id`). For datasets with real cross-provider identifiers (DOI, ISBN, ISIN, CUSIP, patent number), these carry real matching signal. Override with `--content-fields`:

```
fpagent fingerprint --input papers.csv --output manifest.json --content-fields doi,title,abstract
```

## Specification

See [SPEC.md](SPEC.md) for the full fingerprinting specification. The spec is licensed under CC-BY 4.0. Third-party implementations are encouraged — any implementation producing output that matches the conformance test vectors is conformant.

## Related projects

fpagent produces fingerprints; it does **not** match records itself. If
you're looking for matching, these are the closest neighbors:

- **[dedupe](https://github.com/dedupeio/dedupe)** — probabilistic record
  linkage and deduplication. Learns a model from labeled pairs. fpagent
  is complementary: dedupe can consume fpagent fingerprints as features.
- **[Splink](https://moj-analytical-services.github.io/splink/)** —
  scalable Fellegi-Sunter record linkage on Spark / DuckDB. Again,
  fpagent is upstream: produce fingerprints, feed them to Splink.
- **[datasketch](https://github.com/ekzhu/datasketch)** — the MinHash
  library fpagent uses internally. Use it directly if you only want
  MinHashes and don't need the rest of the manifest format.
- **[NeMo Curator](https://github.com/NVIDIA/NeMo-Curator)** — large-
  scale deduplication for training-data pipelines. Heavier and
  GPU-oriented; fpagent is the narrow, local, CLI-shaped alternative.

## Testing

Run `pytest tests/` with the dev deps installed. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow.

## License

Code: Apache 2.0. See [LICENSE](LICENSE).
Spec (SPEC.md): CC-BY 4.0.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
