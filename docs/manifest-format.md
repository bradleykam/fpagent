# Manifest format

This is a human-readable walk through the manifest JSON. For the
authoritative algorithm and byte-level rules, read **[SPEC.md](../SPEC.md)**.
If this document and `SPEC.md` disagree, the spec wins.

## Top-level shape

```json
{
  "spec_version": "1.0.0",
  "agent_version": "0.1.0",
  "agent_implementation": "fpagent-reference",
  "dataset_id": "19678e0f-9fc6-4239-ab1d-62b5fd643870",
  "created_at": "2026-04-24T03:29:53.006787+00:00",
  "record_count": 50,
  "field_decisions": [ /* ... */ ],
  "fingerprint_params": { /* ... */ },
  "records": [ /* ... */ ],
  "signature": "d40e9a72cc3ae510580d39ee62d0aa262fd811d3b8360d353e67b996d9f02ad3"
}
```

### `spec_version`
Which version of `SPEC.md` the manifest conforms to. Consumers should
reject a manifest whose `spec_version` they don't support. Follows
semver on the spec's own cadence (see SPEC.md §1).

### `agent_version`, `agent_implementation`
The version and identifier of the tool that produced the manifest. The
reference implementation shipped by this repo identifies as
`fpagent-reference`. Third-party implementations must pick a distinct
identifier. Useful for debugging a divergence between two tools that claim
to implement the same spec.

### `dataset_id`
A UUIDv4 generated per fingerprint run. Makes it possible to distinguish
two manifests of the same underlying data produced at different times.
Never derived from the data itself.

### `created_at`
ISO 8601 UTC timestamp. Advisory only — not used in signing.

### `record_count`
Number of records fingerprinted. Redundant with `len(records)`; included
for cheap validation.

### `field_decisions`
An ordered list describing what role the agent assigned to each column. One
entry per column that appeared in any input record:

```json
{"field": "patient_id", "role": "id", "reason": "column name matches ^.*_?id$ and value pattern is UUID"}
```

Roles are `"id"` or `"content"`. Only `content` fields contribute to the
fingerprint; `id` fields are deliberately excluded so that renaming
identifiers doesn't change the record's fingerprint.

The `reason` string is advisory and may vary across agent implementations
(the conformance check compares roles, not reasons).

See **[docs/id-detection.md](id-detection.md)** for how the agent decides
and how to override.

### `fingerprint_params`
The exact parameters under which the fingerprints were computed. Consumers
should treat a mismatch here as a hard incompatibility — two manifests with
different params cannot be directly compared.

```json
{
  "canonicalization_version": "1.0.0",
  "minhash_permutations": 128,
  "minhash_seed": 42,
  "shingle_size": 5,
  "tlsh_version": "4.12.1"
}
```

- `canonicalization_version` — version of the canonicalization rules (NFC,
  case-fold, whitespace collapse, etc.) the agent used. Bumped per SPEC.md
  when those rules change.
- `minhash_permutations`, `minhash_seed`, `shingle_size` — the MinHash
  parameters. All three are locked at spec v1.0.0; a manifest with
  different values is invalid under this spec.
- `tlsh_version` — the py-tlsh library version at fingerprint time. Purely
  informational.

### `records`
An ordered list, one entry per input record:

```json
{
  "index": 0,
  "sha256": "a29ca0f3593e03822cd45674e3f25e0a7c5c38e83ffd6a4ec92dfff5302162b7",
  "minhash": "<base64 string, 1368 chars for 128 × uint64>",
  "tlsh": "T1CFA0222C00FC008822A02B008C8328AA2A83CACB20822E80AE208AC083808FC0C2C00E"
}
```

- `index` — the record's position in the input, zero-based. Preserved so
  that a diff can name which specific record changed.
- `sha256` — SHA-256 of the canonicalized content bytes. Lowercase hex.
  Exact-match detection uses this.
- `minhash` — base64-encoded 128 × uint64 MinHash signature. Near-duplicate
  detection uses Jaccard similarity over these arrays.
- `tlsh` — TLSH fuzzy hash of the canonicalized content bytes, or `null`
  when the content is shorter than TLSH's minimum (~50 bytes). Locality-
  sensitive hashing, useful for near-duplicate detection when MinHash is
  too coarse.

### `signature`
A SHA-256 hash of the canonicalized manifest body with the `signature`
field zeroed out first. See SPEC.md §6 for the exact canonicalization.

**Important:** this is a self-sum, not a cryptographic signature. It
detects accidental corruption but not determined tampering. A buyer who
receives a manifest and wants authenticity guarantees should wait for v2
(Ed25519). See [SECURITY.md](../SECURITY.md).

## What's NOT in the manifest

Deliberate omissions:

- **Raw record content.** Only fingerprints are stored. This is the whole
  point: a manifest can be shared without exposing data.
- **Field values.** Even for `id` fields — the agent classifies them and
  discards the values.
- **Per-field fingerprints.** Fingerprints are per-record, not per-field.
  A consumer that wants per-field comparison needs a different tool.
- **Schema metadata beyond column names and roles.** Types, nullability,
  foreign-key relationships, and semantic tags are out of scope.

## Comparing manifests

Consumers can combine the three fingerprint types to answer different
questions:

| Question                                | Use |
|-----------------------------------------|-----|
| Is this the exact same record?          | SHA-256 equality |
| Are these two records near-duplicates?  | MinHash Jaccard ≥ threshold |
| Is this a minor edit of that record?    | TLSH distance ≤ threshold |

How to pick thresholds, how to score a whole-dataset overlap, and how to
present the result are left to the consumer.
