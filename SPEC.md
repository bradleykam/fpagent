# fpagent Specification

**Version:** 1.1.0
**License:** CC-BY 4.0
**Status:** Draft

## Versioning

| spec_version | Change |
|---|---|
| 1.0.0 | Initial release. `signature` is a lowercase-hex SHA-256 string of the canonical manifest body (integrity only, no authenticity). |
| 1.1.0 | `signature` MAY be a SHA-256 self-sum string (v1.0.0 form, still accepted) OR an object `{"algorithm": "ed25519" \| "sha256-selfsum", "value": "<base64>", "public_key_fingerprint": "<sha256 hex>"}`. Ed25519 signatures over the same canonical body add authenticity. Implementations MUST accept both the string and object forms on read; writers SHOULD emit the object form. |

This specification defines the fingerprinting algorithm, manifest format, and conformance requirements for fpagent-compatible implementations. The reference implementation in this repository (`fpagent-reference`) is one conformant implementation; others in any language are welcome.

## 1. Scope

This specification covers:

- Reading record-oriented structured data
- Deciding which fields are IDs (excluded from fingerprinting) and which are content (included)
- Canonicalizing record content deterministically
- Computing per-record fingerprints (SHA-256, MinHash, TLSH)
- Producing a signed manifest

This specification does NOT cover:

- Matching manifests against each other
- Transport or storage of manifests
- Cryptographic key management for signing

## 2. Input formats

A conformant implementation MUST support at least one of:

- **CSV** with header row, UTF-8 encoded, standard CSV quoting. Each row is a record; columns are fields. Empty cells map to null values.
- **JSONL** (newline-delimited JSON), UTF-8 encoded. Each non-blank line is a JSON object. Object keys are fields.
- **JSON directory**: a directory containing one or more `.json` files. Each file is one record (a JSON object).

Implementations MAY support additional formats. Behavior for malformed input is implementation-defined except that implementations MUST NOT silently drop records on parse errors — they must either fail loudly or report the error in their output.

## 3. ID detection

For each field in the dataset, the implementation decides a role: `id` or `content`. Only `content` fields contribute to fingerprints.

Detection proceeds per-field. The following heuristics are applied in order, with manual overrides always winning:

### 3.1 Manual overrides

If the user provides an explicit `--id-fields` list, those fields are forced to `id`. Likewise `--content-fields` forces `content`. A field appearing in both lists is an error.

### 3.2 Cardinality

Compute `distinct_value_count / record_count`. If ≥ 0.99 (`CARDINALITY_THRESHOLD`), the field is a cardinality candidate for ID.

### 3.3 Value shape

If ≥ 0.90 (`VALUE_SHAPE_THRESHOLD`) of non-null values match any of:

- UUID regex: `^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$` (case-insensitive)
- Hex string of length ≥ 16: `^[0-9a-f]{16,}$` (case-insensitive)
- Integer: `^-?\d+$`

The field is a shape candidate for ID.

### 3.4 Field name hint

If the field name matches (case-insensitive):

- `^(id|uid|uuid)$`
- `_(id|uid|uuid|number|num|no)$`
- `^(case|record|patient|user|event|visit|encounter|transaction|ticket|order)_?(id|uid|uuid|number|num|no)$`

The field is a name-hint candidate.

### 3.5 Decision

A field is `id` if any of:

1. Cardinality AND value shape both fire (for UUID, hex, or integer shape with cardinality ≥ 0.8 for integers)
2. Name hint AND cardinality ≥ 0.9

Otherwise, `content`.

Implementations MUST record the reason for the decision per field in the manifest (`field_decisions[].reason`).

## 4. Canonicalization

For each record, content fields are processed into a deterministic canonical string. This is **version 1.0.0** of the canonicalization algorithm. Any change requires a `canonicalization_version` bump.

### 4.1 Value canonicalization

For each field value:

1. `None` (or JSON null, or empty CSV cell) → empty string
2. Non-string values → Python `str()` equivalent in other languages (e.g., JavaScript `String()`)
3. Unicode NFC normalization
4. Strip HTML-shaped tags using the regex `<[^>]+>` (not a full HTML parser)
5. Lowercase via Unicode-aware `lower()`
6. Collapse runs of whitespace (regex `\s+`) to a single space
7. Trim leading and trailing whitespace

### 4.2 Record canonicalization

1. Sort content field names alphabetically by case-sensitive ASCII byte order
2. For each sorted field name, produce the line `{field}={canonical_value}`
3. Join lines with a single LF character (`\n`)
4. UTF-8 encode the result

The result is the canonical byte sequence for the record. All three fingerprint algorithms operate on this byte sequence (or its string form for MinHash shingling).

## 5. Fingerprint algorithms

Each record produces a bundle of three fingerprints.

### 5.1 SHA-256

Standard SHA-256 of the canonical bytes. Lowercase hex-encoded.

### 5.2 MinHash

- **Reference implementation:** `datasketch.MinHash` at version **1.6+**. Any other implementation **MUST** produce output bit-compatible with datasketch 1.6+ at the parameters below.
- **Permutations:** 128
- **Seed:** 42
- **Shingle size:** 5 whitespace-separated tokens

If the record has fewer than 5 tokens after tokenization, the single shingle is the whole token list joined by spaces. If zero tokens, no shingles are updated and all 128 hashvalues remain at their initial maximum (`2^32 - 1`).

Serialized as base64 of the 128-element `uint64` array in little-endian byte order.

### 5.3 TLSH

- **Library reference:** `py-tlsh` (binds the Trend Micro TLSH C++ implementation)
- Compute `tlsh.hash(canonical_bytes)`
- If the library returns `None`, empty string, or `"TNULL"` (indicating content below TLSH's minimum threshold of ~50 bytes), emit `null` in the manifest

Serialized as the TLSH hex string the library produces (70 hex characters for the standard variant).

## 6. Manifest format

A manifest is a JSON document with the following structure:

```json
{
  "spec_version": "1.0.0",
  "agent_version": "<implementation version>",
  "agent_implementation": "<string identifier>",
  "dataset_id": "<UUID>",
  "created_at": "<ISO 8601 timestamp with timezone>",
  "record_count": <integer>,
  "field_decisions": [
    {"field": "<field name>", "role": "id|content", "reason": "<decision reason>"}
  ],
  "fingerprint_params": {
    "minhash_permutations": 128,
    "minhash_seed": 42,
    "shingle_size": 5,
    "tlsh_version": "<library version or 'unavailable'>",
    "canonicalization_version": "1.0.0"
  },
  "records": [
    {
      "index": <integer>,
      "sha256": "<hex>",
      "minhash": "<base64>",
      "tlsh": "<hex or null>"
    }
  ],
  "signature": "<hex>"
}
```

Fields are REQUIRED unless otherwise noted. Additional fields MAY be present and MUST be preserved by implementations that read and re-emit manifests.

### 6.1 `record_count`

Must equal `len(records)`. Consumers MAY reject manifests where these disagree.

### 6.2 `dataset_id`

A UUID (any version) generated at manifest creation time. Uniquely identifies this manifest.

### 6.3 `field_decisions`

One entry per field seen in the input, with its role and a human-readable reason string. Implementations SHOULD preserve the order fields appeared in the input for readability.

## 7. Signing

### 7.1 Canonical body

Both signing schemes operate on the same canonical byte sequence:

1. Copy the manifest; set its `signature` field to the empty string `""`
2. Serialize with `sort_keys=True` and compact separators (`,` and `:`)
3. UTF-8 encode

This canonical body is what gets hashed or signed. Because the input is identical for both schemes, a signer can switch between them without any other manifest change.

### 7.2 SHA-256 self-sum (v1.0.0+)

1. Compute SHA-256 of the canonical body
2. Hex-encode the digest
3. In v1.0.0, place the digest in `signature` as a lowercase hex string
4. In v1.1.0, `signature` MAY alternatively be `{"algorithm": "sha256-selfsum", "value": "<hex>"}`

**This is not cryptographically secure against a determined adversary** — anyone who modifies the manifest can recompute the hash. It establishes integrity, not authenticity. Consumers verifying a self-sum-signed manifest SHOULD print a warning that its provenance is unattested.

### 7.3 Ed25519 (v1.1.0+)

1. Sign the canonical body with an Ed25519 private key
2. Base64-encode the raw 64-byte signature
3. Compute the public-key fingerprint as `SHA-256(public_key_raw_32_bytes)`, hex
4. Place in `signature`:

   ```json
   {
     "algorithm": "ed25519",
     "value": "<base64 signature>",
     "public_key_fingerprint": "<sha256 hex of raw public key>"
   }
   ```

The public key itself is NOT embedded in the manifest. Verifiers must receive trusted public keys out-of-band (e.g., published on the signer's website, included in a software release, provisioned by an admin). Trust is established by matching the manifest's `public_key_fingerprint` against one of the verifier's trusted keys.

### 7.4 Trust model

An Ed25519 signature proves that the holder of the corresponding private key produced the manifest. It says nothing about:

- Whether the source data is correct, current, or authorized for use
- Whether the signer is who they claim to be (that's the verifier's out-of-band trust decision)
- Whether the manifest was produced honestly (a signer can still sign a manifest of junk data)

Signers SHOULD use distinct keys per service account, rotate them on a published schedule, and revoke compromised keys by announcing the revocation out-of-band and re-signing current manifests with a new key.

## 8. Versioning

- `spec_version`: this document's version. Semantic versioning. Major version bumps may break manifest compatibility.
- `canonicalization_version`: independently versioned. Changes here invalidate all prior manifests.
- `agent_version`: implementation-specific, advisory only.

A consumer SHOULD refuse to match manifests with different major `spec_version` values.

## 9. Conformance

An implementation is conformant if:

1. It accepts the input formats declared in section 2
2. It produces manifests matching the structure in section 6
3. For each conformance test vector in `tests/fixtures/conformance/`, it produces a manifest whose:
   - `field_decisions` match the expected roles (reason text MAY differ)
   - `record_count` matches
   - Per-record `sha256` values match exactly
   - Per-record `minhash` values match exactly
   - Per-record `tlsh` values match exactly when py-tlsh (or equivalent) is available, OR match when both the expected and actual are `null`

Implementations MAY vary in `dataset_id`, `created_at`, `agent_version`, `agent_implementation`, and `signature` values.

## 10. Non-goals

This specification explicitly does not address:

- How to compare manifests (MinHash Jaccard, TLSH distance, SHA equality are all implementation choices for consumers)
- Privacy properties of the fingerprints (they are not zero-knowledge; MinHash is partially invertible for short inputs)
- Transport security
- Handling of structured nested values (only flat field-value records are in scope for v1)

These may be addressed in future spec versions.
