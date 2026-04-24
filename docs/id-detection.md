# ID detection

Why it exists, how it decides, how it can go wrong, and how to override.

## Why

fpagent's value proposition is that two copies of the same record should
produce the same fingerprint **even if their identifiers differ**. The way
that works: the agent partitions every column into one of two roles —
`id` or `content` — and fingerprints are computed from content columns
only. IDs are not in the canonical byte sequence at all, so they cannot
change the hash.

This means the classifier has to be reliable. If it misses an ID column
and treats it as content, then two datasets that agree on everything but
assign different UUIDs will fingerprint differently. If it over-classifies
and calls a content column an ID, then content changes in that column go
unnoticed.

## The rules

Applied in order; the first match wins. Every decision records a `reason`
string in the manifest for auditability.

1. **Manual override.** `--id field` and `--content field` from the CLI,
   or the equivalent arguments at the library level. Overrides always win.
   It's an error to name the same field in both lists.
2. **UUID-shaped values.** If ≥ 90% of non-null values in a column match
   the standard UUID regex, that column is an ID.
3. **Long hex-shaped values.** ≥ 90% matching `^[0-9a-f]{16,}$` (for
   example SHA-256 strings) marks a column as an ID.
4. **ID-named columns with high cardinality.** Column names like `id`,
   `uuid`, `case_id`, `patient_id`, `ticket_no`, `transaction_number`,
   and similar (see `_ID_FIELD_NAME_RE` in `src/fpagent/id_detection.py`)
   combined with a distinct-value fraction ≥ 99% mark the column as an
   ID.
5. **Integer-shaped columns with high cardinality.** ≥ 90% of values
   look like integers and distinct-value fraction ≥ 99% → ID.
6. **Default.** Anything else is `content`.

The thresholds — 90% shape, 99% cardinality — are in SPEC.md and cannot
be tuned per-run. That's intentional: drift in thresholds breaks
conformance between implementations.

## Worked example

The dermatology fixture has 29 columns. After classification:

```
$ fpagent fingerprint --input tests/fixtures/dermatology.csv --output /tmp/derm.json
✓ Parsed 50 records from tests/fixtures/dermatology.csv
✓ Identified 2 ID fields, 27 content fields
  ID fields: patient_id, case_id
```

Both `patient_id` and `case_id` are UUID-shaped, so rule 2 fires. Every
other column — `age`, `sex`, `symptoms`, `diagnosis`, and so on — falls
to rule 6 and is treated as content.

Now replace every UUID in both columns with a fresh one and re-verify:

```
$ fpagent verify --manifest /tmp/derm.json --input /tmp/derm_newids.csv
✓ All 50 records match the manifest
```

IDs changed; fingerprints didn't. That's the intended behavior.

## Known failure modes

### Small-dataset integer-cardinality false positives

A column of sequential integers with fewer than ~100 rows may trigger
rule 5 by coincidence: the cardinality ratio is 1.0 because every row
happens to have a distinct integer. The classic case is a `year_of_study`
or `replicate_number` column in a small research table.

When this happens, fingerprints exclude a column that carries meaningful
content. A diff that changes only that column will pass verify when it
shouldn't.

**Detect it** by reading the `field_decisions` section of the manifest
after a fingerprint run. Anything classified as an ID that you think
carries meaning is suspect.

**Fix it** by passing `--content <fieldname>` on the CLI:

```
$ fpagent fingerprint \
    --input mydata.csv \
    --output /tmp/m.json \
    --content year_of_study
```

That forces the column to be content regardless of its shape.

### Content columns that happen to look like UUIDs

Less common but possible: a column of free-form text where ≥ 90% of
values happen to match the UUID pattern. fpagent will classify it as an
ID. Fix with `--content`.

### Inconsistent field presence

If some records have a field and others don't, the agent classifies the
field using the records that do have it. An all-null column is treated
as content. This can cause surprises if two copies of the same dataset
differ on which records include an optional field.

## Manual overrides: when and how

Use `--id` to force a column to be an ID. Use `--content` to force a
column to be content. Both flags can be repeated:

```
$ fpagent fingerprint \
    --input mydata.csv \
    --output /tmp/m.json \
    --id batch_no \
    --content year_of_study \
    --content replicate_id
```

Rule of thumb: **if you care about a column's contents contributing to
the fingerprint, mark it `--content` explicitly**. Don't rely on the
heuristic to do the right thing on a column where the cost of getting it
wrong is high.

## Not in scope

fpagent intentionally does not:

- Detect columns that are *logically* IDs but not *shaped* like them.
  A column called `sample_description` with unique per-row free text
  won't be classified as an ID even if it functions as one.
- Handle composite IDs (two columns together forming an identifier).
  Mark each component with `--id` or, if they carry content, leave them
  as content.
- Pick up on foreign-key relationships between columns.

All three of these would require schema inference, which is out of scope
per SPEC.md. If you need them, combine fpagent with a schema-matching
tool upstream.
