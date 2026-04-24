# Getting started

A five-minute walkthrough from install to your first manifest to tamper
detection to the core "same case, different IDs" demo. All the CLI output
below is real — paste-compare it against what you see.

## Install

Requires Python 3.10+.

```
pip install fpagent
```

For development, clone the repo and install in editable mode:

```
git clone https://github.com/bradleykam/fpagent
cd fpagent
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/
```

Confirm the install:

```
$ fpagent --version
fpagent, version 0.1.0
```

## Your first manifest

The repo ships with a 50-record dermatology fixture. Fingerprint it:

```
$ fpagent fingerprint --input tests/fixtures/dermatology.csv --output /tmp/derm.json
✓ Parsed 50 records from tests/fixtures/dermatology.csv
✓ Identified 2 ID fields, 27 content fields
  ID fields: patient_id, case_id
✓ Fingerprinted 50 records
✓ Manifest signed
→ /tmp/derm.json
```

Three things happened:

1. **Parse** — the CSV became 50 records.
2. **Classify** — two columns (`patient_id`, `case_id`) were tagged as IDs
   and excluded from fingerprinting. The remaining 27 columns carry
   content. See `docs/id-detection.md` for the heuristics.
3. **Fingerprint** — each record got a SHA-256, a MinHash signature, and a
   TLSH digest over its canonicalized content.

The manifest at `/tmp/derm.json` is the only artifact that ever needs to
leave your machine. See `docs/manifest-format.md` for what's inside.

## Verify a delivery

`verify` re-fingerprints an input and compares it to a manifest. If
everything matches, it exits 0.

```
$ fpagent verify --manifest /tmp/derm.json --input tests/fixtures/dermatology.csv
✓ All 50 records match the manifest
$ echo $?
0
```

## Tamper detection

Change a single field in any record and re-run verify:

```
$ cp tests/fixtures/dermatology.csv /tmp/derm.csv
$ python3 -c 'import csv; rows=list(csv.reader(open("/tmp/derm.csv"))); rows[1][-1] += " CHANGED"; csv.writer(open("/tmp/derm.csv","w")).writerows(rows)'

$ fpagent verify --manifest /tmp/derm.json --input /tmp/derm.csv
✗ 1 record(s) do not match the manifest:
  record 0: differs in sha256, minhash, tlsh
$ echo $?
1
```

Verify exited 1. Any consumer (CI, a rebuild script, a delivery pipeline)
can treat this as a hard fail.

## The core demo: same case, different IDs

This is the behavior that motivates fpagent. Replace every `patient_id` and
`case_id` with fresh UUIDs — but leave every content column alone — and the
manifest still matches.

```
$ python3 -c '
import csv, uuid
rows = list(csv.reader(open("tests/fixtures/dermatology.csv")))
header = rows[0]
for row in rows[1:]:
    for j, h in enumerate(header):
        if h in ("patient_id", "case_id"):
            row[j] = str(uuid.uuid4())
csv.writer(open("/tmp/derm_newids.csv", "w")).writerows(rows)
'

$ fpagent verify --manifest /tmp/derm.json --input /tmp/derm_newids.csv
✓ All 50 records match the manifest
$ echo $?
0
```

Every identifier in every row was replaced. The manifest still verifies.
That's because IDs were classified and skipped during canonicalization, so
the fingerprint is computed from content only.

This is what lets two organizations check whether they hold the same cases
without agreeing on a shared ID scheme, and without exchanging the records
themselves.

## What next

- Read `SPEC.md` for the authoritative algorithm and format.
- Read `docs/manifest-format.md` for a field-by-field manifest walkthrough.
- Read `docs/id-detection.md` to understand when the heuristics need an
  override.
