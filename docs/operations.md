# Operating fpagent

Practical notes for running fpagent on real datasets. Memory envelope, throughput
expectations, and the cap flags you'll want to set in production pipelines.

## Memory envelope

`fpagent fingerprint` does two passes over the input:

1. **ID detection (materialized).** The heuristics in SPEC.md §3 require
   full-dataset cardinality and value-shape ratios, so the first pass reads
   every record into memory. Peak additional RSS is roughly `2 × sum(record_size)`
   (Python dict overhead brings the multiplier up).
2. **Fingerprinting (streaming).** The input file is re-read from disk and
   processed one record at a time. Only the fingerprint bundles — small
   fixed-size objects per record — accumulate in memory for the final manifest.
   Per-record overhead is ~300 bytes.

Peak RSS is therefore dominated by pass 1. Rough sizing:

| records | avg record size | peak RSS (approx) |
|---|---|---|
| 10k | 1 KB | ~60 MB |
| 100k | 1 KB | ~400 MB |
| 1M | 1 KB | ~4 GB |
| 1M | 200 B | ~800 MB |

If pass-1 memory would exceed what you're willing to pay for, split the input
into shards and fingerprint each separately. One shard per manifest.

### Why not fully streaming

Full streaming of the ID-detection pass would require sampling-based
cardinality estimation, which is a spec change: two implementations given the
same input would have to agree on what cardinality ≥ 99% means when computed
from a sample. That's not in SPEC.md 1.x and we're not proposing it unilaterally.

If you need to process inputs too large for pass-1 materialization, the
supported path is sharding, not streaming.

## Throughput

Benchmarks on an M1 MacBook Pro with the reference implementation (no GPU,
single core):

| records | input format | wall (s) | records/sec |
|---|---|---|---|
| 10k | JSONL, 200 B/rec | ~2 | ~5,000 |
| 100k | JSONL, 200 B/rec | ~20 | ~5,000 |
| 1M | JSONL, 200 B/rec | ~200 | ~5,000 |

These are fingerprinting-bound (SHA-256 + MinHash + TLSH per record). Parser
overhead is noise at the expected input sizes.

Re-run the benchmark on your hardware:

```
python tests/benchmarks/bench_fingerprint.py --sizes 10000 100000
```

## Recommended flags for production

### `--max-records N`

Hard cap on the number of records fpagent will fingerprint. Good safety net
when the input comes from an upstream system that might silently explode.
Exits non-zero if the input exceeds `N`; no manifest is written.

### `--signing-key PATH`

Use Ed25519 signing in production. The SHA-256 self-sum fallback is integrity-
only and prints a warning on verify. See [signing.md](signing.md).

### `--format` explicit

Auto-detection by extension is fine for ad-hoc use. Pipelines should pass
`--format` explicitly so an accidentally renamed input fails loudly instead
of being silently reinterpreted.

## Sharding large inputs

If a dataset exceeds the single-process memory envelope, split by shard and
produce one manifest per shard:

```
for shard in data/*.jsonl; do
  fpagent fingerprint --input "$shard" --output "$(dirname $shard)/manifests/$(basename $shard .jsonl).json"
done
```

Consumers downstream are responsible for treating the manifest collection as
a logical dataset. fpagent itself does not merge manifests; that's out of
scope for v1.

## Exit codes

Documented in full under [signing.md § Exit codes](signing.md#exit-codes).
Quick reference:

| Code | Meaning |
|---|---|
| 0 | verify passed |
| 1 | content mismatch |
| 2 | manifest schema invalid |
| 3 | signature failure |

Pipelines can distinguish "data changed" (1) from "manifest was tampered
with / signed with an untrusted key" (3).
