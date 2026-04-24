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

Benchmarks on an Intel MacBook with the 0.3.0 vendored-MinHash path (no
GPU, single core, Python 3.12):

| records | wall (s) | records/sec |
|---|---|---|
| 1k | 2.1 | ~475 |
| 10k | 19.3 | ~520 |
| 100k | 191.9 | ~520 |

These are fingerprinting-bound and dominated by the pure-Python MinHash
inner loop (128 modular-multiply-add operations per shingle). The 0.2.x
series delegated MinHash to `datasketch` + `numpy` and was ~6–10× faster
at this stage. The 0.3.0 spec change intentionally cut those deps; the
throughput hit is the honest trade. If you need more speed, shard the
input and fan out; fpagent does not parallelize a single-file run.

For a typical fpagent workload (documents, tickets, records in the
thousands per batch), the pure-Python path is fast enough that it doesn't
dominate the ingest pipeline. Benchmarks at the million-record level put
wall time around 30 minutes; plan shards accordingly.

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
