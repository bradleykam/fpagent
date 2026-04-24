"""Throughput + memory benchmark. Not part of the CI gate.

Runs `fpagent fingerprint` against synthetic JSONL inputs at 10k / 100k / 1M
records and prints wall time and peak RSS. Operators use this to size the
agent for a given dataset.

Usage:
    python tests/benchmarks/bench_fingerprint.py
    python tests/benchmarks/bench_fingerprint.py --sizes 50000 500000
"""
from __future__ import annotations

import argparse
import json
import os
import random
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_SIZES = [10_000, 100_000, 1_000_000]


def write_synthetic(path: Path, n: int, rng: random.Random) -> None:
    """JSONL with one ID column + one content column of plausible text."""
    with path.open("w", encoding="utf-8") as f:
        for i in range(n):
            rec = {
                "record_id": f"rec_{i:07d}",
                "body": " ".join(rng.sample(_WORDS, k=rng.randint(20, 60))),
            }
            f.write(json.dumps(rec) + "\n")


_WORDS = (
    "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. "
    "How vexingly quick daft zebras jump. Sphinx of black quartz judge my vow. "
    "A wizard's job is to vex chumps quickly in fog. Bright vixens jump dozy fowl quack."
).split()


def peak_rss_kb() -> int:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    # On Linux ru_maxrss is in KB; on macOS it's in bytes. Normalize to KB.
    rss = usage.ru_maxrss
    if sys.platform == "darwin":
        rss //= 1024
    return rss


def bench_size(n: int, fmt: str = "jsonl") -> dict:
    rng = random.Random(0xC0FFEE)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        input_path = tmp / f"synthetic_{n}.{fmt}"
        output_path = tmp / "manifest.json"
        write_synthetic(input_path, n, rng)

        start = time.perf_counter()
        before = peak_rss_kb()
        subprocess.run(
            ["fpagent", "fingerprint", "--input", str(input_path), "--output", str(output_path)],
            check=True, stdout=subprocess.DEVNULL,
        )
        wall = time.perf_counter() - start
        after = peak_rss_kb()

    return {
        "records": n,
        "wall_seconds": round(wall, 3),
        "throughput_rps": round(n / wall, 0),
        "peak_child_rss_mb": round(max(after - before, after) / 1024, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="*", default=DEFAULT_SIZES)
    args = ap.parse_args()

    print(f"{'records':>10}  {'wall(s)':>8}  {'rec/s':>10}  {'peak_rss(MB)':>14}")
    print("-" * 50)
    for n in args.sizes:
        r = bench_size(n)
        print(
            f"{r['records']:>10,}  {r['wall_seconds']:>8.3f}  "
            f"{int(r['throughput_rps']):>10,}  {r['peak_child_rss_mb']:>14.1f}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
