# Performance Benchmarks

Benchmarks here compare `soft_canonicalize` with Python’s `pathlib.Path.resolve(strict=False)` on a mixed workload similar to real usage.

## Requirements

- Python available as one of: `python`, `python3`, or `py`
- No extra Python packages needed (stdlib only)

## How to run

```bash
# Runs Rust benches and will invoke the Python baseline automatically
cargo bench

# (Optional) Run Python baseline only
cd python
python python_fair_comparison.py
```

## Current results (mixed workload)

Note: numbers are machine- and OS-dependent. Results below reflect 5-run campaigns on typical dev hardware.

### Latest Benchmark Results (August 2025)

- **Windows (5 runs)**
	- Rust throughput: min 8,342; median 13,319; max 13,983 paths/s
	- Python baseline: min 6,380; median 7,499; max 7,876 paths/s
	- Speedup: median **1.78x** (range 1.06x - 2.13x)

- **Linux (5 runs)**
	- Rust throughput: min 215,075; median 268,570; max 333,023 paths/s
	- Python baseline: min 58,511; median 144,737; max 151,129 paths/s
	- Speedup: median **1.86x** (range 1.78x - 2.28x)

### Detailed Performance Analysis

#### Windows Performance Breakdown:
- **performance_comparison.rs** (mixed workload): 8,342 - 13,983 paths/s (median: 13,319)
- **precision_benchmark.rs** (scenario analysis): 6,535 - 14,035 paths/s (median: 13,844) 
- **throughput_analysis.rs** (detailed scenarios): 7,793 - 14,552 paths/s (median: 13,668)

#### Linux Performance Breakdown:
- **performance_comparison.rs** (mixed workload): 215,075 - 333,023 paths/s (median: 268,570)
- **precision_benchmark.rs** (scenario analysis): 230,323 - 366,054 paths/s (median: 259,569)
- **throughput_analysis.rs** (detailed scenarios): 253,072 - 439,853 paths/s (median: 259,473)

**Key Findings:**
- Linux performance consistently 15-20x higher than Windows due to filesystem differences
- Performance improvements vs Python: Windows median 78%, Linux median 86%
- Consistent performance across different benchmark methodologies
- Rust maintains strong performance advantage across all test scenarios

The harness parses either “Individual Operations Avg” or a “Range:” line from `python_fair_comparison.py`, using whichever is available.

## Files

- `performance_comparison.rs` — main mixed-workload comparison; runs Python baseline
- `throughput_analysis.rs` — per-scenario throughput breakdowns
- `precision_benchmark.rs` — timing precision and scenario micro-benchmarks
- `python/python_fair_comparison.py` — Python baseline generator

If you publish your own numbers, please include OS, CPU, and Python version for context.
