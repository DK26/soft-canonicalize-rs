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
	- Rust mixed-workload runs (performance_comparison): 11294, 10981, 9992, 10437, 9935 — median **10437** paths/s
	- Python baselines observed during runs: 4656, 5398, 5236, 5282, 5689 — median **5282** paths/s
	- Median speedup vs Python: ~**1.97x**

- **Linux (5 runs, WSL)**
	- Rust mixed-workload runs (performance_comparison): 297024, 132240, 226070, 360530, 360530 — median **297024** paths/s
	- Python baselines observed during runs: 92326, 93134, 76609, 91000, 77942 — median **91000** paths/s
	- Median speedup vs Python: ~**3.27x**

#### This session (2025-08-18) — notes

- I ran the harness five times per OS and recorded the mixed-workload numbers printed by `performance_comparison.rs`. These are the raw mixed-workload numbers (medians calculated above). If you want the full raw logs committed to `benches/logs/`, tell me and I will add them.

### Detailed Performance Analysis

#### Windows Performance Breakdown (5-run medians):
- **performance_comparison.rs** (mixed workload): 1.83x speedup (1.70x - 1.93x range)
- **precision_benchmark.rs** (scenario analysis): 1.93x speedup (1.67x - 2.04x range)
- **throughput_analysis.rs** (detailed scenarios): 1.7x speedup (1.6x - 1.7x range)

#### Linux Performance Breakdown (5-run medians):
- **performance_comparison.rs** (mixed workload): 3.56x speedup (3.27x - 4.55x range)
- **precision_benchmark.rs** (scenario analysis): 3.02x speedup (2.41x - 5.25x range)
- **throughput_analysis.rs** (detailed scenarios): 4.7x speedup (3.0x - 5.2x range)

#### Raw Performance Data

**Windows Results:**
- performance_comparison: 9,372 - 10,955 paths/s vs Python 5,139 - 6,001 paths/s
- precision_benchmark: 8,931 - 12,058 paths/s vs Python 5,216 - 6,242 paths/s  
- throughput_analysis: 9,334 - 10,926 paths/s vs Python 5,812 - 6,528 paths/s

**Linux Results:**
- performance_comparison: 276,085 - 425,871 paths/s vs Python 84,389 - 103,782 paths/s
- precision_benchmark: 224,540 - 427,426 paths/s vs Python 70,562 - 112,271 paths/s
- throughput_analysis: 256,280 - 435,998 paths/s vs Python 82,055 - 86,284 paths/s

**Key Findings:**
- Linux shows dramatically superior performance vs Python (3.56x median vs previous 1.86x)
- Windows performance improved and more stable (1.83x median vs previous 1.78x)
- Performance improvements vs Python: Windows median 83%, Linux median 256%
- Excellent consistency across different benchmark methodologies
- Linux filesystem performance advantage over Windows remains significant

The harness parses either “Individual Operations Avg” or a “Range:” line from `python_fair_comparison.py`, using whichever is available.

## Files

- `performance_comparison.rs` — main mixed-workload comparison; runs Python baseline
- `throughput_analysis.rs` — per-scenario throughput breakdowns
- `precision_benchmark.rs` — timing precision and scenario micro-benchmarks
- `python/python_fair_comparison.py` — Python baseline generator

If you publish your own numbers, please include OS, CPU, and Python version for context.
