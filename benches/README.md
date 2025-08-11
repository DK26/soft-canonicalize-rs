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

Note: numbers are machine- and OS-dependent. Results below reflect recent runs on typical dev hardware.

- Windows
	- Python baseline: ~5.9k–6.9k paths/s
	- Rust soft_canonicalize: ~9.5k–11.9k paths/s
	- Speedup: ~1.4–2.0x (varies by run)

- Linux
	- Python baseline: ~95k paths/s
	- Rust soft_canonicalize: ~238k–448k paths/s
	- Speedup: ~2.5–4.7x (varies by run)

The harness parses either “Individual Operations Avg” or a “Range:” line from `python_fair_comparison.py`, using whichever is available.

## Files

- `performance_comparison.rs` — main mixed-workload comparison; runs Python baseline
- `throughput_analysis.rs` — per-scenario throughput breakdowns
- `precision_benchmark.rs` — timing precision and scenario micro-benchmarks
- `python/python_fair_comparison.py` — Python baseline generator

If you publish your own numbers, please include OS, CPU, and Python version for context.
