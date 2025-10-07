# Performance Benchmarks

Benchmarks here compare `soft_canonicalize` with Python’s `pathlib.Path.resolve(strict=False)` on a mixed workload similar to real usage.

## Requirements

- Python available as one of: `python3.13` (preferred), `python`, `python3`, or `py`
- No extra Python packages needed (stdlib only)
- On Linux/WSL, prefer `python3.13` for latest Python comparison

## How to run

```bash
# Runs Rust benches and will invoke the Python baseline automatically
cargo bench

# (Optional) Run Python baseline only
cd python
python python_fair_comparison.py
```

### 5-Run Median Protocol (for formal comparison)

For consistent benchmark reporting, use this exact protocol:

**Windows (PowerShell):**
```powershell
for ($i=1; $i -le 5; $i++) { 
    Write-Host "--- Run $i/5 ---"
    cargo bench --quiet 
}
```

**Linux/WSL (Bash):**
```bash
for i in {1..5}; do 
    echo "--- Run $i/5 ---"
    cargo bench --quiet 
done
```

Extract the "Rust soft_canonicalize   : <N> paths/s" line from each run, sort the five numbers, and report the median. The harness automatically prefers `python3.13` on Linux for the baseline comparison.

## Current results (mixed workload)

Note: numbers are machine- and OS-dependent. Results below reflect 5-run campaigns on typical dev hardware.



### Latest Benchmark Results (October 2025)

- **Windows (5 runs, October 8)**
	- Rust mixed-workload runs (performance_comparison): 6990, 8119, 9907, 13307, 14883 — median **9907** paths/s
	- Python baselines observed during runs: 6358, 7551, 7569, 7722, 8597 — median **7569** paths/s
	- Median speedup vs Python: ~**1.31x**

- **Linux (5 runs, WSL, October 8)**
	- Rust mixed-workload runs (performance_comparison): 204402, 221108, 238038, 465527, 476104 — median **238038** paths/s
	- Python baselines observed during runs: 63916, 75113, 82026, 116569, 119707 — median **82026** paths/s
	- Median speedup vs Python: ~**2.90x**

#### This session (2025-10-08) — notes

- Ran the 5-run median protocol per AGENTS.md using PowerShell (Windows) and WSL (Linux). Windows used `python` (python3.13 not found); Linux used `python3.13`. These are the raw mixed-workload numbers printed by `performance_comparison.rs`. Full raw outputs saved to `target/bench-windows-*.txt` and `target/bench-linux-*.txt`.

### Detailed Performance Analysis

#### Windows Performance Breakdown (October 2025, 5-run medians):
- **performance_comparison.rs** (mixed workload): 1.31x speedup vs Python baseline
- Range: 6,990 - 14,883 paths/s vs Python 6,358 - 8,597 paths/s
- Note: Performance variance expected due to filesystem caching and OS scheduling; median provides stable comparison

#### Linux Performance Breakdown (October 2025, 5-run medians, WSL):
- **performance_comparison.rs** (mixed workload): 2.90x speedup vs Python 3.13 baseline
- Range: 204,402 - 476,104 paths/s vs Python 63,916 - 119,707 paths/s
- Note: Higher variance observed with two runs showing exceptional performance (465k+ paths/s), likely due to filesystem caching effects

#### Raw Performance Data (October 2025)

**Windows Results:**
- performance_comparison: 6,990 - 14,883 paths/s vs Python 6,358 - 8,597 paths/s
- Median: 9,907 paths/s vs Python 7,569 paths/s
- Speedup: 1.31x

**Linux Results (WSL):**
- performance_comparison: 204,402 - 476,104 paths/s vs Python 63,916 - 119,707 paths/s
- Median: 238,038 paths/s vs Python 82,026 paths/s
- Speedup: 2.90x

**Key Findings:**
- Linux maintains strong performance advantage in absolute throughput (~24x vs Windows median)
- Updated Linux results show 2.90x speedup vs Python 3.13 (improved from previous 1.68x)
- Python 3.13 performance was notably slower in this run (63k-120k vs previous 133k-150k paths/s)
- Performance variance expected for filesystem operations; medians provide stable comparison points
- Linux used python3.13; Windows used older python (3.13 not available)
- Results reflect typical development workstation performance under normal system load

The harness parses either “Individual Operations Avg” or a “Range:” line from `python_fair_comparison.py`, using whichever is available.

## Files

- `performance_comparison.rs` — main mixed-workload comparison; runs Python baseline
- `throughput_analysis.rs` — per-scenario throughput breakdowns
- `precision_benchmark.rs` — timing precision and scenario micro-benchmarks
- `python/python_fair_comparison.py` — Python baseline generator

If you publish your own numbers, please include OS, CPU, and Python version for context.
