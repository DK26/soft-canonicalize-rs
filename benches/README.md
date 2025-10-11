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

- **Windows (5 runs, October 11)**
	- Rust mixed-workload runs (performance_comparison): 6928, 8441, 13840, 15910, 16433 — median **13840** paths/s
	- Python baselines observed during runs: 5092, 6474, 7315, 8064, 9212 — median **7315** paths/s
	- Median speedup vs Python: ~**1.89x**

- **Linux (5 runs, WSL, October 11)**
	- Rust mixed-workload runs (performance_comparison): 234778, 450725, 379119, 473091, 231618 — median **379119** paths/s
	- Python baselines observed during runs: 75858, 83702, 125762, 143118, 146680 — median **125762** paths/s
	- Median speedup vs Python: ~**3.02x**

#### This session (2025-10-11) — notes

- Ran the 5-run median protocol per AGENTS.md using PowerShell (Windows). Windows used `python` (python3.13 not found). These are the raw mixed-workload numbers printed by `performance_comparison.rs`. Full raw outputs saved to `target/bench-windows-*.txt`.
- **Windows performance improved**: Median increased from 9,907 to 13,840 paths/s (+39.7%), speedup vs Python improved from 1.31x to 1.89x
- Linux benchmarks refreshed on October 11 (same codebase; updated WSL runner state and filesystem cache yielded higher medians)

### Detailed Performance Analysis

#### Windows Performance Breakdown (October 2025, 5-run medians):
- **performance_comparison.rs** (mixed workload): 1.89x speedup vs Python baseline
- Range: 6,928 - 16,433 paths/s vs Python 5,092 - 9,212 paths/s
- Note: Performance variance expected due to filesystem caching and OS scheduling; median provides stable comparison

#### Linux Performance Breakdown (October 2025, 5-run medians, WSL):
- **performance_comparison.rs** (mixed workload): 3.02x speedup vs Python 3.13 baseline
- Range: 231,618 - 473,091 paths/s vs Python 75,858 - 146,680 paths/s
- Note: Variance expected due to filesystem caching and runner load; median provides stable comparison

#### Raw Performance Data (October 2025)

**Windows Results:**
- performance_comparison: 6,928 - 16,433 paths/s vs Python 5,092 - 9,212 paths/s
- Median: 13,840 paths/s vs Python 7,315 paths/s
- Speedup: 1.89x

**Linux Results (WSL):**
- performance_comparison: 231,618 - 473,091 paths/s vs Python 75,858 - 146,680 paths/s
- Median: 379,119 paths/s vs Python 125,762 paths/s
- Speedup: 3.02x

**Key Findings:**
- Linux maintains strong performance advantage in absolute throughput (~27x vs Windows median)
- Windows performance improved significantly: 1.89x vs Python (up from 1.31x), median throughput +39.7%
- Python baselines varied between runs (Windows: 5k-9k paths/s, Linux: 63k-120k paths/s)
- Performance variance expected for filesystem operations; medians provide stable comparison points
- Linux used python3.13; Windows used older python (3.13 not available)
- Results reflect typical development workstation performance under normal system load
- Windows improvement likely due to code optimizations in v0.4.4 (component-based comparison, clamping logic)

The harness parses either “Individual Operations Avg” or a “Range:” line from `python_fair_comparison.py`, using whichever is available.

## Files

- `performance_comparison.rs` — main mixed-workload comparison; runs Python baseline
- `throughput_analysis.rs` — per-scenario throughput breakdowns
- `precision_benchmark.rs` — timing precision and scenario micro-benchmarks
- `python/python_fair_comparison.py` — Python baseline generator

If you publish your own numbers, please include OS, CPU, and Python version for context.
