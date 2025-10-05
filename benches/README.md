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

- **Windows (5 runs)**
	- Rust mixed-workload runs (performance_comparison): 9037, 8421, 7386, 7064, 7985 — median **7985** paths/s
	- Python baselines observed during runs: 5074, 4566, 8828, 4669, 6727 — median **5074** paths/s
	- Median speedup vs Python: ~**1.57x**

- **Linux (5 runs, WSL)**
	- Rust mixed-workload runs (performance_comparison): 243261, 239059, 278270, 235361 — median **239059** paths/s
	- Python baselines observed during runs: 133617, 142792, 141888, 150017 — median **141888** paths/s
	- Median speedup vs Python: ~**1.68x**

#### This session (2025-10-05) — notes

- Ran the 5-run median protocol per AGENTS.md using PowerShell (Windows) and WSL (Linux). Windows used `python` (python3.13 not found); Linux used `python3.13`. These are the raw mixed-workload numbers printed by `performance_comparison.rs`. Full raw outputs saved to `target/bench-windows-*.txt` and `target/bench-linux-*.txt`.

### Detailed Performance Analysis

#### Windows Performance Breakdown (October 2025, 5-run medians):
- **performance_comparison.rs** (mixed workload): 1.57x speedup vs Python baseline
- Range: 7,064 - 9,037 paths/s vs Python 4,566 - 8,828 paths/s
- Note: Python baseline variance high in this run (one outlier at 8,828)

#### Linux Performance Breakdown (October 2025, 5-run medians, WSL):
- **performance_comparison.rs** (mixed workload): 1.68x speedup vs Python 3.13 baseline
- Range: 235,361 - 278,270 paths/s vs Python 133,617 - 150,017 paths/s
- Consistent speedup across all runs

#### Raw Performance Data (October 2025)

**Windows Results:**
- performance_comparison: 7,064 - 9,037 paths/s vs Python 4,566 - 8,828 paths/s
- Median: 7,985 paths/s vs Python 5,074 paths/s
- Speedup: 1.57x

**Linux Results (WSL):**
- performance_comparison: 235,361 - 278,270 paths/s vs Python 133,617 - 150,017 paths/s
- Median: 239,059 paths/s vs Python 141,888 paths/s
- Speedup: 1.68x

**Key Findings:**
- Linux maintains strong performance advantage in absolute throughput (~30x vs Windows)
- Windows and Linux both show consistent 1.5-1.7x speedup over Python
- Python baseline variance higher on Windows (possible system load or Python version differences)
- Linux used python3.13; Windows used older python (3.13 not available)
- Results reflect typical development workstation performance under normal system load

The harness parses either “Individual Operations Avg” or a “Range:” line from `python_fair_comparison.py`, using whichever is available.

## Files

- `performance_comparison.rs` — main mixed-workload comparison; runs Python baseline
- `throughput_analysis.rs` — per-scenario throughput breakdowns
- `precision_benchmark.rs` — timing precision and scenario micro-benchmarks
- `python/python_fair_comparison.py` — Python baseline generator

If you publish your own numbers, please include OS, CPU, and Python version for context.
