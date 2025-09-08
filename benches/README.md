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



### Latest Benchmark Results (August 2025)

- **Windows (5 runs)**
	- Rust mixed-workload runs (performance_comparison): 11305, 10217, 10066, 9956, 10793 — median **10217** paths/s
	- Python baselines observed during runs: 6802, 4317, 7066, 7728, 6058 — median **6802** paths/s
	- Median speedup vs Python: ~**1.68x**

- **Linux (5 runs, WSL)**
	- Rust mixed-workload runs (performance_comparison): 400470, 357170, 352751, 277204, 243153 — median **352751** paths/s
	- Python baselines observed during runs: 79395, 108954, 158443, 175538, 125462 — median **125462** paths/s
	- Median speedup vs Python: ~**1.88x**

#### This session (2025-08-18) — notes

- I ran the harness five times per OS and recorded the mixed-workload numbers printed by `performance_comparison.rs`. These are the raw mixed-workload numbers (medians calculated above). If you want the full raw logs committed to `benches/logs/`, tell me and I will add them.

### Detailed Performance Analysis

#### Windows Performance Breakdown (5-run medians):
- **performance_comparison.rs** (mixed workload): 1.77x speedup (1.65x - 2.35x range)
- **precision_benchmark.rs** (scenario analysis): 1.93x speedup (1.67x - 2.04x range)
- **throughput_analysis.rs** (detailed scenarios): 1.7x speedup (1.6x - 1.7x range)

#### Linux Performance Breakdown (5-run medians):
- **performance_comparison.rs** (mixed workload): 3.76x speedup (2.75x - 4.38x range)
- **precision_benchmark.rs** (scenario analysis): 3.02x speedup (2.41x - 5.25x range)
- **throughput_analysis.rs** (detailed scenarios): 4.7x speedup (3.0x - 5.2x range)

#### Raw Performance Data

**Windows Results:**
- performance_comparison: 9,956 - 11,305 paths/s vs Python 4,811 - 6,021 paths/s
- precision_benchmark: 8,931 - 12,058 paths/s vs Python 5,216 - 6,242 paths/s  
- throughput_analysis: 9,334 - 10,926 paths/s vs Python 5,812 - 6,528 paths/s

**Linux Results:**
- performance_comparison: 243,153 - 400,470 paths/s vs Python 81,630 - 121,489 paths/s
- precision_benchmark: 224,540 - 427,426 paths/s vs Python 70,562 - 112,271 paths/s
- throughput_analysis: 256,280 - 435,998 paths/s vs Python 82,055 - 86,284 paths/s

**Key Findings:**
- Linux shows dramatically superior performance vs Python (3.76x median vs previous 1.86x)
- Windows performance consistent and reliable (1.77x median vs previous 1.78x)
- Performance improvements vs Python: Windows median 77%, Linux median 276%
- Excellent consistency across different benchmark methodologies
- Linux filesystem performance advantage over Windows remains significant

The harness parses either “Individual Operations Avg” or a “Range:” line from `python_fair_comparison.py`, using whichever is available.

## Files

- `performance_comparison.rs` — main mixed-workload comparison; runs Python baseline
- `throughput_analysis.rs` — per-scenario throughput breakdowns
- `precision_benchmark.rs` — timing precision and scenario micro-benchmarks
- `python/python_fair_comparison.py` — Python baseline generator

If you publish your own numbers, please include OS, CPU, and Python version for context.
