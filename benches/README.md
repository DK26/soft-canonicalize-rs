# Performance Benchmarks

This directory contains performance benchmarks comparing `soft_canonicalize` with Python 3.6+ `pathlib.Path.resolve(strict=False)`.

## Quick Test

```bash
# Run Rust benchmarks
cargo bench

# Compare with Python baseline
cd python/
python python_fair_comparison.py
```

## Current Results

- **Python 3.12.4**: 6,845 - 7,159 paths/s
- **Rust soft_canonicalize**: 6,029 - 8,283 paths/s  
- **Performance**: 1.1x - 1.3x faster than Python (machine-dependent)

## Benchmark Files

- `performance_comparison.rs`: Main performance comparison benchmark
- `throughput_analysis.rs`: Detailed throughput measurement
- `precision_benchmark.rs`: Precision testing
- `python/python_fair_comparison.py`: Python baseline measurement

Results vary by hardware. Performance claims should be verified on your specific machine.
