# Performance Benchmarks

This directory contains performance benchmarks comparing `soft_canonicalize` with Python's `pathlib.Path.resolve(strict=False)` and other implementations.

## Benchmark Results

**Latest Results (Release Mode)**:
- **Python 3.12.4 Baseline**: 3,221 paths/s
- **Rust soft_canonicalize**: 5,269 paths/s (1.64x faster, +63.6% improvement)

## Running Benchmarks

```bash
# Performance comparison with Python
cargo bench performance_comparison

# Throughput analysis
cargo bench throughput_analysis

# Precision benchmark
cargo bench precision_benchmark

# Run all benchmarks
cargo bench
```

## Benchmark Files

- `performance_comparison.rs`: Direct comparison with Python's pathlib performance
- `throughput_analysis.rs`: Raw throughput measurement
- `precision_benchmark.rs`: Precision and accuracy testing

## Documentation

The `docs/` directory contains detailed performance analysis documentation:

- `performance_analysis_deep_dive.md`: Comprehensive analysis of why Python is fast
- `rust_optimization_analysis.md`: Rust-specific optimization strategies
- `final_performance_analysis.md`: Summary of performance findings
- Additional analysis files documenting the optimization journey

## Test Environment

Benchmarks are designed to run on mixed workloads including:
- Existing files and directories
- Non-existing paths
- Complex `..` traversals
- Symlink resolution
- Cross-platform path handling
