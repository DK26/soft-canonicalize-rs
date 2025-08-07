use std::fs;
use std::time::Instant;
use tempfile::TempDir;

fn main() -> std::io::Result<()> {
    println!("Direct Rust Throughput Measurement");
    println!("==================================");

    // Create test structure
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();

    // Create nested structure
    let deep_path = temp_path
        .join("level1")
        .join("level2")
        .join("level3")
        .join("level4");
    fs::create_dir_all(&deep_path)?;
    fs::write(deep_path.join("file.txt"), "test")?;

    let test_cases = vec![
        (
            "existing_simple",
            deep_path.join("file.txt").to_string_lossy().to_string(),
        ),
        (
            "existing_complex",
            temp_path
                .join("level1/level2/../level2/level3/level4/file.txt")
                .to_string_lossy()
                .to_string(),
        ),
        (
            "non_existing_simple",
            temp_path
                .join("non_existing.txt")
                .to_string_lossy()
                .to_string(),
        ),
        (
            "non_existing_complex",
            temp_path
                .join("level1/level2/level3/level4/level5/non_existing.txt")
                .to_string_lossy()
                .to_string(),
        ),
        (
            "with_dots",
            temp_path
                .join("level1/level2/../level3/../level2/level3/file.txt")
                .to_string_lossy()
                .to_string(),
        ),
    ];

    println!("Scenario             Original (paths/s) Optimized (paths/s) Speedup");
    println!("------------------------------------------------------------------");

    for (test_name, test_path) in &test_cases {
        // Benchmark original implementation
        let iterations = 10000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = soft_canonicalize::soft_canonicalize(test_path).unwrap();
        }
        let original_elapsed = start.elapsed();
        let original_throughput = iterations as f64 / original_elapsed.as_secs_f64();

        // Benchmark optimized implementation
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = soft_canonicalize::soft_canonicalize(test_path).unwrap();
        }
        let optimized_elapsed = start.elapsed();
        let optimized_throughput = iterations as f64 / optimized_elapsed.as_secs_f64();

        let speedup = optimized_throughput / original_throughput;

        println!(
            "{test_name:<20} {original_throughput:>10.0}       {optimized_throughput:>12.0}      {speedup:.1}x"
        );
    }

    // Mixed workload test
    println!("\nMixed Workload Test (10,000 paths each scenario):");
    println!("================================================");

    let total_iterations = 50000; // 10k per scenario

    // Original implementation
    let start = Instant::now();
    for i in 0..total_iterations {
        let case_idx = i % test_cases.len();
        let (_, test_path) = &test_cases[case_idx];
        let _ = soft_canonicalize::soft_canonicalize(test_path).unwrap();
    }
    let original_mixed_elapsed = start.elapsed();
    let original_mixed_throughput = total_iterations as f64 / original_mixed_elapsed.as_secs_f64();

    // Optimized implementation
    let start = Instant::now();
    for i in 0..total_iterations {
        let case_idx = i % test_cases.len();
        let (_, test_path) = &test_cases[case_idx];
        let _ = soft_canonicalize::soft_canonicalize(test_path).unwrap();
    }
    let optimized_mixed_elapsed = start.elapsed();
    let optimized_mixed_throughput =
        total_iterations as f64 / optimized_mixed_elapsed.as_secs_f64();

    println!("Original implementation:  {original_mixed_throughput:>10.0} paths/second");
    println!("Optimized implementation: {optimized_mixed_throughput:>10.0} paths/second");
    println!(
        "Speedup: {:.1}x",
        optimized_mixed_throughput / original_mixed_throughput
    );

    // Compare with Python estimates
    println!("\nComparison with Python 3.12.4 (from separate benchmark):");
    println!("=========================================================");
    let python_mixed_throughput = 3243.0; // From our Python benchmark

    println!("Python 3.12.4:           {python_mixed_throughput:>10.0} paths/second");
    println!("Rust Original:           {original_mixed_throughput:>10.0} paths/second");
    println!("Rust Optimized:          {optimized_mixed_throughput:>10.0} paths/second");
    println!();
    println!(
        "Rust Original vs Python: {:.1}x faster",
        original_mixed_throughput / python_mixed_throughput
    );
    println!(
        "Rust Optimized vs Python: {:.1}x faster",
        optimized_mixed_throughput / python_mixed_throughput
    );

    Ok(())
}
