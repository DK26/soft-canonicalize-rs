use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tempfile::TempDir;

fn create_test_structure() -> Result<TempDir, Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    // Create directory structure matching performance_comparison
    fs::create_dir_all(temp_dir.path().join("existing/nested/deep"))?;
    fs::create_dir_all(temp_dir.path().join("symlinks"))?;

    // Create test files
    fs::write(temp_dir.path().join("existing/file1.txt"), "test")?;
    fs::write(temp_dir.path().join("existing/nested/file2.txt"), "test")?;

    Ok(temp_dir)
}

fn benchmark_detailed_scenarios(
    base_dir: &Path,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let test_scenarios = vec![
        (
            "existing_simple",
            vec![
                base_dir.join("existing/file1.txt"),
                base_dir.join("existing/nested/file2.txt"),
            ],
        ),
        (
            "non_existing_simple",
            vec![
                base_dir.join("nonexistent/file.txt"),
                base_dir.join("very/deeply/nested/nonexistent/path/file.txt"),
            ],
        ),
        (
            "with_dotdot",
            vec![
                base_dir.join("existing/../existing/file1.txt"),
                base_dir.join("existing/nested/../../existing/nested/file2.txt"),
            ],
        ),
        (
            "complex_paths",
            vec![
                base_dir.join("existing/./nested/../file1.txt"),
                base_dir.join("symlinks/../existing/nested/deep/../../file1.txt"),
            ],
        ),
    ];

    println!("📊 Scenario-by-Scenario Analysis:");
    println!("==================================");
    println!("Scenario             Throughput (paths/s)  Avg Time (ms)");
    println!("-------------------------------------------------------");

    for (scenario_name, paths) in &test_scenarios {
        let mut times = Vec::new();

        for _ in 0..iterations {
            let start = Instant::now();
            for path in paths {
                let _ = soft_canonicalize(path)?;
            }
            let elapsed = start.elapsed();
            times.push(elapsed.as_secs_f64());
        }

        let total_time: f64 = times.iter().sum();
        let total_paths = paths.len() * iterations;
        let throughput = total_paths as f64 / total_time;
        let avg_time_ms = total_time * 1000.0 / total_paths as f64;

        println!("{scenario_name:<20} {throughput:>12.0}       {avg_time_ms:>8.3}");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔬 Detailed Rust soft_canonicalize Analysis");
    println!("==========================================");

    let temp_dir = create_test_structure()?;
    let base_dir = temp_dir.path();
    println!("Test directory: {}", base_dir.display());

    let iterations = 200; // Same as performance_comparison

    // Run detailed scenario analysis
    benchmark_detailed_scenarios(base_dir, iterations)?;

    // Now run the same mixed workload test as performance_comparison
    let test_paths = vec![
        base_dir.join("existing/file1.txt"),
        base_dir.join("existing/nested/file2.txt"),
        base_dir.join("nonexistent/file.txt"),
        base_dir.join("existing/../existing/file1.txt"),
        base_dir.join("existing/./nested/../file1.txt"),
        base_dir.join("symlinks/../existing/nested/deep/../../file1.txt"),
        base_dir.join("very/deeply/nested/nonexistent/path/file.txt"),
        base_dir.join("existing/nested/../../existing/nested/file2.txt"),
    ];

    println!("\n🔬 Mixed Workload (same as performance_comparison):");
    println!("===================================================");

    // Warmup
    for _ in 0..10 {
        for path in &test_paths {
            let _ = soft_canonicalize(path);
        }
    }

    let mut times = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        for path in &test_paths {
            let _ = soft_canonicalize(path)?;
        }
        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64());
    }

    let total_time: f64 = times.iter().sum();
    let total_paths = test_paths.len() * iterations;
    let throughput = total_paths as f64 / total_time;

    println!("Mixed workload throughput: {throughput:.0} paths/s");

    // Compare with Python baseline
    println!("\n📊 Comparison with Python 3.12.4:");
    println!("==================================");
    let python_baseline = 4627.0;

    println!("Python 3.12.4:            {python_baseline:>10.0} paths/second");
    println!("Rust (mixed workload):     {throughput:>10.0} paths/second");
    println!(
        "Performance vs Python:     {:.1}x faster ({:.1}% improvement)",
        throughput / python_baseline,
        (throughput / python_baseline - 1.0) * 100.0
    );

    Ok(())
}
