use soft_canonicalize::soft_canonicalize;
//use crate::optimized::soft_canonicalize_optimized;  // We'll add this option
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;

/// Run the Python baseline benchmark and extract the performance number
fn get_python_baseline() -> Result<f64, Box<dyn std::error::Error>> {
    let python_commands = ["python", "python3", "py"];

    for python_cmd in &python_commands {
        let output = Command::new(python_cmd)
            .arg("python_fair_comparison.py")
            .current_dir("benches/python")
            .env("PYTHONIOENCODING", "utf-8")
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);

                for line in stdout.lines() {
                    if line.contains("Individual Operations Avg:") {
                        if let Some(ops_part) = line.split(':').nth(1) {
                            if let Some(number_part) = ops_part.split("ops/s").next() {
                                let clean_number = number_part.trim().replace(',', "");
                                if let Ok(baseline) = clean_number.parse::<f64>() {
                                    return Ok(baseline);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err("Failed to get Python baseline".into())
}

fn create_test_structure() -> Result<TempDir, Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    // Create directory structure matching Python benchmark
    fs::create_dir_all(temp_dir.path().join("existing/nested/deep"))?;
    fs::create_dir_all(temp_dir.path().join("symlinks"))?;

    // Create test files
    fs::write(temp_dir.path().join("existing/file1.txt"), "test")?;
    fs::write(temp_dir.path().join("existing/nested/file2.txt"), "test")?;

    Ok(temp_dir)
}

fn benchmark_rust_resolve(
    base_dir: &Path,
    iterations: usize,
) -> Result<(f64, f64), Box<dyn std::error::Error>> {
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

    let mut times = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();

        // Process all test paths
        for path in &test_paths {
            let _ = soft_canonicalize(path)?;
        }

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64());
    }

    let avg_time: f64 = times.iter().sum::<f64>() / times.len() as f64;
    let total_paths = test_paths.len() * iterations;
    let total_time: f64 = times.iter().sum();
    let paths_per_second = total_paths as f64 / total_time;

    Ok((avg_time, paths_per_second))
}

fn analyze_specific_scenarios(base_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let scenarios = vec![
        ("simple_existing", vec![base_dir.join("existing/file1.txt")]),
        (
            "complex_dots",
            vec![
                base_dir.join("existing/../existing/./nested/../file1.txt"),
                base_dir.join("existing/nested/../../existing/nested/deep/../../file1.txt"),
            ],
        ),
        (
            "nonexistent_paths",
            vec![
                base_dir.join("nonexistent/file.txt"),
                base_dir.join("very/deeply/nested/nonexistent/path/file.txt"),
            ],
        ),
        (
            "mixed_workload",
            vec![
                base_dir.join("existing/file1.txt"),
                base_dir.join("nonexistent/file.txt"),
                base_dir.join("existing/../existing/file1.txt"),
                base_dir.join("very/deeply/nested/nonexistent/path/file.txt"),
            ],
        ),
    ];

    println!("\n🎯 Scenario-Specific Analysis");

    for (scenario_name, paths) in scenarios {
        println!("\n📊 Benchmarking scenario: {scenario_name}");

        // Warmup
        for _ in 0..10 {
            for path in &paths {
                let _ = soft_canonicalize(path);
            }
        }

        // Benchmark
        let mut times = Vec::new();
        let iterations = 500;

        for _ in 0..iterations {
            let start = Instant::now();
            for path in &paths {
                let _ = soft_canonicalize(path);
            }
            let elapsed = start.elapsed();
            times.push(elapsed.as_secs_f64());
        }

        let total_time: f64 = times.iter().sum();
        let paths_per_second = (paths.len() * iterations) as f64 / total_time;
        let avg_time_per_path = total_time / (paths.len() * iterations) as f64;

        println!("   Paths per second: {paths_per_second:.0}");
        println!("   Avg time per path: {:.3} ms", avg_time_per_path * 1000.0);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🦀 Rust soft_canonicalize Performance Analysis");
    println!("============================================================");

    let temp_dir = create_test_structure()?;
    let base_dir = temp_dir.path();
    println!("Test directory: {}", base_dir.display());

    // Overall benchmark
    println!("\n📈 Overall Mixed Workload Benchmark");
    let (avg_time, paths_per_second) = benchmark_rust_resolve(base_dir, 200)?;

    println!("Average time per iteration: {avg_time:.6} seconds");
    println!("Paths per second: {paths_per_second:.0}");

    // Scenario-specific analysis
    analyze_specific_scenarios(base_dir)?;

    // Comparison with Python
    println!("\n📝 Direct Comparison with Python");
    println!("Use these numbers for comparison:");
    println!("Overall mixed workload: {paths_per_second:.0} paths/s");

    println!("\n🔍 Performance Ratio Analysis");
    let python_baseline = get_python_baseline()?;
    let ratio = paths_per_second / python_baseline;
    println!("Python baseline: {python_baseline:.0} ops/s");
    println!("Rust vs Python ratio: {ratio:.2}x");

    if ratio > 1.0 {
        println!(
            "✅ Rust is {:.1}% faster than Python",
            (ratio - 1.0) * 100.0
        );
    } else {
        println!(
            "⚠️  Rust is {:.1}% slower than Python",
            (1.0 - ratio) * 100.0
        );
    }

    Ok(())
}
