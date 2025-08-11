use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;

/// Run the Python baseline benchmark and extract the performance number
fn get_python_baseline() -> Result<f64, Box<dyn std::error::Error>> {
    println!("📊 Running Python baseline measurement...");

    // Try different Python commands
    let python_commands = ["python", "python3", "py"];
    let script_path = "python_fair_comparison.py";
    let working_dir = "benches/python";

    for python_cmd in &python_commands {
        let output = Command::new(python_cmd)
            .arg(script_path)
            .current_dir(working_dir)
            .env("PYTHONIOENCODING", "utf-8") // Handle encoding issues
            .output();

        match output {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("⚠️  {} failed: {}", python_cmd, stderr.trim());
                    continue;
                }

                let stdout = String::from_utf8_lossy(&output.stdout);

                // Look for "Individual Operations Avg:     5431 ops/s"
                for line in stdout.lines() {
                    if line.contains("Individual Operations Avg:") {
                        if let Some(ops_part) = line.split(':').nth(1) {
                            if let Some(number_part) = ops_part.split("ops/s").next() {
                                let clean_number = number_part.trim().replace(',', "");
                                if let Ok(baseline) = clean_number.parse::<f64>() {
                                    println!(
                                        "✅ Python baseline: {baseline:.0} ops/s (using {python_cmd})"
                                    );
                                    return Ok(baseline);
                                }
                            }
                        }
                    }
                }

                // Fallback: parse Range line "Range: 5431 - 6473 ops/s"
                for line in stdout.lines() {
                    if line.contains("Range:") && line.contains('-') {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        for (i, part) in parts.iter().enumerate() {
                            if part == &"Range:" && i + 1 < parts.len() {
                                let clean_number = parts[i + 1].replace(',', "");
                                if let Ok(baseline) = clean_number.parse::<f64>() {
                                    println!(
                                        "✅ Python baseline (from range): {baseline:.0} ops/s (using {python_cmd})"
                                    );
                                    return Ok(baseline);
                                }
                            }
                        }
                    }
                }

                println!("⚠️  {python_cmd} ran successfully but couldn't parse output");
            }
            Err(e) => {
                println!("⚠️  {python_cmd} not found or failed: {e}");
            }
        }
    }

    Err(format!(
        "Failed to run Python baseline. Tried: {}. \n\
         Make sure Python is installed and the benchmark script exists at {}",
        python_commands.join(", "),
        working_dir
    )
    .into())
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

fn benchmark_implementation<F>(
    name: &str,
    base_dir: &Path,
    iterations: usize,
    mut func: F,
) -> Result<f64, Box<dyn std::error::Error>>
where
    F: FnMut(&Path) -> Result<std::path::PathBuf, std::io::Error>,
{
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

    // Warmup
    for _ in 0..10 {
        for path in &test_paths {
            let _ = func(path);
        }
    }

    let mut times = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();

        for path in &test_paths {
            let _ = func(path)?;
        }

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64());
    }

    let total_time: f64 = times.iter().sum();
    let total_paths = test_paths.len() * iterations;
    let paths_per_second = total_paths as f64 / total_time;

    println!("{name:25}: {paths_per_second:.0} paths/s");

    Ok(paths_per_second)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🦀 Rust soft_canonicalize Performance Test");
    println!("============================================================");

    let temp_dir = create_test_structure()?;
    let base_dir = temp_dir.path();
    println!("Test directory: {}", base_dir.display());

    let iterations = 200;

    println!("\n📈 Performance Analysis (Mixed Workload)");
    println!("------------------------------------------------------------");

    // Benchmark our consolidated implementation
    let rust_perf =
        benchmark_implementation("Rust soft_canonicalize", base_dir, iterations, |path| {
            soft_canonicalize(path)
        })?;

    println!("\n📊 Performance Summary");
    println!("------------------------------------------------------------");

    let python_baseline = get_python_baseline()?;
    let ratio = rust_perf / python_baseline;

    println!("Python Baseline:           {python_baseline:.0} paths/s");
    println!("Rust soft_canonicalize:    {rust_perf:.0} paths/s");
    println!("Performance Ratio:         {ratio:.2}x");

    if ratio > 1.0 {
        println!("✅ Rust beats Python by {:.1}%", (ratio - 1.0) * 100.0);
    } else {
        println!(
            "⚠️  Rust is {:.1}% slower than Python",
            (1.0 - ratio) * 100.0
        );
    }

    println!("\n🎯 PathResolver Algorithm Integration");
    println!("------------------------------------------------------------");
    println!("✅ Fast-path fs::canonicalize for existing paths");
    println!("✅ Boundary detection for mixed existing/non-existing paths");
    println!("✅ Lexical .. resolution without filesystem calls");
    println!("✅ Windows UNC path canonicalization (\\\\?\\C:\\...)");
    println!("✅ Zero external dependencies");

    Ok(())
}
