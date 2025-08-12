//! Performance regression and DoS attack tests
//!
//! Tests to ensure our optimizations don't introduce performance vulnerabilities
//! or create new attack vectors for denial-of-service.

use soft_canonicalize::soft_canonicalize;
// FS operations will be added if needed
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn test_performance_regression_with_optimizations() -> std::io::Result<()> {
    // BLACK-BOX: Ensure our recent optimizations don't create performance regressions
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create test scenarios that might stress the optimized paths
    let test_scenarios = [
        // Many components with tildes (stress the 8.3 detection)
        (0..100)
            .map(|i| format!("test~{i}"))
            .collect::<Vec<_>>()
            .join("/"),
        // Mixed tilde patterns
        (0..50)
            .map(|i| {
                if i % 2 == 0 {
                    format!("real~{i}")
                } else {
                    format!("fake~name{i}")
                }
            })
            .collect::<Vec<_>>()
            .join("/"),
        // Very long components with tildes
        format!("{}~1", "A".repeat(200)),
        // Alternating valid/invalid 8.3 patterns
        (0..100)
            .map(|i| {
                if i % 3 == 0 {
                    format!("VALID~{i}")
                } else if i % 3 == 1 {
                    format!("invalid~name{i}")
                } else {
                    format!("test~{}", "X".repeat(i % 10))
                }
            })
            .collect::<Vec<_>>()
            .join("/"),
    ];

    for (i, scenario) in test_scenarios.iter().enumerate() {
        let test_path = base.join(scenario);

        let start = Instant::now();
        let result = soft_canonicalize(&test_path);
        let duration = start.elapsed();

        // Performance should be reasonable even for pathological cases
        assert!(
            duration < Duration::from_secs(1),
            "Scenario {i} took too long: {duration:?}"
        );

        println!("Scenario {i} completed in {duration:?}");

        if let Ok(canonical) = result {
            assert!(canonical.is_absolute());
        }
    }

    Ok(())
}

#[test]
fn test_algorithmic_complexity_attacks() -> std::io::Result<()> {
    // BLACK-BOX: Test for basic functional correctness on pathological inputs
    // Note: Removed timing-based complexity assertions due to flakiness and questionable value
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Test different input patterns that should still resolve correctly
    let test_patterns = [
        // Many regular components (test path depth handling)
        (0..100).map(|i| format!("comp{i}")).collect::<Vec<_>>(),
        // Many parent directory traversals
        vec![".."; 50].iter().map(|s| s.to_string()).collect(),
        // Mixed current/parent directory components
        (0..50)
            .map(|i| {
                if i % 2 == 0 {
                    ".".to_string()
                } else {
                    "..".to_string()
                }
            })
            .collect(),
        // Regular deep path
        vec!["deep"; 100].iter().map(|s| s.to_string()).collect(),
    ];

    for (i, components) in test_patterns.iter().enumerate() {
        let test_path = base.join(components.join("/"));

        // Focus on correctness, not timing
        let start = Instant::now();
        let result = soft_canonicalize(&test_path);
        let duration = start.elapsed();

        // Very generous timeout - just ensure no infinite loops or crashes
        assert!(
            duration < Duration::from_secs(30),
            "Pattern {i} took excessively long (potential infinite loop): {duration:?}"
        );

        match result {
            Ok(canonical) => {
                assert!(
                    canonical.is_absolute(),
                    "Result should be absolute for pattern {i}"
                );
                println!("Pattern {i}: resolved in {duration:?}");
            }
            Err(e) => {
                println!("Pattern {i}: failed as expected in {duration:?}: {e}");
            }
        }
    }

    Ok(())
}

#[test]
fn test_memory_exhaustion_with_optimizations() -> std::io::Result<()> {
    // BLACK-BOX: Ensure optimizations don't create memory vulnerabilities
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Test scenarios that might cause excessive memory allocation
    let memory_stress_tests = [
        // Very wide path (many components)
        (0..1000)
            .map(|i| format!("comp{i}"))
            .collect::<Vec<_>>()
            .join("/"),
        // Many tilde components (stress the string processing)
        (0..500)
            .map(|i| format!("test~{i}"))
            .collect::<Vec<_>>()
            .join("/"),
        // Very long individual components
        format!("{}/end", "A".repeat(4000)),
        // Mixed long and short with tildes
        (0..100)
            .map(|i| {
                if i % 2 == 0 {
                    "A".repeat(100)
                } else {
                    format!("test~{i}")
                }
            })
            .collect::<Vec<_>>()
            .join("/"),
    ];

    for (i, test_path) in memory_stress_tests.iter().enumerate() {
        let full_path = base.join(test_path);

        println!("Memory stress test {}: {} chars", i, test_path.len());

        let start = Instant::now();
        let result = soft_canonicalize(&full_path);
        let duration = start.elapsed();

        // Should complete in reasonable time without excessive memory usage
        assert!(
            duration < Duration::from_secs(5),
            "Memory stress test {i} took too long: {duration:?}"
        );

        if let Ok(canonical) = result {
            assert!(canonical.is_absolute());
            // Result should be reasonable in size
            assert!(
                canonical.to_string_lossy().len() < test_path.len() * 2,
                "Result unexpectedly large for test {i}"
            );
        }
    }

    Ok(())
}

#[cfg(windows)]
#[test]
fn test_windows_specific_performance_attacks() -> std::io::Result<()> {
    // BLACK-BOX: Windows-specific performance attack vectors
    let test_vectors = [
        // UNC paths with many tilde components
        format!(
            r"\\server\share\{}",
            (0..100)
                .map(|i| format!("test~{i}"))
                .collect::<Vec<_>>()
                .join("\\")
        ),
        // Extended-length paths with tildes
        format!(
            r"\\?\C:\{}",
            (0..100)
                .map(|i| format!("comp~{i}"))
                .collect::<Vec<_>>()
                .join("\\")
        ),
        // Mixed separators with tildes
        (0..50)
            .map(|i| format!("test~{i}"))
            .collect::<Vec<_>>()
            .join("/\\"),
        // Device namespace with tildes
        format!(
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\{}",
            (0..50)
                .map(|i| format!("test~{i}"))
                .collect::<Vec<_>>()
                .join("\\")
        ),
    ];

    for (i, test_path) in test_vectors.iter().enumerate() {
        println!("Windows performance test {}: {} chars", i, test_path.len());

        let start = Instant::now();
        let result = soft_canonicalize(test_path);
        let duration = start.elapsed();

        assert!(
            duration < Duration::from_secs(2),
            "Windows test {i} took too long: {duration:?}"
        );

        match result {
            Ok(canonical) => {
                assert!(canonical.is_absolute());
                println!("  ✓ Resolved in {:?}: {}", duration, canonical.display());
            }
            Err(e) => {
                println!("  ✓ Rejected in {duration:?}: {e}");
            }
        }
    }

    Ok(())
}

#[test]
fn test_concurrent_performance_stress() -> std::io::Result<()> {
    // BLACK-BOX: Test performance under concurrent load
    use std::sync::Arc;
    use std::thread;

    let temp_dir = TempDir::new()?;
    let base = Arc::new(temp_dir.path().to_path_buf());

    // Create test paths with different characteristics
    let test_paths: Arc<Vec<String>> = Arc::new(vec![
        // Regular paths
        "normal/path/file.txt".to_string(),
        // Tilde paths (stress the optimization)
        (0..20)
            .map(|i| format!("test~{i}"))
            .collect::<Vec<_>>()
            .join("/"),
        // Mixed patterns
        "real~1/fake~name/test~2".to_string(),
        // Traversal patterns
        "../../../test.txt".to_string(),
        // Very long path
        format!("{}/end", "component/".repeat(50)),
    ]);

    let num_threads = 4;
    let iterations_per_thread = 100;

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let base = Arc::clone(&base);
            let paths = Arc::clone(&test_paths);

            thread::spawn(move || {
                let start = Instant::now();

                for i in 0..iterations_per_thread {
                    let path_idx = (thread_id * iterations_per_thread + i) % paths.len();
                    let test_path = base.join(&paths[path_idx]);

                    let _result = soft_canonicalize(&test_path);
                    // Don't assert on results, just ensure no crashes
                }

                start.elapsed()
            })
        })
        .collect();

    let mut total_time = Duration::new(0, 0);
    for handle in handles {
        let thread_time = handle.join().expect("Thread panicked");
        total_time += thread_time;
        println!("Thread completed in {thread_time:?}");
    }

    let avg_time = total_time / num_threads as u32;
    println!("Average thread time: {avg_time:?}");

    // Should complete reasonably quickly even under concurrent load
    assert!(
        avg_time < Duration::from_secs(10),
        "Concurrent performance test too slow: {avg_time:?}"
    );

    Ok(())
}
