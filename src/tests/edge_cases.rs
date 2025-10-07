//! Edge case tests for soft_canonicalize
//!
//! Tests edge cases, boundary detection, and performance characteristics
//! to ensure robust behavior.

use crate::soft_canonicalize;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_boundary_detection() -> std::io::Result<()> {
    let temp_dir = tempdir()?;
    let base = temp_dir.path();

    // Create nested directory structure
    let level1 = base.join("level1");
    let level2 = level1.join("level2");
    let level3 = level2.join("level3");
    std::fs::create_dir_all(&level2)?;
    // level3 doesn't exist - this is our boundary

    // Test exact boundary detection
    let path_at_boundary = level3.join("file.txt");
    let result = soft_canonicalize(path_at_boundary)?;

    // Result should have canonical prefix up to level2, lexical suffix from level3
    let canonical_prefix = soft_canonicalize(&level2)?;
    assert!(result.starts_with(canonical_prefix));

    Ok(())
}

#[test]
fn test_performance_characteristics() -> std::io::Result<()> {
    // Test that validates reasonable performance characteristics
    // This ensures the function doesn't have pathological behavior with deep paths
    // Focus on correctness rather than absolute timing to avoid CI flakiness
    let temp_dir = tempdir()?;

    // Test with progressively deeper paths to ensure no exponential behavior
    let depths = [10, 20, 50];
    let mut all_succeeded = true;

    for depth in depths {
        // Create path with specified depth
        let deep_components = vec!["component"; depth];
        let deep_path: std::path::PathBuf = deep_components.iter().collect();
        let test_path = temp_dir.path().join(&deep_path).join("file.txt");

        // Test that canonicalization completes successfully
        let result = soft_canonicalize(&test_path);

        match result {
            Ok(canonical_path) => {
                // Verify the result is correct
                let expected = fs::canonicalize(temp_dir.path())?
                    .join(deep_path)
                    .join("file.txt");

                #[cfg(not(feature = "dunce"))]
                {
                    assert_eq!(canonical_path, expected, "Without dunce: exact match");
                }

                #[cfg(feature = "dunce")]
                {
                    #[cfg(windows)]
                    {
                        let result_str = canonical_path.to_string_lossy();
                        let expected_str = expected.to_string_lossy();

                        // Deep paths (>260 chars) are NOT safe to simplify, so dunce preserves UNC
                        // Both should be in UNC format for deep paths
                        if result_str.len() > 260 || expected_str.len() > 260 {
                            assert!(
                                result_str.starts_with(r"\\?\"),
                                "dunce preserves UNC for long paths"
                            );
                            assert!(
                                expected_str.starts_with(r"\\?\"),
                                "expected has UNC from std"
                            );
                        } else {
                            // Short paths can be simplified
                            assert!(
                                !result_str.starts_with(r"\\?\"),
                                "dunce simplifies short paths"
                            );
                            assert!(
                                expected_str.starts_with(r"\\?\"),
                                "expected has UNC from std"
                            );
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        assert_eq!(canonical_path, expected);
                    }
                }
            }
            Err(e) => {
                all_succeeded = false;
                eprintln!("Canonicalization failed for depth {depth}: {e}");
            }
        }
    }

    // The main assertion: all deep paths should canonicalize successfully
    // This validates that we don't have stack overflow or other pathological behavior
    assert!(all_succeeded, "Some deep path canonicalizations failed");

    // Optional: Basic timing sanity check (generous limit to avoid CI flakes)
    let very_deep_path = temp_dir
        .path()
        .join(
            vec!["component"; 100]
                .iter()
                .collect::<std::path::PathBuf>(),
        )
        .join("file.txt");

    let start = std::time::Instant::now();
    let _result = soft_canonicalize(very_deep_path)?;
    let elapsed = start.elapsed();

    // Very generous limit - just ensure we don't hang or take extremely long
    assert!(
        elapsed.as_secs() < 1,
        "Even very deep paths should complete within 1 second, took: {elapsed:?}"
    );

    Ok(())
}
