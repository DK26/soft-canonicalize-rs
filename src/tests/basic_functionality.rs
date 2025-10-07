//! Basic functionality tests for soft_canonicalize
//!
//! Tests core functionality including existing paths, non-existing paths,
//! and deeply nested paths.

use crate::soft_canonicalize;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tempfile::tempdir;

// Synchronize tests that depend on current working directory
static WORKING_DIR_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_existing_path() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test with existing directory
    let result = soft_canonicalize(temp_dir.path())?;
    let std_result = fs::canonicalize(temp_dir.path())?;

    // WITHOUT dunce: EXACT match with std (UNC format on Windows)
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, std_result, "Without dunce: must match std EXACTLY");
    }

    // WITH dunce: Simplified format (no \\?\ when safe)
    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert!(
                !result_str.starts_with(r"\\?\"),
                "dunce should simplify safe paths"
            );
            assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
        }
        #[cfg(not(windows))]
        {
            // Unix: should be identical
            assert_eq!(result, std_result);
        }
    }
    Ok(())
}

#[test]
fn test_non_existing_path() -> std::io::Result<()> {
    let temp_dir = tempdir()?;
    let non_existing = temp_dir
        .path()
        .join("non_existing_sub_dir/non_existing_file.txt");

    let result = soft_canonicalize(non_existing)?;

    // Build expected: canonicalize the existing base, then add non-existing tail
    let base_canonical = fs::canonicalize(temp_dir.path())?;
    let expected_tail = base_canonical.join("non_existing_sub_dir/non_existing_file.txt");

    // WITHOUT dunce: EXACT match (UNC format on Windows)
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            result, expected_tail,
            "Without dunce: must match expected UNC format"
        );
    }

    // WITH dunce: Simplified format when safe
    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected_tail.to_string_lossy();
            assert!(
                !result_str.starts_with(r"\\?\"),
                "dunce should simplify non-existing paths"
            );
            assert!(
                expected_str.starts_with(r"\\?\"),
                "expected has UNC from std"
            );
            // Verify semantic equivalence by checking path ends correctly
            assert!(result_str.ends_with(r"non_existing_sub_dir\non_existing_file.txt"));
        }
        #[cfg(not(windows))]
        {
            // Unix: should be identical
            assert_eq!(result, expected_tail);
        }
    }

    Ok(())
}

#[test]
fn test_relative_path() -> std::io::Result<()> {
    // Serialize tests that depend on current working directory
    let _lock = WORKING_DIR_MUTEX.lock().unwrap();

    let result = soft_canonicalize(Path::new("non/existing/relative/path.txt"))?;

    // Calculate the expected result: current_dir + "non/existing/relative/path.txt"
    let current_dir = std::env::current_dir()?;
    let expected = fs::canonicalize(current_dir)?
        .join("non")
        .join("existing")
        .join("relative")
        .join("path.txt");

    // Result should be absolute and equal to current_dir + relative_path
    assert!(result.is_absolute());
    assert!(result.ends_with("non/existing/relative/path.txt"));

    // WITHOUT dunce: EXACT match (UNC on Windows)
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected, "Without dunce: exact match");
    }

    // WITH dunce: Simplified format
    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(
                !result_str.starts_with(r"\\?\"),
                "dunce should simplify relative paths"
            );
            assert!(
                expected_str.starts_with(r"\\?\"),
                "expected has UNC from std"
            );
            // Verify path ends correctly
            assert!(result_str.ends_with(r"non\existing\relative\path.txt"));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected);
        }
    }

    Ok(())
}

#[test]
fn test_no_filesystem_modification() -> std::io::Result<()> {
    // Test that soft_canonicalize creates no temporary files during operation
    // This validates the "Pure algorithm - No filesystem modification" claim
    let temp_dir = tempdir()?;
    let initial_contents: Vec<_> = fs::read_dir(temp_dir.path())?.collect();
    let initial_count = initial_contents.len();

    // Test canonicalization of non-existing path
    let _result = soft_canonicalize(temp_dir.path().join("non/existing/deep/path.txt"))?;

    // Verify no new files were created
    let final_contents: Vec<_> = fs::read_dir(temp_dir.path())?.collect();
    let final_count = final_contents.len();

    assert_eq!(
        initial_count, final_count,
        "soft_canonicalize should not create any files during operation"
    );

    Ok(())
}

#[test]
fn test_readme_examples() -> std::io::Result<()> {
    // Test that all examples from README.md actually work
    // This ensures documentation promises are backed by working code

    // Example 1: Basic usage from README
    let _path = soft_canonicalize("some/path/../other/file.txt")?;

    // Example 2: Security validation function from README
    fn is_safe_path(user_path: &str, jail: &std::path::Path) -> std::io::Result<bool> {
        let canonical_user = soft_canonicalize(user_path)?;
        let canonical_jail = soft_canonicalize(jail)?;

        // Both paths are now in the same format (UNC or simplified based on dunce feature)
        // Direct comparison works correctly
        Ok(canonical_user.starts_with(canonical_jail))
    }

    // Test the security function with tempdir
    let temp_dir = tempdir()?;
    let jail_path = temp_dir.path();

    // Safe path (inside jail)
    let safe_user_path = format!("{}/safe/file.txt", jail_path.display());
    let is_safe = is_safe_path(&safe_user_path, jail_path)?;
    assert!(is_safe, "Path inside jail should be safe");

    // Potentially unsafe path (tries to escape jail with ..)
    let unsafe_user_path = format!("{}/../escape.txt", jail_path.display());
    let is_unsafe = is_safe_path(&unsafe_user_path, jail_path)?;
    assert!(
        !is_unsafe,
        "Path escaping jail should be detected as unsafe"
    );

    Ok(())
}
