//! Tests adapted from Rust's std library canonicalize tests — existing-path and non-existing-path
//! group, plus edge cases, long paths, unicode, and the compatibility sweep.
//!
//! Feature-conditional testing:
//! - WITHOUT dunce: Verifies EXACT UNC format match with std::fs::canonicalize
//! - WITH dunce: Verifies simplified format (no \\?\ prefix when safe)

use soft_canonicalize::soft_canonicalize;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tempfile::{Builder, TempDir};

/// Helper to create a temporary directory for testing
fn tmpdir() -> TempDir {
    Builder::new()
        .prefix("soft_canonicalize_test")
        .tempdir()
        .unwrap()
}

// ── tests ──────────────────────────────────────────────────────────────────────

/// Test that soft_canonicalize behaves like std canonicalize for existing files
#[test]
fn soft_canonicalize_works_simple() {
    let tmpdir = tmpdir();
    let tmpdir = fs::canonicalize(tmpdir.path()).unwrap();
    let file = tmpdir.join("test");
    File::create(&file).unwrap();

    let soft_result = soft_canonicalize(&file).unwrap();
    let std_result = fs::canonicalize(&file).unwrap();

    // WITHOUT dunce: EXACT format match with std::fs::canonicalize (UNC on Windows)
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            soft_result, std_result,
            "Without dunce: must match std EXACTLY"
        );
        assert_eq!(soft_canonicalize(&file).unwrap(), file);
    }

    // WITH dunce: Simplified format (no \\?\ prefix when safe on Windows)
    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let soft_str = soft_result.to_string_lossy();
            let std_str = std_result.to_string_lossy();

            // std returns \\?\C:\... but dunce simplifies to C:\...
            assert!(std_str.starts_with(r"\\?\"), "std should return UNC format");
            assert!(
                !soft_str.starts_with(r"\\?\"),
                "dunce should simplify safe paths"
            );

            // Verify semantic equivalence
            let soft_stripped = soft_str.strip_prefix(r"\\?\").unwrap_or(&soft_str);
            let std_stripped = std_str.strip_prefix(r"\\?\").unwrap_or(&std_str);
            assert_eq!(
                soft_stripped, std_stripped,
                "Paths should be semantically equal"
            );
        }
        #[cfg(not(windows))]
        {
            // On Unix, dunce doesn't change behavior
            assert_eq!(soft_result, std_result);
        }
    }
}

/// Test soft_canonicalize with non-existing files (the key difference from std)
#[test]
fn soft_canonicalize_nonexisting() {
    let tmpdir = tmpdir();
    let tmpdir_canonical_all = fs::canonicalize(tmpdir.path()).unwrap();

    // Non-existing file in existing directory
    let nonexisting = tmpdir.path().join("does_not_exist.txt");
    let result = soft_canonicalize(&nonexisting).unwrap();

    // WITHOUT dunce: UNC format
    #[cfg(not(feature = "dunce"))]
    {
        let expected = tmpdir_canonical_all.join("does_not_exist.txt");
        assert_eq!(result, expected, "Without dunce: exact UNC format");
    }

    // WITH dunce: Simplified format
    #[cfg(feature = "dunce")]
    {
        let expected = tmpdir_canonical_all.join("does_not_exist.txt");
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            assert!(
                !result_str.starts_with(r"\\?\"),
                "dunce should simplify non-existing paths"
            );
            let expected_str = expected.to_string_lossy();
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
            assert_eq!(
                result_str.as_ref(),
                expected_str.trim_start_matches(r"\\?\")
            );
        }
        #[cfg(not(windows))]
        {
            // On non-Windows, dunce has no effect; exact equality holds
            assert_eq!(result, expected);
        }
    }

    // Non-existing directory
    let nonexisting_dir = tmpdir.path().join("missing_dir").join("file.txt");
    let result2 = soft_canonicalize(&nonexisting_dir).unwrap();

    #[cfg(not(feature = "dunce"))]
    {
        let expected2 = tmpdir_canonical_all.join("missing_dir").join("file.txt");
        assert_eq!(result2, expected2, "Without dunce: exact UNC format");
    }

    #[cfg(feature = "dunce")]
    {
        let expected2 = tmpdir_canonical_all.join("missing_dir").join("file.txt");
        #[cfg(windows)]
        {
            let result2_str = result2.to_string_lossy();
            assert!(!result2_str.starts_with(r"\\?\"), "dunce should simplify");
            let expected2_str = expected2.to_string_lossy();
            assert!(expected2_str.starts_with(r"\\?\"), "std returns UNC");
            assert_eq!(
                result2_str.as_ref(),
                expected2_str.trim_start_matches(r"\\?\")
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result2, expected2);
        }
    }

    // Std canonicalize should fail for these
    assert!(fs::canonicalize(&nonexisting).is_err());
    assert!(fs::canonicalize(&nonexisting_dir).is_err());
}

/// Test edge cases and error conditions
#[test]
fn soft_canonicalize_edge_cases() {
    // Test empty path - should fail exactly like std::fs::canonicalize
    assert!(soft_canonicalize(Path::new("")).is_err());
    assert!(fs::canonicalize("").is_err());

    // Both should fail with NotFound error kind
    match soft_canonicalize(Path::new("")) {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        Ok(_) => panic!("Empty path should fail"),
    }

    // Test root path
    #[cfg(unix)]
    {
        let root_result = soft_canonicalize(Path::new("/")).unwrap();
        assert_eq!(root_result, PathBuf::from("/"));
    }

    #[cfg(windows)]
    {
        let c_root = soft_canonicalize(Path::new("C:\\")).unwrap();

        // WITHOUT dunce: UNC format
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(c_root, PathBuf::from("\\\\?\\C:\\"));
        }

        // WITH dunce: Simplified format
        #[cfg(feature = "dunce")]
        {
            assert_eq!(c_root, PathBuf::from("C:\\"));
        }
    }
}

/// Test with very long paths
#[test]
fn soft_canonicalize_long_paths() {
    let tmpdir = tmpdir();

    // Create a very deep directory structure
    let mut path = tmpdir.path().to_path_buf();
    for i in 0..50 {
        path = path.join(format!("dir_{i}"));
    }

    // Test with non-existing deep path
    let result = soft_canonicalize(&path).unwrap();
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("dir_49"));
}

/// Test Unicode path handling
#[test]
fn soft_canonicalize_unicode() {
    let tmpdir = tmpdir();

    // Test with Unicode characters in path
    let unicode_dir = tmpdir.path().join("测试目录");
    let unicode_file = unicode_dir.join("файл.txt");

    fs::create_dir(&unicode_dir).unwrap();
    File::create(&unicode_file).unwrap();

    // Test existing Unicode path
    let result = soft_canonicalize(&unicode_file).unwrap();

    // WITHOUT dunce: EXACT match
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, fs::canonicalize(&unicode_file).unwrap());
    }

    // WITH dunce: Simplified format
    #[cfg(feature = "dunce")]
    {
        let soft_str = result.to_string_lossy();
        let std_path = fs::canonicalize(&unicode_file).unwrap();
        assert!(
            !soft_str.starts_with(r"\\?\"),
            "dunce should simplify Unicode"
        );

        // Windows-specific UNC format check
        #[cfg(windows)]
        {
            let std_str = std_path.to_string_lossy();
            assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
        }

        // Unix: Verify basic equality
        #[cfg(not(windows))]
        {
            assert_eq!(result, std_path);
        }

        assert!(soft_str.contains("файл.txt"));
    }

    // Test non-existing Unicode path
    let nonexisting_unicode = unicode_dir.join("не_существует.txt");
    let result = soft_canonicalize(nonexisting_unicode).unwrap();
    assert!(result.to_string_lossy().contains("не_существует.txt"));
}

/// Test that soft_canonicalize preserves the behavior for existing paths
#[test]
fn soft_canonicalize_compatibility() {
    let tmpdir = tmpdir();

    // Create various existing paths to test compatibility
    let file = tmpdir.path().join("file.txt");
    let dir = tmpdir.path().join("directory");
    let nested_file = dir.join("nested.txt");

    File::create(&file).unwrap();
    fs::create_dir(&dir).unwrap();
    File::create(&nested_file).unwrap();

    let test_paths = vec![tmpdir.path(), &file, &dir, &nested_file];

    for path in test_paths {
        let soft_result = soft_canonicalize(path).unwrap();
        let std_result = fs::canonicalize(path).unwrap();

        // WITHOUT dunce: EXACT format match
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                soft_result, std_result,
                "Mismatch for existing path: {path:?}"
            );
        }

        // WITH dunce: Verify simplified but semantically equal
        #[cfg(feature = "dunce")]
        {
            let soft_str = soft_result.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert!(
                !soft_str.starts_with(r"\\?\"),
                "dunce should simplify for path: {path:?}"
            );

            // Windows-specific UNC format check
            #[cfg(windows)]
            {
                assert!(
                    std_str.starts_with(r"\\?\"),
                    "std returns UNC for path: {path:?}"
                );
            }

            // Semantic equality
            let soft_stripped = soft_str.strip_prefix(r"\\?\").unwrap_or(&soft_str);
            let std_stripped = std_str.strip_prefix(r"\\?\").unwrap_or(&std_str);
            assert_eq!(
                soft_stripped, std_stripped,
                "Semantic mismatch for path: {path:?}"
            );
        }
    }
}
