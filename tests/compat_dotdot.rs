//! Tests adapted from Rust's std library canonicalize tests — dot/dotdot and
//! absolute/relative path group.
//!
//! Feature-conditional testing:
//! - WITHOUT dunce: Verifies EXACT UNC format match with std::fs::canonicalize
//! - WITH dunce: Verifies simplified format (no \\?\ prefix when safe)

use soft_canonicalize::soft_canonicalize;
use std::fs::{self, File};
use std::path::Path;
use tempfile::{Builder, TempDir};

/// Helper to create a temporary directory for testing
fn tmpdir() -> TempDir {
    Builder::new()
        .prefix("soft_canonicalize_test")
        .tempdir()
        .unwrap()
}

// ── tests ──────────────────────────────────────────────────────────────────────

/// Test dot and dotdot handling
#[test]
fn soft_canonicalize_dots() {
    let tmpdir = tmpdir();
    #[cfg(not(feature = "dunce"))]
    let tmpdir_canonical = fs::canonicalize(tmpdir.path()).unwrap();

    // Create nested directory structure
    let a = tmpdir.path().join("a");
    let b = a.join("b");
    fs::create_dir_all(&b).unwrap();

    let file = b.join("test.txt");
    File::create(&file).unwrap();

    // Test various dot patterns
    let cases = vec![
        // (input_path, should_equal_to)
        (a.join(".").join("b").join("test.txt"), file.clone()),
        (b.join(".").join("test.txt"), file.clone()),
        (b.join("..").join("b").join("test.txt"), file.clone()),
        (
            a.join("b").join("..").join("b").join("test.txt"),
            file.clone(),
        ),
        (
            tmpdir
                .path()
                .join("a")
                .join("./b")
                .join("../b")
                .join("test.txt"),
            file,
        ),
    ];

    for (input, expected) in cases {
        let soft_result = soft_canonicalize(&input).unwrap();
        let std_result = fs::canonicalize(&expected).unwrap();

        // WITHOUT dunce: EXACT match
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(soft_result, std_result, "Failed for input: {input:?}");
        }

        // WITH dunce: Verify simplified but semantically equal
        #[cfg(feature = "dunce")]
        {
            let soft_str = soft_result.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert!(
                !soft_str.starts_with(r"\\?\"),
                "dunce should simplify for input: {input:?}"
            );

            // Windows-specific UNC format check
            #[cfg(windows)]
            {
                assert!(
                    std_str.starts_with(r"\\?\"),
                    "std returns UNC for input: {input:?}"
                );
            }

            // Semantic equality check
            let soft_stripped = soft_str.strip_prefix(r"\\?\").unwrap_or(&soft_str);
            let std_stripped = std_str.strip_prefix(r"\\?\").unwrap_or(&std_str);
            assert_eq!(soft_stripped, std_stripped, "Failed for input: {input:?}");
        }
    }

    // Test with non-existing components
    let nonexisting_with_dots = a.join("b").join("..").join("c").join("test.txt");
    let result = soft_canonicalize(nonexisting_with_dots).unwrap();

    #[cfg(not(feature = "dunce"))]
    {
        let expected = tmpdir_canonical.join("a").join("c").join("test.txt");
        assert_eq!(result, expected);
    }

    #[cfg(feature = "dunce")]
    {
        let tmpdir_canonical = fs::canonicalize(tmpdir.path()).unwrap();
        let expected = tmpdir_canonical.join("a").join("c").join("test.txt");
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            assert!(
                !result_str.starts_with(r"\\?\"),
                "dunce should simplify non-existing"
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
            assert_eq!(result, expected);
        }
    }
}

/// Test absolute vs relative paths
#[test]
fn soft_canonicalize_absolute_relative() {
    let tmpdir = tmpdir();
    #[cfg(not(feature = "dunce"))]
    let tmpdir_canonical = fs::canonicalize(tmpdir.path()).unwrap();

    // Create test structure
    let subdir = tmpdir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    let file = subdir.join("test.txt");
    File::create(&file).unwrap();

    // Test that relative paths get converted to absolute
    let original_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmpdir.path()).unwrap();

    let relative_result = soft_canonicalize(Path::new("subdir/test.txt")).unwrap();
    assert!(relative_result.is_absolute());

    // WITHOUT dunce: EXACT match
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(relative_result, fs::canonicalize(&file).unwrap());
    }

    // WITH dunce: Simplified format
    #[cfg(feature = "dunce")]
    {
        let soft_str = relative_result.to_string_lossy();
        let std_path = fs::canonicalize(&file).unwrap();
        assert!(!soft_str.starts_with(r"\\?\"), "dunce should simplify");

        // Windows-specific UNC format check
        #[cfg(windows)]
        {
            let std_str = std_path.to_string_lossy();
            assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
        }

        // Unix: Verify basic equality
        #[cfg(not(windows))]
        {
            assert_eq!(relative_result, std_path);
        }
    }

    // Test relative non-existing path
    let relative_nonexisting = soft_canonicalize(Path::new("subdir/nonexisting.txt")).unwrap();

    #[cfg(not(feature = "dunce"))]
    {
        let expected = tmpdir_canonical.join("subdir").join("nonexisting.txt");
        assert_eq!(relative_nonexisting, expected);
    }

    #[cfg(feature = "dunce")]
    {
        let expected = fs::canonicalize(tmpdir.path())
            .unwrap()
            .join("subdir")
            .join("nonexisting.txt");
        #[cfg(windows)]
        {
            let result_str = relative_nonexisting.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            let expected_str = expected.to_string_lossy();
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
            assert_eq!(
                result_str.as_ref(),
                expected_str.trim_start_matches(r"\\?\")
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(relative_nonexisting, expected);
        }
    }

    std::env::set_current_dir(original_cwd).unwrap();
}
