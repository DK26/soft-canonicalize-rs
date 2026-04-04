//! Core tests for feature combination behaviors.
//!
//! Covers basic functionality (existing + non-existing paths), feature
//! detection, and edge cases that apply to all feature combinations.
//!
//! | Features                          | Backend Used                          |
//! |-----------------------------------|---------------------------------------|
//! | default (proc-canonicalize)       | proc_canonicalize::canonicalize       |
//! | default + dunce                   | proc_canonicalize with dunce feature  |
//! | --no-default-features             | std::fs::canonicalize                 |
//! | --no-default-features + dunce     | dunce::canonicalize (Windows)         |
//!
//! Run specific configurations:
//! ```bash
//! cargo test --test feature_combinations_core
//! cargo test --test feature_combinations_core --features anchored,dunce
//! cargo test --test feature_combinations_core --no-default-features --features anchored
//! cargo test --test feature_combinations_core --no-default-features --features anchored,dunce
//! ```

use soft_canonicalize::soft_canonicalize;

// ============================================================================
// Basic Functionality Tests (All Feature Combinations)
// ============================================================================

/// Verify soft_canonicalize works for existing paths.
/// This should work regardless of which backend is used.
#[test]
fn test_existing_path_canonicalization() {
    // Use temp dir which always exists
    let tmp = std::env::temp_dir();
    let result = soft_canonicalize(&tmp);

    assert!(result.is_ok(), "Should canonicalize existing temp dir");

    let canonicalized = result.unwrap();

    // Should be absolute
    assert!(
        canonicalized.is_absolute(),
        "Result should be absolute path"
    );

    // Verify it matches std::fs::canonicalize behavior for existing paths
    // (accounting for dunce feature on Windows)
    let std_result = std::fs::canonicalize(&tmp).expect("std should work on temp dir");

    #[cfg(all(windows, feature = "dunce"))]
    {
        // With dunce, our result should be simplified (no \\?\)
        let our_str = canonicalized.to_string_lossy();
        let std_str = std_result.to_string_lossy();

        // Our path should NOT have \\?\ prefix
        assert!(
            !our_str.starts_with(r"\\?\"),
            "With dunce feature, path should be simplified: {}",
            our_str
        );

        // std always returns UNC on Windows
        // Our simplified path should equal std's path minus the prefix
        assert_eq!(
            our_str.as_ref(),
            std_str.trim_start_matches(r"\\?\"),
            "Simplified path should match std minus UNC prefix"
        );
    }

    #[cfg(not(all(windows, feature = "dunce")))]
    {
        // Without dunce (or on non-Windows), should match std exactly
        assert_eq!(
            canonicalized, std_result,
            "Without dunce, should match std::fs::canonicalize exactly"
        );
    }
}

/// Verify soft_canonicalize works for non-existing paths.
/// This is the core value proposition of the crate.
#[test]
fn test_nonexisting_path_canonicalization() {
    let tmp = std::env::temp_dir();
    let non_existing = tmp.join("definitely_does_not_exist_12345");

    // std::fs::canonicalize should fail
    assert!(
        std::fs::canonicalize(&non_existing).is_err(),
        "std should fail on non-existing path"
    );

    // soft_canonicalize should succeed
    let result = soft_canonicalize(&non_existing);
    assert!(
        result.is_ok(),
        "soft_canonicalize should handle non-existing paths"
    );

    let canonicalized = result.unwrap();
    assert!(
        canonicalized.is_absolute(),
        "Result should be absolute path"
    );

    // Should end with our non-existing component
    assert!(
        canonicalized
            .to_string_lossy()
            .contains("definitely_does_not_exist_12345"),
        "Should preserve non-existing path component"
    );
}

/// Verify dotdot resolution in non-existing paths.
#[test]
fn test_dotdot_resolution_nonexisting() {
    let tmp = std::env::temp_dir();

    // Create path with .. that resolves to temp dir + suffix
    let with_dotdot = tmp.join("fake_dir").join("..").join("result_file.txt");

    let result = soft_canonicalize(with_dotdot).expect("should canonicalize");

    // The .. should be resolved, so we should NOT see "fake_dir" in the result
    let result_str = result.to_string_lossy();
    assert!(
        !result_str.contains("fake_dir"),
        "Path should have .. resolved: {}",
        result_str
    );
    assert!(
        result_str.contains("result_file.txt"),
        "Should preserve target filename: {}",
        result_str
    );
}

// ============================================================================
// Feature Detection Tests (Compile-Time Verification)
// ============================================================================

/// This test verifies the feature flags are properly set at compile time.
#[test]
fn test_feature_detection() {
    // These are compile-time checks
    #[cfg(feature = "proc-canonicalize")]
    {
        println!("proc-canonicalize feature: ENABLED");
    }
    #[cfg(not(feature = "proc-canonicalize"))]
    {
        println!("proc-canonicalize feature: DISABLED");
    }

    #[cfg(feature = "dunce")]
    {
        println!("dunce feature: ENABLED");
    }
    #[cfg(not(feature = "dunce"))]
    {
        println!("dunce feature: DISABLED");
    }

    #[cfg(feature = "anchored")]
    {
        println!("anchored feature: ENABLED");
    }
    #[cfg(not(feature = "anchored"))]
    {
        println!("anchored feature: DISABLED");
    }

    // This test always passes - it's for visibility into feature state
}

// ============================================================================
// Edge Cases
// ============================================================================

/// Test empty path handling.
#[test]
fn test_empty_path() {
    let result = soft_canonicalize("");

    // Empty path should error
    assert!(result.is_err(), "Empty path should return error");
}

/// Test current directory (.)
#[test]
fn test_current_dir() {
    let result = soft_canonicalize(".").expect("should canonicalize current dir");

    // Should resolve to absolute path
    assert!(
        result.is_absolute(),
        "Current dir should resolve to absolute"
    );

    // Should match std behavior
    let std_result = std::fs::canonicalize(".").expect("std should work on current dir");

    #[cfg(all(windows, feature = "dunce"))]
    {
        let our_str = result.to_string_lossy();
        let std_str = std_result.to_string_lossy();
        assert_eq!(our_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
    }

    #[cfg(not(all(windows, feature = "dunce")))]
    {
        assert_eq!(result, std_result);
    }
}

/// Test parent directory (..)
#[test]
fn test_parent_dir() {
    let result = soft_canonicalize("..").expect("should canonicalize parent dir");

    // Should resolve to absolute path
    assert!(
        result.is_absolute(),
        "Parent dir should resolve to absolute"
    );
}
