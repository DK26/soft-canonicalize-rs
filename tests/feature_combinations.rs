//! Comprehensive tests for feature combination behaviors.
//!
//! This test suite validates the behavior of all feature combinations:
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
//! cargo test --test feature_combinations --features anchored
//! cargo test --test feature_combinations --features anchored,dunce
//! cargo test --test feature_combinations --no-default-features --features anchored
//! cargo test --test feature_combinations --no-default-features --features anchored,dunce
//! ```

use soft_canonicalize::soft_canonicalize;

// PathBuf is used in platform-specific modules (Windows, Linux) but not macOS
#[cfg(any(windows, target_os = "linux"))]
use std::path::PathBuf;

#[cfg(feature = "anchored")]
use soft_canonicalize::anchored_canonicalize;

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
// Windows-Specific Tests
// ============================================================================

#[cfg(windows)]
mod windows_tests {
    use super::*;

    /// Test Windows extended-length path output format.
    #[test]
    fn test_windows_path_format() {
        let tmp = std::env::temp_dir();
        let result = soft_canonicalize(tmp).expect("should canonicalize temp dir");
        let result_str = result.to_string_lossy();

        #[cfg(feature = "dunce")]
        {
            // With dunce: simplified format (no \\?\)
            assert!(
                !result_str.starts_with(r"\\?\"),
                "With dunce feature, should NOT have \\\\?\\ prefix: {}",
                result_str
            );
            // Should start with drive letter
            assert!(
                result_str.chars().nth(1) == Some(':'),
                "Should start with drive letter: {}",
                result_str
            );
        }

        #[cfg(not(feature = "dunce"))]
        {
            // Without dunce: extended-length UNC format
            assert!(
                result_str.starts_with(r"\\?\"),
                "Without dunce feature, should have \\\\?\\ prefix: {}",
                result_str
            );
        }
    }

    /// Test that drive-relative paths are handled correctly.
    #[test]
    fn test_drive_relative_path() {
        // C:filename (relative to current directory on C:)
        // This is different from C:\filename (absolute from root)
        let drive_relative = PathBuf::from("C:test_file.txt");

        // This may or may not succeed depending on whether C: is accessible
        // The key is it shouldn't panic
        let result = soft_canonicalize(drive_relative);

        if let Ok(path) = result {
            let path_str = path.to_string_lossy();

            // Result should be absolute (has backslash after colon)
            #[cfg(feature = "dunce")]
            {
                // With dunce: C:\...
                assert!(
                    path_str.len() > 2 && &path_str[2..3] == "\\",
                    "Drive-relative should resolve to absolute: {}",
                    path_str
                );
            }
            #[cfg(not(feature = "dunce"))]
            {
                // Without dunce: \\?\C:\...
                assert!(
                    path_str.starts_with(r"\\?\") && path_str.len() > 6 && &path_str[6..7] == "\\",
                    "Drive-relative should resolve to absolute UNC: {}",
                    path_str
                );
            }
        }
    }

    /// Test non-existing path with UNC input.
    #[test]
    fn test_unc_input_nonexisting() {
        let unc_nonexisting = PathBuf::from(r"\\?\C:\definitely_not_real_path_xyz");

        let result = soft_canonicalize(unc_nonexisting);
        assert!(result.is_ok(), "Should handle UNC non-existing path");

        let path = result.unwrap();
        let path_str = path.to_string_lossy();

        #[cfg(feature = "dunce")]
        {
            // dunce should simplify if safe
            // Non-existing paths might remain UNC or be simplified
            assert!(
                path_str.contains("definitely_not_real_path_xyz"),
                "Should preserve path component: {}",
                path_str
            );
        }

        #[cfg(not(feature = "dunce"))]
        {
            // Without dunce, should remain UNC
            assert!(
                path_str.starts_with(r"\\?\"),
                "Without dunce, should keep UNC prefix: {}",
                path_str
            );
        }
    }
}

// ============================================================================
// Linux-Specific Tests
// ============================================================================

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::*;
    use std::process;

    /// Test /proc/self/root handling.
    ///
    /// With proc-canonicalize feature (default): preserves /proc/self/root
    /// Without proc-canonicalize: resolves to / (std behavior)
    #[test]
    fn test_proc_self_root_behavior() {
        let proc_self_root = PathBuf::from("/proc/self/root");

        if !proc_self_root.exists() {
            println!("Skipping: /proc/self/root doesn't exist");
            return;
        }

        let result = soft_canonicalize(&proc_self_root).expect("should canonicalize");

        #[cfg(feature = "proc-canonicalize")]
        {
            // With proc-canonicalize (default): preserves namespace boundary
            assert_eq!(
                result,
                PathBuf::from("/proc/self/root"),
                "With proc-canonicalize, should preserve /proc/self/root"
            );
        }

        #[cfg(not(feature = "proc-canonicalize"))]
        {
            // Without proc-canonicalize: follows std behavior (resolves to /)
            assert_eq!(
                result,
                PathBuf::from("/"),
                "Without proc-canonicalize, should resolve to / (std behavior)"
            );
        }
    }

    /// Test /proc/PID/root handling with actual PID.
    #[test]
    fn test_proc_pid_root_behavior() {
        let pid = process::id();
        let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

        if !proc_pid_root.exists() {
            println!("Skipping: /proc/{}/root doesn't exist", pid);
            return;
        }

        let result = soft_canonicalize(&proc_pid_root).expect("should canonicalize");

        #[cfg(feature = "proc-canonicalize")]
        {
            // With proc-canonicalize (default): preserves namespace boundary
            assert_eq!(
                result, proc_pid_root,
                "With proc-canonicalize, should preserve /proc/PID/root"
            );
        }

        #[cfg(not(feature = "proc-canonicalize"))]
        {
            // Without proc-canonicalize: follows std behavior (resolves to /)
            assert_eq!(
                result,
                PathBuf::from("/"),
                "Without proc-canonicalize, should resolve to / (std behavior)"
            );
        }
    }

    /// Test /proc/PID/root handling with a non-existing suffix.
    #[test]
    fn test_proc_pid_root_nonexisting_suffix_behavior() {
        let pid = process::id();
        let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

        if !proc_pid_root.exists() {
            println!("Skipping: /proc/{}/root doesn't exist", pid);
            return;
        }

        let planned = proc_pid_root.join("planned_dir").join("future_config.toml");
        let result = soft_canonicalize(&planned).expect("should canonicalize planned path");

        #[cfg(feature = "proc-canonicalize")]
        {
            // With proc-canonicalize (default): preserve namespace boundary for non-existing suffixes
            assert_eq!(
                result, planned,
                "With proc-canonicalize, should keep /proc/PID/root prefix for non-existing suffixes"
            );
        }

        #[cfg(not(feature = "proc-canonicalize"))]
        {
            // Without proc-canonicalize: behaves like std, resolving /proc/PID/root to /
            let expected = PathBuf::from("/")
                .join("planned_dir")
                .join("future_config.toml");
            assert_eq!(
                result, expected,
                "Without proc-canonicalize, should resolve to / (std behavior) before appending suffix"
            );
        }
    }

    /// Test /proc/PID/cwd handling.
    #[test]
    fn test_proc_pid_cwd_behavior() {
        let pid = process::id();
        let proc_pid_cwd = PathBuf::from(format!("/proc/{}/cwd", pid));

        if !proc_pid_cwd.exists() {
            println!("Skipping: /proc/{}/cwd doesn't exist", pid);
            return;
        }

        let result = soft_canonicalize(&proc_pid_cwd).expect("should canonicalize");

        #[cfg(feature = "proc-canonicalize")]
        {
            // With proc-canonicalize (default): preserves namespace boundary
            assert_eq!(
                result, proc_pid_cwd,
                "With proc-canonicalize, should preserve /proc/PID/cwd"
            );
        }

        #[cfg(not(feature = "proc-canonicalize"))]
        {
            // Without proc-canonicalize: follows symlink to actual cwd
            let expected_cwd = std::env::current_dir().expect("should get cwd");
            let expected_canonical =
                std::fs::canonicalize(&expected_cwd).expect("should canonicalize cwd");
            assert_eq!(
                result, expected_canonical,
                "Without proc-canonicalize, should resolve to actual cwd"
            );
        }
    }

    /// Test /proc/self/cwd with a non-existing suffix.
    #[test]
    fn test_proc_self_cwd_nonexisting_suffix_behavior() {
        let proc_self_cwd = PathBuf::from("/proc/self/cwd");

        if !proc_self_cwd.exists() {
            println!("Skipping: /proc/self/cwd doesn't exist");
            return;
        }

        let planned = proc_self_cwd.join("planned_dir").join("future_config.toml");
        let result = soft_canonicalize(&planned).expect("should canonicalize planned path");

        // Note: /proc/self resolves to /proc/{pid}, so the result will be /proc/{pid}/cwd/...
        let pid = process::id();
        let _expected_with_proc = PathBuf::from(format!("/proc/{}/cwd", pid))
            .join("planned_dir")
            .join("future_config.toml");

        #[cfg(feature = "proc-canonicalize")]
        {
            // With proc-canonicalize (default): keep the /proc/PID/cwd boundary intact
            // (the /proc/self symlink resolves to /proc/{pid})
            assert_eq!(
                result, _expected_with_proc,
                "With proc-canonicalize, should preserve /proc/PID/cwd prefix for non-existing suffixes"
            );
        }

        #[cfg(not(feature = "proc-canonicalize"))]
        {
            // Without proc-canonicalize: resolve cwd normally then append the suffix
            let expected_cwd =
                std::fs::canonicalize(std::env::current_dir().expect("cwd should exist"))
                    .expect("canonicalize cwd");
            assert_eq!(
                result,
                expected_cwd.join("planned_dir").join("future_config.toml"),
                "Without proc-canonicalize, should resolve /proc/self/cwd to the real cwd"
            );
        }
    }

    /// Test /proc/thread-self/root handling.
    #[test]
    fn test_proc_thread_self_root_behavior() {
        let proc_thread_self_root = PathBuf::from("/proc/thread-self/root");

        if !proc_thread_self_root.exists() {
            println!("Skipping: /proc/thread-self/root doesn't exist");
            return;
        }

        let result = soft_canonicalize(&proc_thread_self_root).expect("should canonicalize");

        #[cfg(feature = "proc-canonicalize")]
        {
            // With proc-canonicalize (default): preserves namespace boundary
            assert_eq!(
                result,
                PathBuf::from("/proc/thread-self/root"),
                "With proc-canonicalize, should preserve /proc/thread-self/root"
            );
        }

        #[cfg(not(feature = "proc-canonicalize"))]
        {
            // Without proc-canonicalize: follows std behavior (resolves to /)
            assert_eq!(
                result,
                PathBuf::from("/"),
                "Without proc-canonicalize, should resolve to / (std behavior)"
            );
        }
    }
}

// ============================================================================
// Anchored Canonicalize Tests
// ============================================================================

#[cfg(feature = "anchored")]
mod anchored_tests {
    use super::*;

    /// Test basic anchored canonicalization.
    #[test]
    fn test_anchored_basic() {
        let anchor = std::env::temp_dir();
        let result =
            anchored_canonicalize(&anchor, "subdir/file.txt").expect("should canonicalize");

        assert!(
            result.starts_with(soft_canonicalize(&anchor).unwrap()),
            "Result should be within anchor"
        );
        assert!(
            result.to_string_lossy().contains("file.txt"),
            "Should preserve filename"
        );
    }

    /// Test that escape attempts are clamped.
    #[test]
    fn test_anchored_escape_clamped() {
        let anchor = std::env::temp_dir();
        let escape_attempt = "../../../../../../etc/passwd";

        let result = anchored_canonicalize(&anchor, escape_attempt).expect("should canonicalize");

        // Result should still be within the anchor
        let anchor_canonical = soft_canonicalize(&anchor).unwrap();
        assert!(
            result.starts_with(anchor_canonical),
            "Escape attempt should be clamped to anchor"
        );
    }

    /// Test anchored with non-existing path.
    #[test]
    fn test_anchored_nonexisting() {
        let anchor = std::env::temp_dir();
        let non_existing = "this/path/does/not/exist/file.txt";

        let result = anchored_canonicalize(anchor, non_existing).expect("should canonicalize");

        // Should succeed even though path doesn't exist
        assert!(
            result.to_string_lossy().contains("file.txt"),
            "Should preserve non-existing filename"
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_anchored_windows_format() {
        let anchor = std::env::temp_dir();
        let result = anchored_canonicalize(anchor, "test.txt").expect("should canonicalize");
        let result_str = result.to_string_lossy();

        #[cfg(feature = "dunce")]
        {
            assert!(
                !result_str.starts_with(r"\\?\"),
                "With dunce, anchored paths should be simplified: {}",
                result_str
            );
        }

        #[cfg(not(feature = "dunce"))]
        {
            assert!(
                result_str.starts_with(r"\\?\"),
                "Without dunce, anchored paths should have UNC prefix: {}",
                result_str
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_anchored_proc_root_boundary() {
        use std::process;

        let pid = process::id();
        let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

        if !proc_pid_root.exists() {
            println!("Skipping: /proc/{}/root doesn't exist", pid);
            return;
        }

        let escape_attempt = "../../../etc/passwd";
        let result = anchored_canonicalize(&proc_pid_root, escape_attempt);

        match result {
            #[cfg(feature = "proc-canonicalize")]
            Ok(path) => {
                // With proc-canonicalize: should preserve /proc/PID/root prefix
                assert!(
                    path.starts_with(&proc_pid_root),
                    "With proc-canonicalize, anchored should preserve /proc/PID/root: {:?}",
                    path
                );
            }
            #[cfg(not(feature = "proc-canonicalize"))]
            Ok(_) => {
                // Without proc-canonicalize: anchor resolves differently, just verify it succeeds
            }
            Err(e) => {
                // Error is also acceptable depending on anchor semantics
                println!("anchored_canonicalize returned error: {}", e);
            }
        }
    }
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
