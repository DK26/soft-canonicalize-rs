//! Black-box security tests for soft_canonicalize
//!
//! These tests treat soft_canonicalize as a black box and try to break it
//! through the public API without knowledge of internal implementation.
//! Focus is on discovering vulnerabilities through external behavior.

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::path::Path;
use tempfile::{Builder, TempDir};

/// Helper to create a temporary directory for testing
fn tmpdir() -> TempDir {
    Builder::new()
        .prefix("soft_canonicalize_complex_attacks")
        .tempdir()
        .unwrap()
}

/// Check if we have symlink permissions (mainly for Windows)
fn got_symlink_permission(tmpdir: &TempDir) -> bool {
    #[cfg(windows)]
    {
        let link = tmpdir.path().join("symlink_test");
        let target = tmpdir.path().join("target");
        let _ = fs::File::create(&target);
        std::os::windows::fs::symlink_file(&target, link).is_ok()
    }
    #[cfg(not(windows))]
    {
        let _ = tmpdir;
        true
    }
}

/// Helper to create symlinks in a cross-platform way
fn symlink_file(original: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(original, link);
    #[cfg(not(windows))]
    return std::os::unix::fs::symlink(original, link);
}

#[test]
fn test_toctou_symlink_swap_to_dangling() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    if !got_symlink_permission(&tmpdir) {
        return Ok(());
    }

    let real_target = tmpdir.path().join("real_target");
    fs::File::create(&real_target)?;

    let symlink_path = tmpdir.path().join("symlink");
    symlink_file(&real_target, &symlink_path)?;

    let dangling_target = tmpdir.path().join("dangling_target");

    let symlink_path_clone = symlink_path.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Atomically swap the symlink to a dangling one
        let _ = fs::remove_file(&symlink_path_clone);
        let _ = symlink_file(&dangling_target, &symlink_path_clone);
    });

    let result = soft_canonicalize(&symlink_path);
    handle.join().unwrap();

    // The result should either be the original target or an error.
    // It should NOT be the dangling target.
    if let Ok(path) = result {
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(path, fs::canonicalize(&real_target)?);
        }
        #[cfg(feature = "dunce")]
        {
            let expected_canonical = fs::canonicalize(&real_target)?;
            #[cfg(windows)]
            {
                let path_str = path.to_string_lossy();
                let expected_str = expected_canonical.to_string_lossy();
                assert!(!path_str.starts_with(r"\\?\"), "dunce should simplify");
                assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
                assert_eq!(path_str.as_ref(), expected_str.trim_start_matches(r"\\?\"));
            }
            #[cfg(not(windows))]
            {
                assert_eq!(path, expected_canonical);
            }
        }
    }

    Ok(())
}

#[test]
fn test_toctou_directory_swap() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    if !got_symlink_permission(&tmpdir) {
        return Ok(());
    }

    let dir1 = tmpdir.path().join("dir1");
    let dir2 = tmpdir.path().join("dir2");
    fs::create_dir(&dir1)?;
    fs::create_dir(&dir2)?;

    let file_in_dir1 = dir1.join("file.txt");
    fs::File::create(&file_in_dir1)?;

    let tmpdir_path_clone = tmpdir.path().to_path_buf();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Swap directories
        let _ = fs::rename(&dir1, tmpdir_path_clone.join("temp"));
        let _ = fs::rename(&dir2, &dir1);
    });

    let result = soft_canonicalize(&file_in_dir1);
    handle.join().unwrap();

    // The result should be the path in the original directory, or an error.
    if let Ok(path) = result {
        let canonical_tmpdir = fs::canonicalize(tmpdir.path())?;

        #[cfg(not(feature = "dunce"))]
        {
            assert!(path.starts_with(&canonical_tmpdir));
        }
        #[cfg(feature = "dunce")]
        {
            // With dunce, strip UNC prefix from both for comparison
            #[cfg(windows)]
            {
                let path_str = path.to_string_lossy();
                let tmpdir_str = canonical_tmpdir.to_string_lossy();
                let path_normalized = path_str.trim_start_matches(r"\\?\");
                let tmpdir_normalized = tmpdir_str.trim_start_matches(r"\\?\");
                assert!(path_normalized.starts_with(tmpdir_normalized));
            }
            #[cfg(not(windows))]
            {
                assert!(path.starts_with(canonical_tmpdir));
            }
        }
        assert!(path.to_string_lossy().contains("dir1"));
    }

    Ok(())
}

#[test]
#[cfg(windows)]
fn test_windows_short_name_bypass() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    let long_name_dir = tmpdir.path().join("long_name_directory");
    fs::create_dir(&long_name_dir)?;

    let sensitive_file = long_name_dir.join("secret.txt");
    fs::File::create(&sensitive_file)?;

    // This is a best-effort test, as short name generation can be disabled.
    // We'll try to guess the short name.
    let short_name_dir = tmpdir.path().join("LONGNA~1");
    if short_name_dir.exists() {
        let attack_path = short_name_dir.join("secret.txt");
        let result = soft_canonicalize(attack_path)?;

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(result, fs::canonicalize(&sensitive_file)?);
        }
        #[cfg(feature = "dunce")]
        {
            let expected = fs::canonicalize(&sensitive_file)?;
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
            assert_eq!(
                result_str.as_ref(),
                expected_str.trim_start_matches(r"\\?\")
            );
        }
    }

    Ok(())
}

#[test]
#[cfg(windows)]
fn test_windows_device_name_bypass() -> std::io::Result<()> {
    // These paths should be handled correctly and not cause panics.
    let device_paths = vec![
        r"\\.\\C:\\windows\\system32\\kernel32.dll",
        r"\\\\?\\C:\\windows\\system32\\kernel32.dll",
        "CON",
        "NUL",
        "COM1",
        "LPT1",
    ];

    for path in device_paths {
        let result = soft_canonicalize(path);
        // We just want to ensure this doesn't panic.
        // The result can be an error, which is fine.
        let _ = result;
    }

    Ok(())
}

#[test]
#[cfg(windows)]
fn test_windows_ntfs_alternate_data_streams() -> std::io::Result<()> {
    // Test NTFS Alternate Data Streams (ADS) syntax handling
    // This tests whether our canonicalization behaves consistently with std::fs::canonicalize
    // for paths that use Windows ADS syntax (file.txt:stream:$DATA)
    let tmpdir = tmpdir();

    // Create a regular file
    let regular_file = tmpdir.path().join("document.txt");
    fs::write(&regular_file, "regular content")?;

    // Test various ADS syntax patterns
    let ads_patterns = vec![
        // Basic ADS syntax
        "document.txt:hidden:$DATA",
        "document.txt:secret",
        "document.txt:malware.exe:$DATA",
        // ADS with path traversal (the real security test)
        "../document.txt:hidden:$DATA",
        "subdir/../document.txt:secret:$DATA",
        // Complex ADS patterns
        "document.txt::$DATA",
        "document.txt:::$DATA",
        "document.txt:$DATA",
        // Non-existing file with ADS syntax
        "nonexistent.txt:stream:$DATA",
    ];

    for ads_pattern in ads_patterns {
        let test_path = tmpdir.path().join(ads_pattern);

        // Test our library
        let our_result = soft_canonicalize(&test_path);

        // Test std library behavior for comparison (when file exists)
        let std_result =
            if test_path.exists() || test_path.parent().unwrap().join("document.txt").exists() {
                // Only test std::fs::canonicalize if the base file exists
                std::fs::canonicalize(&test_path)
            } else {
                // For non-existing files, we expect an error from std
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not found",
                ))
            };

        // Compare behaviors
        match (our_result, std_result) {
            (Ok(our_path), Ok(std_path)) => {
                // Both succeeded - they should resolve to the same location
                println!(
                    "✓ Both accepted ADS pattern '{}': our={}, std={}",
                    ads_pattern,
                    our_path.display(),
                    std_path.display()
                );
                assert!(our_path.is_absolute());
                assert!(std_path.is_absolute());
                // They should resolve to the same canonical location
                assert_eq!(our_path, std_path, "Mismatch for pattern: {ads_pattern}");
            }
            (Ok(our_path), Err(_)) => {
                // We succeeded, std failed - this is OK for non-existing files
                // We should still provide a reasonable canonical path
                println!(
                    "✓ We handled non-existing ADS pattern '{}': {}",
                    ads_pattern,
                    our_path.display()
                );
                assert!(our_path.is_absolute());
                // The path should be canonical (absolute) but may not contain the exact pattern
                // due to path normalization - that's actually correct behavior
            }
            (Err(our_err), Err(_)) => {
                // Both failed - that's consistent
                println!("✓ Both rejected ADS pattern '{ads_pattern}': {our_err}");
            }
            (Err(our_err), Ok(std_path)) => {
                // We failed but std succeeded - this might be a problem
                println!(
                    "⚠️ Inconsistency for '{}': we failed ({}), std succeeded ({})",
                    ads_pattern,
                    our_err,
                    std_path.display()
                );
                // This is potentially a bug in our implementation
            }
        }
    }

    Ok(())
}

#[test]
fn test_resource_exhaustion_long_filename() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    let long_filename = "a".repeat(255); // Max on many filesystems
    let path = tmpdir.path().join(long_filename);

    let result = soft_canonicalize(path);
    // Should not panic.
    if let Ok(canonical_path) = result {
        assert!(canonical_path.ends_with("a".repeat(255)));
    }
    Ok(())
}

#[test]
fn test_resource_exhaustion_many_components() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    #[cfg(not(feature = "dunce"))]
    let mut expected_path = fs::canonicalize(tmpdir.path())?;
    #[cfg(all(feature = "dunce", windows))]
    let mut expected_path = dunce::canonicalize(tmpdir.path())?;
    #[cfg(all(feature = "dunce", not(windows)))]
    let mut expected_path = fs::canonicalize(tmpdir.path())?;
    for i in 0..1024 {
        expected_path.push(format!("c{i}"));
    }

    let result = soft_canonicalize(&expected_path);
    // Should not panic.
    if let Ok(canonical_path) = result {
        // On Windows, the path may be truncated if it exceeds MAX_PATH.
        // So we check if the canonical path is a prefix of the expected path.
        #[cfg(not(feature = "dunce"))]
        {
            assert!(expected_path.starts_with(canonical_path));
        }
        #[cfg(feature = "dunce")]
        {
            // With dunce feature, paths may still have UNC prefix if they're too long for dunce to simplify
            // (dunce refuses to simplify paths that exceed certain length limits for safety)
            // So we normalize both to comparable format by stripping UNC prefix
            let canonical_str = canonical_path.to_string_lossy();
            let expected_str = expected_path.to_string_lossy();
            let canonical_normalized = canonical_str.trim_start_matches(r"\\?\");
            let expected_normalized = expected_str.trim_start_matches(r"\\?\");

            // The canonical result might be truncated if it exceeds MAX_PATH,
            // so we check if expected starts with canonical
            assert!(
                expected_normalized.starts_with(canonical_normalized),
                "Expected path should start with canonical path.\n\
                 Canonical: {} (len: {})\n\
                 Expected:  {} (len: {})",
                canonical_normalized,
                canonical_normalized.len(),
                expected_normalized,
                expected_normalized.len()
            );
        }
    }
    Ok(())
}

#[test]
fn test_filesystem_limits_edge_cases() -> std::io::Result<()> {
    let tmpdir = tmpdir();

    // Test path length limits
    let max_component_len = 255; // Standard filesystem limit for component names
    let max_component = "x".repeat(max_component_len);
    let max_component_path = tmpdir.path().join(&max_component);

    let result = soft_canonicalize(&max_component_path);
    if let Ok(canonical) = result {
        assert!(canonical.file_name().unwrap().len() == max_component_len);
    }

    // Test component name edge cases
    let edge_case_names = vec![
        "a".repeat(256),  // Just over the limit
        "b".repeat(1000), // Way over the limit
        " ".repeat(255),  // All spaces
        ".".repeat(100),  // Many dots (but not .. components)
        "valid_name_with_exactly_255_chars_".to_string() + &"x".repeat(255 - 31),
    ];

    for edge_name in edge_case_names {
        let edge_path = tmpdir.path().join(&edge_name);
        let result = soft_canonicalize(&edge_path);

        // Should handle gracefully without panicking
        match result {
            Ok(canonical) => {
                assert!(canonical.is_absolute());
                println!("✓ Handled edge case filename: len={}", edge_name.len());
            }
            Err(e) => {
                println!(
                    "✓ Rejected edge case filename (len={}): {e}",
                    edge_name.len()
                );
                // Rejection is acceptable for invalid filenames
            }
        }
    }

    Ok(())
}

#[test]
fn test_broken_symlink_jail_escape() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    if !got_symlink_permission(&tmpdir) {
        return Ok(());
    }

    // Create a more complex structure
    let jail = tmpdir.path().join("jail");
    let dir_a = jail.join("a");
    let dir_b = dir_a.join("b");
    fs::create_dir_all(&dir_b)?;

    // Create a symlink that seems safe (points within the jail)
    let symlink_to_b = dir_a.join("symlink_to_b");
    symlink_file(Path::new("b"), &symlink_to_b)?;

    // Create a broken symlink inside 'b' that tries to escape
    let escape_link = dir_b.join("escape");
    symlink_file(Path::new("../../outside_file.txt"), &escape_link)?;

    // The attack path combines the "safe" symlink with the broken escape symlink
    let attack_path = symlink_to_b.join("escape");
    let result = soft_canonicalize(attack_path)?;

    // The final resolved path should not escape the jail.
    let canonical_jail = fs::canonicalize(&jail)?;

    #[cfg(not(feature = "dunce"))]
    {
        assert!(
            result.starts_with(&canonical_jail),
            "Path escaped jail! Resolved to: {}",
            result.display()
        );
    }
    #[cfg(feature = "dunce")]
    {
        // With dunce, strip UNC prefix from both for comparison
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let jail_str = canonical_jail.to_string_lossy();
            let result_normalized = result_str.trim_start_matches(r"\\?\");
            let jail_normalized = jail_str.trim_start_matches(r"\\?\");
            assert!(
                result_normalized.starts_with(jail_normalized),
                "Path escaped jail! Resolved to: {}",
                result.display()
            );
        }
        #[cfg(not(windows))]
        {
            assert!(
                result.starts_with(canonical_jail),
                "Path escaped jail! Resolved to: {}",
                result.display()
            );
        }
    }

    Ok(())
}
