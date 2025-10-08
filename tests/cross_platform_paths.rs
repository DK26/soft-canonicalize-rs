//! Cross-platform path handling tests
//!
//! These tests verify that the crate handles Windows-style paths gracefully on Unix
//! and vice versa. This is important for tools that process paths from different
//! platforms (e.g., build systems, package managers, cross-compilation tools).
//!
//! ## Test Coverage
//!
//! ### Unix platform tests:
//! - Windows UNC paths (`\\?\C:\...`) - should fail gracefully, not panic
//! - Windows drive letters (`C:\...`) - treated as relative paths
//! - Backslashes - NOT treated as path separators (literal characters)
//! - Unix absolute paths (`/tmp`) - work normally
//!
//! ### Windows platform tests:
//! - UNC network paths (`\\server\share`) - handled correctly or fail gracefully
//! - Extended-length UNC paths (`\\?\C:\...`) - handled with/without dunce feature
//! - Device namespace paths (`\\.\COM1`) - don't panic
//! - Drive-relative paths - resolve to absolute paths
//! - Mixed separators (`/` and `\`) - both work as separators
//! - Unix-style forward slashes - work as path separators
//!
//! ### Cross-platform tests:
//! - Relative paths - work consistently
//! - Dot-dot (`..`) resolution - works consistently

use soft_canonicalize::soft_canonicalize;

/// Test that Windows-style UNC paths are handled gracefully on Unix
#[test]
#[cfg(unix)]
fn unix_handles_windows_unc_paths_gracefully() {
    // Windows UNC paths should be treated as regular paths on Unix (not special)
    // They won't resolve to anything real, but shouldn't cause panics or errors
    // beyond normal NotFound errors

    let unc_path = r"\\?\C:\Windows\System32";
    let result = soft_canonicalize(unc_path);

    // Should either fail with NotFound (most likely) or succeed by treating it
    // as a relative path (depending on filesystem state)
    match result {
        Err(e) => {
            // Expected: NotFound or InvalidInput
            assert!(
                e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::InvalidInput,
                "UNC path on Unix should fail gracefully, got: {:?}",
                e.kind()
            );
        }
        Ok(path) => {
            // If it succeeds, it should have treated it as a relative path
            // and resolved it relative to CWD (very unlikely but valid)
            assert!(path.is_absolute(), "Result should be absolute");
        }
    }
}

/// Test that Windows drive letters are handled gracefully on Unix
#[test]
#[cfg(unix)]
fn unix_handles_windows_drive_letters_gracefully() {
    // Windows absolute paths like C:\path should be treated as relative paths on Unix
    // (C: is just a directory/file name, \ is a path separator)

    let drive_path = r"C:\Users\test";
    let result = soft_canonicalize(drive_path);

    // Should either fail with NotFound or succeed by treating C: as a directory name
    match result {
        Err(e) => {
            assert!(
                e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::InvalidInput,
                "Drive letter path on Unix should fail gracefully, got: {:?}",
                e.kind()
            );
        }
        Ok(_path) => {
            // If it succeeds, Unix treated C: as a relative path component
            // This is valid behavior
        }
    }
}

/// Test that Windows backslash paths are treated as forward slashes on Unix
#[test]
#[cfg(unix)]
fn unix_treats_backslashes_as_path_separators() {
    use std::fs;
    use tempfile::TempDir;

    let tmpdir = TempDir::new().unwrap();
    let dir = tmpdir.path().join("testdir");
    fs::create_dir(&dir).unwrap();

    // Create a file using Unix separators
    let file = dir.join("testfile.txt");
    fs::write(&file, b"test").unwrap();

    // Try to access it using Windows-style backslashes (treated as literals on Unix)
    // On Unix, backslashes are NOT path separators, so this creates a wrong path
    let windows_style = format!(r"{}\\testdir\\testfile.txt", tmpdir.path().display());
    let result = soft_canonicalize(windows_style).unwrap();

    // soft_canonicalize succeeds (it handles non-existing paths), but the result
    // should NOT match the actual file because backslashes aren't separators on Unix
    let expected_file = soft_canonicalize(&file).unwrap();
    assert_ne!(
        result, expected_file,
        "Backslashes should not be treated as separators on Unix"
    );
}

/// Test that Unix absolute paths work correctly on Unix
#[test]
#[cfg(unix)]
fn unix_handles_unix_absolute_paths() {
    // Unix absolute paths should work normally
    let result = soft_canonicalize("/tmp");

    // /tmp usually exists, but if not, we should get NotFound
    match result {
        Ok(path) => {
            // On macOS, /tmp is a symlink to /private/tmp, so we need to compare with std::fs::canonicalize
            let expected = std::fs::canonicalize("/tmp").unwrap();
            assert_eq!(
                path, expected,
                "Should match std::fs::canonicalize for existing paths"
            );
        }
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        }
    }
}

/// Test that Unix paths with forward slashes work on Windows
#[test]
#[cfg(windows)]
fn windows_handles_unix_style_paths() {
    use tempfile::TempDir;

    let tmpdir = TempDir::new().unwrap();

    // Create a directory using Windows API
    let subdir = tmpdir.path().join("subdir");
    std::fs::create_dir(subdir).unwrap();

    // Access it using Unix-style forward slashes
    // Windows treats / as a path separator (compatible with \)
    let unix_style = format!("{}/subdir", tmpdir.path().display());
    let result = soft_canonicalize(unix_style).unwrap();

    // Should succeed and resolve to the same directory
    assert!(result.ends_with("subdir"));
}

/// Test that relative paths work consistently across platforms
#[test]
fn relative_paths_are_cross_platform() {
    use std::fs;
    use tempfile::TempDir;

    let tmpdir = TempDir::new().unwrap();
    let subdir = tmpdir.path().join("sub");
    fs::create_dir(subdir).unwrap();

    // Save current directory and change to tmpdir
    let orig_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmpdir.path()).unwrap();

    // Relative paths should work the same on both platforms
    let result = soft_canonicalize("sub").unwrap();
    assert!(result.is_absolute());
    assert!(result.ends_with("sub"));

    // Restore original directory
    std::env::set_current_dir(orig_dir).unwrap();
}

/// Test that dots in paths work consistently across platforms
#[test]
fn dots_in_paths_are_cross_platform() {
    use std::fs;
    use tempfile::TempDir;

    let tmpdir = TempDir::new().unwrap();
    let a = tmpdir.path().join("a");
    let b = a.join("b");
    fs::create_dir_all(&b).unwrap();

    // Path with .. should work on both platforms
    let with_dotdot = b.join("..").join("sibling");
    let result = soft_canonicalize(with_dotdot).unwrap();

    // Should resolve to tmpdir/a/sibling (canonicalized)
    let expected = soft_canonicalize(&a).unwrap().join("sibling");
    assert_eq!(result, expected);
}

/// Test that Windows UNC network paths are handled correctly
#[test]
#[cfg(windows)]
fn windows_handles_unc_network_paths() {
    // UNC network paths like \\server\share should be recognized
    // They won't resolve unless the network share exists, but shouldn't panic

    // Use a definitely nonexistent server name (RFC 2606 reserved domain)
    let unc_network = r"\\nonexistent.invalid\share\file.txt";
    let result = soft_canonicalize(unc_network);

    // Should fail with NotFound (server doesn't exist) but not panic
    // Or might succeed if treated as a relative path (unlikely but valid)
    match result {
        Err(e) => {
            // Expected: NotFound, InvalidInput, or other network-related error
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::InvalidInput
                        | std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::Other
                ),
                "UNC network path should fail gracefully, got: {:?}",
                e.kind()
            );
        }
        Ok(path) => {
            // If it succeeded, it must have treated it as a relative path
            // (very unlikely on Windows, but theoretically possible)
            assert!(
                path.is_absolute(),
                "If UNC path resolves, result should be absolute"
            );
        }
    }
}

/// Test that Windows extended-length UNC paths are handled
#[test]
#[cfg(windows)]
fn windows_handles_extended_length_unc_paths() {
    use tempfile::TempDir;

    let tmpdir = TempDir::new().unwrap();
    let file = tmpdir.path().join("test.txt");
    std::fs::write(&file, b"test").unwrap();

    // Get the UNC version of the path
    let unc_path = std::fs::canonicalize(&file).unwrap();

    // Should start with \\?\ on Windows
    let unc_str = unc_path.to_string_lossy();
    assert!(
        unc_str.starts_with(r"\\?\"),
        "std::fs::canonicalize should return UNC path"
    );

    // Our function should handle UNC paths correctly
    let result = soft_canonicalize(&unc_path).unwrap();

    // Without dunce: should match std::fs::canonicalize exactly
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, unc_path, "Should handle UNC paths correctly");
    }

    // With dunce: should simplify the path
    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        assert!(
            !result_str.starts_with(r"\\?\"),
            "dunce should simplify UNC path"
        );
        assert_eq!(
            result_str.as_ref(),
            unc_str.trim_start_matches(r"\\?\"),
            "Should be simplified version of UNC path"
        );
    }
}

/// Test that Windows device namespace paths are handled
#[test]
#[cfg(windows)]
fn windows_handles_device_namespace_paths() {
    // Device namespace paths like \\.\COM1 or \\?\Volume{GUID}
    // Should not panic, even if they don't resolve

    let device_path = r"\\.\COM999"; // Unlikely to exist
    let result = soft_canonicalize(device_path);

    // Should fail gracefully or succeed (depending on device availability)
    if let Err(e) = result {
        // Expected: various error kinds are acceptable
        assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::Other
            ),
            "Device path should fail gracefully, got: {:?}",
            e.kind()
        );
    }
}

/// Test that Windows drive-relative paths work correctly
#[test]
#[cfg(windows)]
fn windows_handles_drive_relative_paths() {
    use std::fs;
    use tempfile::TempDir;

    let tmpdir = TempDir::new().unwrap();
    let file = tmpdir.path().join("test.txt");
    fs::write(&file, b"test").unwrap();

    // Get the canonical path
    let canonical = soft_canonicalize(&file).unwrap();

    // Should be absolute and start with a drive letter (or UNC prefix)
    assert!(canonical.is_absolute());
    let path_str = canonical.to_string_lossy();

    #[cfg(not(feature = "dunce"))]
    {
        assert!(
            path_str.starts_with(r"\\?\"),
            "Without dunce, should return UNC format"
        );
    }

    #[cfg(feature = "dunce")]
    {
        assert!(
            path_str.chars().nth(1) == Some(':'),
            "With dunce, should return simplified C:\\ format"
        );
    }
}

/// Test that Windows handles mixed separators (forward and back slashes)
#[test]
#[cfg(windows)]
fn windows_handles_mixed_separators() {
    use std::fs;
    use tempfile::TempDir;

    let tmpdir = TempDir::new().unwrap();
    let subdir = tmpdir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    let file = subdir.join("test.txt");
    fs::write(&file, b"test").unwrap();

    // Create path with mixed separators (both / and \)
    let mixed = format!("{}/subdir\\test.txt", tmpdir.path().display());
    let result = soft_canonicalize(mixed).unwrap();

    // Should resolve correctly despite mixed separators
    let expected = soft_canonicalize(&file).unwrap();
    assert_eq!(result, expected, "Mixed separators should be handled");
}
