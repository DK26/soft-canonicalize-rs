//! Tests verifying graceful fallback when `std::fs::canonicalize` fails.
//!
//! These tests address the issues documented in normpath's README where `std::fs::canonicalize`
//! fails on certain Windows filesystems:
//! - [rust-lang/rust#45067](https://github.com/rust-lang/rust/issues/45067) - Network drives
//! - [rust-lang/rust#48249](https://github.com/rust-lang/rust/issues/48249) - RAM disks (ImDisk)
//! - [rust-lang/rust#52440](https://github.com/rust-lang/rust/issues/52440) - Ext4 via Ext2Fsd
//! - [rust-lang/rust#55812](https://github.com/rust-lang/rust/issues/55812) - RAM disks (buffer error)
//! - [rust-lang/rust#58613](https://github.com/rust-lang/rust/issues/58613) - Docker containers
//! - [rust-lang/rust#59107](https://github.com/rust-lang/rust/issues/59107) - RAM disks
//! - [rust-lang/rust#74327](https://github.com/rust-lang/rust/issues/74327) - RAM disks (ImDisk)
//!
//! While we cannot directly test RAM disks or network drives in CI, we verify that:
//! 1. Our code structure handles `fs::canonicalize` failures gracefully
//! 2. Non-existing paths (which exercise the fallback logic) produce correct results
//! 3. The fallback path produces valid, normalized absolute paths

use soft_canonicalize::soft_canonicalize;

/// Verify that non-existing paths work correctly.
/// This exercises the same fallback code path that handles exotic filesystem failures.
#[test]
fn fallback_path_produces_valid_result_for_non_existing() {
    // This path doesn't exist, so fs::canonicalize will fail with NotFound
    // and we fall back to our prefix-discovery logic
    #[cfg(windows)]
    {
        let result = soft_canonicalize(r"C:\this\path\definitely\does\not\exist\file.txt");
        assert!(result.is_ok(), "Should succeed for non-existing path");
        let path = result.unwrap();
        assert!(path.is_absolute(), "Result should be absolute");
        // Should have proper Windows extended-length prefix (unless dunce simplifies it)
        #[cfg(not(feature = "dunce"))]
        {
            let path_str = path.to_string_lossy();
            assert!(
                path_str.starts_with(r"\\?\"),
                "Should have extended-length prefix: {}",
                path_str
            );
        }
    }

    #[cfg(unix)]
    {
        let result = soft_canonicalize("/this/path/definitely/does/not/exist/file.txt");
        assert!(result.is_ok(), "Should succeed for non-existing path");
        let path = result.unwrap();
        assert!(path.is_absolute(), "Result should be absolute");
    }
}

/// Verify that paths with `..` components are normalized in fallback.
/// This is important because exotic filesystem failures skip the fast-path canonicalization.
#[test]
fn fallback_normalizes_dotdot_components() {
    #[cfg(windows)]
    {
        let result = soft_canonicalize(r"C:\Users\test\..\test\subdir\..\file.txt");
        assert!(result.is_ok());
        let path = result.unwrap();
        let path_str = path.to_string_lossy();
        // Should not contain literal ".." after normalization
        assert!(
            !path_str.contains(r"\..\"),
            "Should normalize .. components: {}",
            path_str
        );
    }

    #[cfg(unix)]
    {
        let result = soft_canonicalize("/home/test/../test/subdir/../file.txt");
        assert!(result.is_ok());
        let path = result.unwrap();
        let path_str = path.to_string_lossy();
        assert!(
            !path_str.contains("/../"),
            "Should normalize .. components: {}",
            path_str
        );
    }
}

/// Verify that paths with `.` components are normalized in fallback.
#[test]
fn fallback_normalizes_dot_components() {
    #[cfg(windows)]
    {
        let result = soft_canonicalize(r"C:\Users\.\test\.\subdir\.\file.txt");
        assert!(result.is_ok());
        let path = result.unwrap();
        let path_str = path.to_string_lossy();
        assert!(
            !path_str.contains(r"\.\"),
            "Should normalize . components: {}",
            path_str
        );
    }

    #[cfg(unix)]
    {
        let result = soft_canonicalize("/home/./test/./subdir/./file.txt");
        assert!(result.is_ok());
        let path = result.unwrap();
        let path_str = path.to_string_lossy();
        assert!(
            !path_str.contains("/./"),
            "Should normalize . components: {}",
            path_str
        );
    }
}

/// Verify that deeply nested non-existing paths work correctly.
/// RAM disk issues often manifested with deeply nested paths.
#[test]
fn fallback_handles_deeply_nested_paths() {
    #[cfg(windows)]
    {
        let deep_path = r"C:\a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\q\r\s\t\u\v\w\x\y\z\file.txt";
        let result = soft_canonicalize(deep_path);
        assert!(result.is_ok(), "Should handle deeply nested paths");
        let path = result.unwrap();
        assert!(path.is_absolute());
    }

    #[cfg(unix)]
    {
        let deep_path = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/file.txt";
        let result = soft_canonicalize(deep_path);
        assert!(result.is_ok(), "Should handle deeply nested paths");
        let path = result.unwrap();
        assert!(path.is_absolute());
    }
}

/// Verify that relative paths are converted to absolute in fallback.
/// This is critical for the exotic filesystem case where CWD might be on a RAM disk.
#[test]
fn fallback_converts_relative_to_absolute() {
    let result = soft_canonicalize("relative/path/to/nonexistent/file.txt");
    assert!(
        result.is_ok(),
        "Should succeed for relative non-existing path"
    );
    let path = result.unwrap();
    assert!(
        path.is_absolute(),
        "Relative path should become absolute: {}",
        path.display()
    );
}

/// Verify that Unicode paths work correctly in fallback.
/// Some exotic filesystem issues were related to path encoding.
#[test]
fn fallback_handles_unicode_paths() {
    #[cfg(windows)]
    {
        let unicode_path = r"C:\Users\用户\文档\配置\file.txt";
        let result = soft_canonicalize(unicode_path);
        assert!(result.is_ok(), "Should handle Unicode paths");
        let path = result.unwrap();
        assert!(path.is_absolute());
        // Verify Unicode is preserved
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("用户"),
            "Should preserve Unicode: {}",
            path_str
        );
    }

    #[cfg(unix)]
    {
        let unicode_path = "/home/用户/文档/配置/file.txt";
        let result = soft_canonicalize(unicode_path);
        assert!(result.is_ok(), "Should handle Unicode paths");
        let path = result.unwrap();
        assert!(path.is_absolute());
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("用户"),
            "Should preserve Unicode: {}",
            path_str
        );
    }
}

/// Verify that paths with mixed separators work on Windows.
/// Exotic filesystem drivers sometimes have separator handling issues.
#[cfg(windows)]
#[test]
fn fallback_handles_mixed_separators_windows() {
    let mixed_path = r"C:\Users/test\subdir/file.txt";
    let result = soft_canonicalize(mixed_path);
    assert!(result.is_ok(), "Should handle mixed separators");
    let path = result.unwrap();
    assert!(path.is_absolute());
}

/// Verify that existing prefix + non-existing suffix works correctly.
/// This is the core use case that exercises our fallback logic.
#[test]
fn fallback_with_partial_existing_path() {
    // Use temp dir as existing prefix
    let temp = std::env::temp_dir();
    let path_with_suffix = temp
        .join("nonexistent_subdir")
        .join("also_nonexistent")
        .join("file.txt");

    let result = soft_canonicalize(path_with_suffix);
    assert!(result.is_ok(), "Should succeed with partial existing path");
    let resolved = result.unwrap();
    assert!(resolved.is_absolute());

    // The result should contain our non-existing suffix
    let resolved_str = resolved.to_string_lossy();
    assert!(
        resolved_str.contains("nonexistent_subdir"),
        "Should preserve non-existing suffix: {}",
        resolved_str
    );
}

/// Verify that the function doesn't panic on edge cases that might
/// cause issues with exotic filesystem drivers.
#[test]
fn fallback_no_panic_on_edge_cases() {
    // Single component
    let _ = soft_canonicalize("file.txt");

    // Just dots
    let _ = soft_canonicalize(".");
    let _ = soft_canonicalize("..");

    // Trailing separator
    #[cfg(windows)]
    {
        let _ = soft_canonicalize(r"C:\path\to\dir\");
    }
    #[cfg(unix)]
    {
        let _ = soft_canonicalize("/path/to/dir/");
    }

    // Multiple consecutive separators (should not panic)
    #[cfg(windows)]
    {
        let _ = soft_canonicalize(r"C:\path\\to\\\\dir");
    }
    #[cfg(unix)]
    {
        let _ = soft_canonicalize("/path//to////dir");
    }
}

/// Document the error codes that exotic filesystems return.
/// Our fallback handles these by continuing when fs::canonicalize fails.
#[test]
fn document_exotic_filesystem_error_codes() {
    // These are the error codes from the Rust issues:
    // - os error 1: ERROR_INVALID_FUNCTION (network drives, RAM disks)
    // - os error 2: ERROR_FILE_NOT_FOUND (Docker, Ext2Fsd)
    // - os error 122: ERROR_INSUFFICIENT_BUFFER (RAM disks)
    //
    // Our code handles all of these in the match statement:
    // ```
    // match fs_canonicalize(&absolute_path) {
    //     Ok(p) => return Ok(p),
    //     Err(e) => match e.kind() {
    //         io::ErrorKind::NotFound => { /* continue */ }
    //         io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied => return Err(e),
    //         _ => { /* continue to optimized boundary detection */ }
    //     },
    // }
    // ```
    //
    // The `_ => { /* continue */ }` branch catches all exotic filesystem errors
    // and falls back to our prefix-discovery logic.

    // This test just documents the behavior - actual testing of these errors
    // would require access to RAM disks or network drives.
    // No assertion needed - this is a documentation test
}

/// Verify symlink resolution still works when falling back.
/// This is the key advantage over pure lexical normalization (like normpath).
#[cfg(unix)]
#[test]
fn fallback_still_resolves_symlinks() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let temp = std::env::temp_dir();
    let test_dir = temp.join("soft_canon_symlink_fallback_test");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let real_dir = test_dir.join("real");
    fs::create_dir_all(&real_dir).unwrap();

    let link = test_dir.join("link");
    if symlink(&real_dir, &link).is_ok() {
        // Path through symlink to non-existing file
        let path = link.join("nonexistent.txt");
        let result = soft_canonicalize(path);

        assert!(result.is_ok());
        let resolved = result.unwrap();

        // Should resolve through symlink to real directory
        let resolved_str = resolved.to_string_lossy();
        assert!(
            resolved_str.contains("/real/"),
            "Should resolve symlink: {}",
            resolved_str
        );
        assert!(
            !resolved_str.contains("/link/"),
            "Should not contain symlink name: {}",
            resolved_str
        );
    }

    let _ = fs::remove_dir_all(&test_dir);
}

/// Windows symlink test (requires privileges)
#[cfg(windows)]
#[test]
fn fallback_still_resolves_symlinks_windows() {
    use std::fs;
    use std::os::windows::fs::symlink_dir;

    let temp = std::env::temp_dir();
    let test_dir = temp.join("soft_canon_symlink_fallback_test_win");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let real_dir = test_dir.join("real");
    fs::create_dir_all(&real_dir).unwrap();

    let link = test_dir.join("link");

    // Symlink creation may fail without admin privileges - skip gracefully
    match symlink_dir(&real_dir, &link) {
        Ok(_) => {
            let path = link.join("nonexistent.txt");
            let result = soft_canonicalize(path);

            assert!(result.is_ok());
            let resolved = result.unwrap();

            let resolved_str = resolved.to_string_lossy();
            // On Windows with extended-length prefix, check for "real" in path
            assert!(
                resolved_str.contains("real"),
                "Should resolve symlink: {}",
                resolved_str
            );
        }
        Err(e) if e.raw_os_error() == Some(1314) => {
            // ERROR_PRIVILEGE_NOT_HELD - skip test
            eprintln!("Skipping symlink test: requires elevated privileges");
        }
        Err(e) => {
            panic!("Unexpected error creating symlink: {}", e);
        }
    }

    let _ = fs::remove_dir_all(&test_dir);
}
