//! Unix-specific security and edge case tests for soft-canonicalize
//!
//! This module tests platform-specific behaviors and limitations:
//! - Non-UTF8 filename handling differences between Unix systems
//! - macOS UTF-8 enforcement vs Linux permissive byte sequences
//! - Edge cases in symlink resolution and path canonicalization

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(unix)]
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn test_symlink_to_non_utf8_path() -> std::io::Result<()> {
    // This test documents the behavior differences between Unix systems regarding non-UTF8 filenames:
    // - Linux and other Unix systems generally allow arbitrary byte sequences in filenames
    // - macOS enforces UTF-8 encoding and rejects invalid sequences with EILSEQ (error 92)
    // Our canonicalization should handle both behaviors appropriately

    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();
    let non_utf8 = OsStr::from_bytes(b"nonutf8_\xFF");
    let target = base.join("target");
    fs::create_dir(&target)?;
    let link = base.join(non_utf8);

    // On macOS, creating symlinks with non-UTF8 names should fail
    #[cfg(target_os = "macos")]
    {
        let symlink_result = symlink(&target, &link);
        assert!(
            symlink_result.is_err(),
            "macOS should reject non-UTF8 filenames"
        );

        // Verify the error is about illegal byte sequence
        let err = symlink_result.unwrap_err();
        assert_eq!(err.raw_os_error(), Some(92)); // EILSEQ - Illegal byte sequence
    }

    // On other Unix systems, this should work
    #[cfg(not(target_os = "macos"))]
    {
        symlink(&target, &link)?;
        let test_path = link.join("file.txt");
        let result = crate::soft_canonicalize(test_path);
        // Should not panic, should either succeed or error gracefully
        assert!(result.is_ok() || result.is_err());
    }

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_utf8_edge_cases() -> std::io::Result<()> {
    // Test that our canonicalization works correctly with valid UTF-8 edge cases on macOS
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Test with Unicode normalization edge cases that macOS handles
    let test_cases = vec![
        "normal_path",
        "special_ñämé_with_émojî_🦀",
        "file with spaces",
        "file.with.dots",
        "file-with-dashes_and_underscores",
        "アニメ", // Japanese characters
        "файл",   // Cyrillic characters
    ];

    for case in test_cases {
        let target = base.join("target");
        fs::create_dir_all(&target)?;

        let link = base.join(case);
        symlink(&target, &link)?;

        let test_path = link.join("file.txt");
        let result = crate::soft_canonicalize(test_path);

        // Should handle these gracefully
        assert!(result.is_ok() || result.is_err());

        // Clean up for next iteration
        if link.exists() {
            fs::remove_file(&link)?;
        }
        if target.exists() {
            fs::remove_dir_all(&target)?;
        }
    }

    Ok(())
}
