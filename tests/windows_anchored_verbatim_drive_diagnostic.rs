//! Diagnostic test to identify the source of malformed verbatim drive paths.
//!
//! This test is designed to help diagnose when and why anchored_canonicalize might produce
//! malformed verbatim drive paths like "\\?\C:Users\..." instead of "\\?\C:\Users\...".

#![cfg(all(feature = "anchored", windows))]

use std::path::{Path, PathBuf};

/// Create a test that explicitly builds a malformed path to verify our detection works
#[test]
fn test_malformed_verbatim_drive_detection() {
    use std::ffi::OsString;

    // Manually construct a malformed verbatim drive path (what the bug would produce)
    let mut malformed = OsString::from(r"\\?\");
    malformed.push("C:Users\\test\\file.txt"); // Missing backslash after C:
    let malformed_path = PathBuf::from(malformed);

    eprintln!("Malformed path: {:?}", malformed_path);

    // Our detection function should catch this
    let s = malformed_path.as_os_str().to_string_lossy();
    assert!(
        s.starts_with(r"\\?\C:"),
        "Should start with verbatim prefix"
    );

    // Check that it's missing the backslash
    let after_prefix = &s[4..]; // Skip "\\?\"
    assert_eq!(&after_prefix[0..2], "C:", "Should have drive letter");
    assert_ne!(
        &after_prefix[2..3],
        "\\",
        "Bug pattern: missing backslash after colon"
    );
    assert_ne!(
        &after_prefix[2..3],
        "/",
        "Bug pattern: missing separator after colon"
    );

    eprintln!("Successfully detected malformed pattern");
}

/// Test to understand how PathBuf handles drive-relative paths
#[test]
fn test_drive_relative_path_behavior() {
    // A drive-relative path (C:file.txt) is relative to the current directory on drive C:
    // These are different from absolute paths (C:\file.txt)

    let drive_relative = PathBuf::from("C:file.txt");
    let absolute = PathBuf::from(r"C:\file.txt");

    eprintln!("Drive-relative: {:?}", drive_relative);
    eprintln!("Absolute:       {:?}", absolute);

    for (i, comp) in drive_relative.components().enumerate() {
        eprintln!("  Drive-relative component {}: {:?}", i, comp);
    }
    for (i, comp) in absolute.components().enumerate() {
        eprintln!("  Absolute component {}: {:?}", i, comp);
    }
}

/// Test the ensure_windows_extended_prefix function behavior
#[test]
fn test_ensure_windows_extended_prefix_with_drive_relative() {
    // Import the function from the crate (if exposed) or replicate its logic
    use std::ffi::OsString;
    use std::path::{Component, Prefix};

    // Replicate the ensure_windows_extended_prefix logic
    fn add_verbatim_prefix(p: &Path) -> PathBuf {
        let mut comps = p.components();
        let first = match comps.next() {
            Some(Component::Prefix(pr)) => pr,
            _ => return p.to_path_buf(),
        };

        match first.kind() {
            Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => {
                p.to_path_buf()
            }
            Prefix::Disk(_drive) => {
                let mut s = OsString::from(r"\\?\");
                s.push(p.as_os_str());
                PathBuf::from(s)
            }
            _ => p.to_path_buf(),
        }
    }

    // Test with absolute path (should work correctly)
    let absolute = PathBuf::from(r"C:\Users\test\file.txt");
    let result_abs = add_verbatim_prefix(&absolute);
    eprintln!("Absolute input:  {:?}", absolute);
    eprintln!("With prefix:     {:?}", result_abs);

    let result_str = result_abs.to_string_lossy();
    assert!(
        result_str.starts_with(r"\\?\C:\"),
        "Should have backslash after colon"
    );

    // Test with drive-relative path (this is where the bug would occur)
    let drive_relative = PathBuf::from("C:Users\\test\\file.txt");
    let result_rel = add_verbatim_prefix(&drive_relative);
    eprintln!("Drive-rel input: {:?}", drive_relative);
    eprintln!("With prefix:     {:?}", result_rel);

    let result_rel_str = result_rel.to_string_lossy();
    if result_rel_str.starts_with(r"\\?\C:") && !result_rel_str.starts_with(r"\\?\C:\") {
        eprintln!("BUG MECHANISM CONFIRMED: Drive-relative path produces malformed verbatim path");
        eprintln!("  Input:  {:?}", drive_relative);
        eprintln!("  Output: {:?}", result_rel);
        eprintln!("This demonstrates how the bug would occur if anchored_canonicalize");
        eprintln!("constructs a path with Disk prefix but no RootDir component.");

        // This is expected behavior for the diagnostic - don't panic
        // The actual bug would be if anchored_canonicalize produces such paths
    } else {
        eprintln!(
            "Drive-relative path handling: {:?} -> {:?}",
            drive_relative, result_rel
        );
    }
}
