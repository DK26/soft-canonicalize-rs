//! Test suite for the `dunce` feature (simplified path output)
//!
//! These tests are based on the dunce crate test suite:
//! https://gitlab.com/kornelski/dunce
//!
//! Credit: kornelski for the original test patterns
//!
//! The `dunce` feature simplifies Windows UNC paths (\\?\C:\foo) to legacy format (C:\foo)
//! when safe to do so, while maintaining our non-existing path support.

use crate::soft_canonicalize;

#[cfg(feature = "anchored")]
use crate::anchored_canonicalize;

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::path::Path;

// ============================================================================
// Helper Functions (will be part of dunce feature implementation)
// ============================================================================

/// Count UTF-16 code units in an OsStr (Windows path length semantics)
#[cfg(windows)]
fn windows_char_len(s: &OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().count()
}

/// Check if a filename is valid according to Windows rules
#[cfg(windows)]
fn is_valid_filename(file_name: &OsStr) -> bool {
    // 255 character limit (both bytes and UTF-16 code units)
    if file_name.len() > 255 && windows_char_len(file_name) > 255 {
        return false;
    }

    // Non-unicode is safe, but Rust can't reasonably losslessly operate on such strings
    let byte_str = if let Some(s) = file_name.to_str() {
        s.as_bytes()
    } else {
        return false;
    };

    if byte_str.is_empty() {
        return false;
    }

    // Check for invalid characters
    if byte_str.iter().any(|&c| {
        matches!(
            c,
            0..=31 | b'<' | b'>' | b':' | b'"' | b'/' | b'\\' | b'|' | b'?' | b'*'
        )
    }) {
        return false;
    }

    // Filename can't end with . or space
    if matches!(byte_str.last(), Some(b' ' | b'.')) {
        return false;
    }

    true
}

/// Reserved DOS/Windows device names
#[cfg(windows)]
const RESERVED_NAMES: [&str; 22] = [
    "AUX", "NUL", "PRN", "CON", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Check if a filename is a reserved Windows name
#[cfg(windows)]
fn is_reserved<P: AsRef<OsStr>>(file_name: P) -> bool {
    // con.txt is reserved too
    // all reserved DOS names have ASCII-compatible stem
    if let Some(name) = Path::new(&file_name)
        .file_stem()
        .and_then(|s| s.to_str()?.split('.').next())
    {
        // "con.. .txt" is "CON" for DOS
        let trimmed = name.trim_end_matches(' ');
        return trimmed.len() <= 4
            && RESERVED_NAMES
                .into_iter()
                .any(|name| trimmed.eq_ignore_ascii_case(name));
    }
    false
}

// ============================================================================
// Reserved Name Tests (from dunce)
// ============================================================================

#[cfg(windows)]
#[test]
fn test_reserved_names() {
    // Should detect as reserved
    assert!(is_reserved("CON"));
    assert!(is_reserved("con"));
    assert!(is_reserved("con.con"));
    assert!(is_reserved("COM4"));
    assert!(is_reserved("COM4.txt"));
    assert!(is_reserved("COM4 .txt"));
    assert!(is_reserved("con."));
    assert!(is_reserved("con ."));
    assert!(is_reserved("con  "));
    assert!(is_reserved("con . "));
    assert!(is_reserved("con . .txt"));
    assert!(is_reserved("con.....txt"));
    assert!(is_reserved("PrN....."));
    assert!(is_reserved("nul.tar.gz"));

    // Should NOT detect as reserved
    assert!(!is_reserved(" PrN....."));
    assert!(!is_reserved(" CON"));
    assert!(!is_reserved("COM0"));
    assert!(!is_reserved("COM77"));
    assert!(!is_reserved(" CON "));
    assert!(!is_reserved(".CON"));
    assert!(!is_reserved("@CON"));
    assert!(!is_reserved("not.CON"));
    assert!(!is_reserved("CON。")); // Full-width ideographic period
}

// ============================================================================
// UTF-16 Length Tests (from dunce)
// ============================================================================

#[cfg(windows)]
#[test]
fn test_windows_char_len() {
    assert_eq!(1, windows_char_len(OsStr::new("a")));
    assert_eq!(1, windows_char_len(OsStr::new("€")));
    assert_eq!(1, windows_char_len(OsStr::new("本")));
    assert_eq!(2, windows_char_len(OsStr::new("🧐")));
    assert_eq!(2, windows_char_len(OsStr::new("®®")));
}

// ============================================================================
// Filename Validation Tests (from dunce)
// ============================================================================

#[cfg(windows)]
#[test]
fn test_filename_validation() {
    // Invalid filenames
    assert!(!is_valid_filename("..".as_ref()));
    assert!(!is_valid_filename(".".as_ref()));
    assert!(!is_valid_filename("aaaaaaaaaa:".as_ref()));
    assert!(!is_valid_filename("ą:ą".as_ref()));
    assert!(!is_valid_filename("".as_ref()));
    assert!(!is_valid_filename("a ".as_ref()));
    assert!(!is_valid_filename(" a. ".as_ref()));
    assert!(!is_valid_filename("a/".as_ref()));
    assert!(!is_valid_filename("/a".as_ref()));
    assert!(!is_valid_filename("/".as_ref()));
    assert!(!is_valid_filename("\\".as_ref()));
    assert!(!is_valid_filename("\\a".as_ref()));
    assert!(!is_valid_filename("<x>".as_ref()));
    assert!(!is_valid_filename("a*".as_ref()));
    assert!(!is_valid_filename("?x".as_ref()));
    assert!(!is_valid_filename("a\0a".as_ref()));
    assert!(!is_valid_filename("\x1f".as_ref()));
    assert!(!is_valid_filename("a".repeat(257).as_ref()));

    // Valid filenames
    assert!(is_valid_filename("®".repeat(254).as_ref()));
    assert!(is_valid_filename("ファイル".as_ref()));
    assert!(is_valid_filename("a".as_ref()));
    assert!(is_valid_filename("a.aaaaaaaa".as_ref()));
    assert!(is_valid_filename("a........a".as_ref()));
    assert!(is_valid_filename("       b".as_ref()));
}

// ============================================================================
// Path Simplification Tests (from dunce)
// ============================================================================

#[cfg(windows)]
#[test]
fn test_simplify_unc_paths() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = tmp.path();

    // Create a test file in a subdirectory with emoji
    let emoji_dir = base.join("foo").join("😀");
    std::fs::create_dir_all(emoji_dir).ok();

    // Test: UNC path with emoji should simplify to C:\foo\😀
    let unc_path = format!(r"\\?\{}\foo\😀", base.display());
    let result = soft_canonicalize(unc_path).expect("should canonicalize");

    // When dunce feature is enabled, this should be simplified (no \\?\)
    let result_str = result.to_str().expect("valid UTF-8");
    assert!(
        !result_str.starts_with(r"\\?\"),
        "Expected simplified path without \\\\?\\, got: {}",
        result_str
    );
    assert!(
        result_str.contains('😀'),
        "Expected emoji preserved in simplified path: {}",
        result_str
    );
}

#[cfg(windows)]
#[test]
fn test_simplify_preserve_unc_when_unsafe() {
    // These paths should NOT be simplified (from dunce test suite)

    // Server paths should remain UNC
    let server_path = r"\\?\serv\";
    let result = soft_canonicalize(server_path).expect("should handle UNC server path");
    assert!(
        result.to_str().unwrap().starts_with(r"\\?\"),
        "Server UNC paths should remain as UNC"
    );

    // Device paths should remain UNC
    let device_path = r"\\.\C:\notdisk";
    let result = soft_canonicalize(device_path).expect("should handle device path");
    assert!(
        result.to_str().unwrap().starts_with(r"\\"),
        "Device paths should remain as UNC"
    );

    // GLOBALROOT paths should remain UNC
    let globalroot_path = r"\\?\GLOBALROOT\Device\ImDisk0\path\to\file.txt";
    let result = soft_canonicalize(globalroot_path).expect("should handle GLOBALROOT");
    assert!(
        result.to_str().unwrap().starts_with(r"\\?\"),
        "GLOBALROOT paths should remain as UNC"
    );
}

#[cfg(windows)]
#[test]
fn test_safe_to_simplify_basic_paths() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Create test paths
    let foo_bar = tmp.path().join("foo").join("bar");
    std::fs::create_dir_all(foo_bar).ok();

    // These should be simplifiable (when they exist or as non-existing)
    let test_cases = vec![
        tmp.path().join("foo").join("bar"),
        tmp.path().join("😀").join("🎃"),
    ];

    for path in test_cases {
        let result = soft_canonicalize(path).expect("should canonicalize");
        let result_str = result.to_str().expect("valid UTF-8");

        // With dunce feature, should be simplified (no \\?\)
        assert!(
            !result_str.starts_with(r"\\?\"),
            "Expected simplified path without \\\\?\\, got: {}",
            result_str
        );
    }
}

#[cfg(windows)]
#[test]
fn test_unsafe_to_simplify_long_paths() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Path with component near MAX_PATH should remain UNC
    let long = "®".repeat(160);
    let short_path = tmp.path().join(&long);

    let result = soft_canonicalize(short_path).expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    // Single 160-char component should be safe to simplify
    assert!(
        !result_str.starts_with(r"\\?\"),
        "160-char component should be simplifiable"
    );

    // Two 160-char components should exceed MAX_PATH, remain UNC
    let long_path = tmp.path().join(&long).join(&long);
    let result = soft_canonicalize(long_path).expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    assert!(
        result_str.starts_with(r"\\?\"),
        "Path > 260 chars should remain UNC, got: {}",
        result_str
    );
}

#[cfg(windows)]
#[test]
fn test_unsafe_to_simplify_dotdot_paths() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Note: This test verifies that our canonicalization properly resolves .. in verbatim paths,
    // and then dunce simplification works correctly on the resolved result.
    //
    // Original test expectation: "Paths with . or .. in UNC form should NOT simplify
    // (UNC treats them literally, not as navigation)"
    //
    // However, this expectation conflicts with the purpose of soft_canonicalize, which is to
    // RESOLVE . and .. (canonicalize). The proper behavior is:
    // 1. Input: \\?\C:\Temp\foo\..\bar
    // 2. After canonicalization: \\?\C:\Temp\bar (.. is resolved)
    // 3. After dunce simplification: C:\Temp\bar (safe to simplify)
    //
    // The original dunce behavior (keeping .. in UNC paths) applies when:
    // - You pass an ALREADY-canonical path to dunce::simplified()
    // - That path still has .. components (very unusual, would mean literal ".." directories)
    //
    // For our use case, we canonicalize first, so .. is resolved before dunce sees it.
    let dotdot_path = format!(r"\\?\{}\foo\..\bar", tmp.path().display());
    eprintln!("INPUT: {}", dotdot_path);
    let result = soft_canonicalize(dotdot_path).expect("should handle UNC dotdot");
    let result_str = result.to_str().expect("valid UTF-8");
    eprintln!("OUTPUT: {}", result_str);

    // After canonicalization, .. is resolved, and the path is safe to simplify
    // We verify that the result equals the expected simplified path
    let expected = tmp.path().join("bar");
    let expected_canonical = crate::soft_canonicalize(expected).expect("canonicalize expected");

    assert_eq!(
        result, expected_canonical,
        "Verbatim path with .. should be resolved and then simplified (when safe)"
    );
}

#[cfg(windows)]
#[test]
fn test_unsafe_to_simplify_malformed_unc() {
    // Various malformed UNC paths should remain as-is or error
    let malformed_cases = vec![
        r"\\?\c\foo",     // No colon after drive letter
        r"\\?\c\foo/bar", // Forward slash (invalid in UNC)
        r"\\?\c:foo",     // No backslash after colon
        r"\\?\cc:foo",    // Invalid drive prefix
        r"\\?\c:foo\bar", // No backslash after drive
    ];

    for malformed in malformed_cases {
        let result = soft_canonicalize(malformed);

        if let Ok(path) = result {
            let path_str = path.to_str().expect("valid UTF-8");
            // If accepted, should remain UNC (not simplified)
            assert!(
                path_str.starts_with(r"\\?\"),
                "Malformed UNC path should remain UNC or error: {}",
                malformed
            );
        }
        // Error is also acceptable for malformed paths
    }
}

// ============================================================================
// Anchored Canonicalize + Dunce Feature Tests
// ============================================================================

#[cfg(all(windows, feature = "anchored"))]
#[test]
fn test_anchored_with_dunce_simplification() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    // Test: anchored_canonicalize should also simplify when dunce feature is enabled
    let result = anchored_canonicalize(base, "foo/bar/file.txt").expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    // With dunce feature, should be simplified (no \\?\)
    assert!(
        !result_str.starts_with(r"\\?\"),
        "Anchored paths with dunce feature should simplify, got: {}",
        result_str
    );
    assert!(
        result_str.contains("foo") && result_str.contains("bar"),
        "Path should contain expected components"
    );
}

#[cfg(all(windows, feature = "anchored"))]
#[test]
fn test_anchored_with_emoji_and_dunce() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    // Test: emoji in anchored path should simplify correctly
    let result = anchored_canonicalize(base, "😀/🎃/file.txt").expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    assert!(
        !result_str.starts_with(r"\\?\"),
        "Anchored emoji path should simplify"
    );
    assert!(
        result_str.contains('😀') && result_str.contains('🎃'),
        "Emoji should be preserved in simplified path"
    );
}

#[cfg(all(windows, feature = "anchored"))]
#[test]
fn test_anchored_with_reserved_names_stay_unc() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    // Test: reserved names in path should prevent simplification
    let result = anchored_canonicalize(base, "subdir/CON.txt").expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    // Should remain UNC because CON is reserved
    assert!(
        result_str.starts_with(r"\\?\"),
        "Path with reserved name should remain UNC for safety, got: {}",
        result_str
    );
}

#[cfg(all(windows, feature = "anchored"))]
#[test]
fn test_anchored_long_path_stays_unc() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    // Test: very long path should remain UNC
    let long_component = "a".repeat(200);
    let long_path = format!(
        "{}/{}_{}/file.txt",
        long_component, long_component, long_component
    );

    let result = anchored_canonicalize(base, long_path).expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    // Should remain UNC because total length > 260
    assert!(
        result_str.starts_with(r"\\?\"),
        "Long anchored path should remain UNC, got length: {}",
        result_str.len()
    );
}

// ============================================================================
// Non-existing Path + Dunce Feature Tests
// ============================================================================

#[cfg(windows)]
#[test]
fn test_nonexisting_path_simplification() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Test: non-existing path should still simplify when safe
    let nonexisting = tmp.path().join("does").join("not").join("exist.txt");

    let result = soft_canonicalize(nonexisting).expect("should canonicalize non-existing");
    let result_str = result.to_str().expect("valid UTF-8");

    // With dunce feature, even non-existing paths should simplify
    assert!(
        !result_str.starts_with(r"\\?\"),
        "Non-existing path should simplify with dunce feature, got: {}",
        result_str
    );
    assert!(
        result_str.contains("does")
            && result_str.contains("not")
            && result_str.contains("exist.txt"),
        "Non-existing components should be preserved"
    );
}

#[cfg(windows)]
#[test]
fn test_nonexisting_with_reserved_name_stays_unc() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Test: non-existing path with reserved name should NOT simplify
    let reserved_nonexisting = tmp.path().join("some").join("path").join("CON");

    let result = soft_canonicalize(reserved_nonexisting).expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    // Should remain UNC for safety (CON is reserved)
    assert!(
        result_str.starts_with(r"\\?\"),
        "Non-existing path with reserved name should remain UNC, got: {}",
        result_str
    );
}

#[cfg(windows)]
#[test]
fn test_nonexisting_long_path_stays_unc() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Test: non-existing path exceeding MAX_PATH should remain UNC
    let long = "a".repeat(100);
    let long_nonexisting = tmp
        .path()
        .join(&long)
        .join(&long)
        .join(&long)
        .join("file.txt");

    let result = soft_canonicalize(long_nonexisting).expect("should canonicalize");
    let result_str = result.to_str().expect("valid UTF-8");

    // Should remain UNC because length > 260
    assert!(
        result_str.starts_with(r"\\?\"),
        "Long non-existing path should remain UNC, got: {}",
        result_str
    );
}

// ============================================================================
// Unix Tests (dunce is no-op on Unix)
// ============================================================================

#[cfg(unix)]
#[test]
fn test_dunce_noop_on_unix() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // On Unix, dunce feature should be a no-op
    // Just verify our canonicalization still works
    let path = tmp.path().join("foo").join("bar").join("file.txt");
    let result = soft_canonicalize(path).expect("should canonicalize on Unix");

    // Should be absolute and contain the components
    assert!(result.is_absolute());
    assert!(result.to_str().unwrap().contains("foo"));
    assert!(result.to_str().unwrap().contains("bar"));
}

#[cfg(all(unix, feature = "anchored"))]
#[test]
fn test_anchored_dunce_noop_on_unix() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    // On Unix, dunce feature should not affect anchored_canonicalize
    let result = anchored_canonicalize(&base, "foo/bar/file.txt").expect("should canonicalize");

    assert!(result.is_absolute());
    assert_eq!(result, base.join("foo").join("bar").join("file.txt"));
}
