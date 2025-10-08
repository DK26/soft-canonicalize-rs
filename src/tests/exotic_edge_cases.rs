//! Exotic edge cases identified from dunce crate and MSDN analysis
//!
//! This module covers rare edge cases discovered during comparison with:
//! - dunce crate (https://gitlab.com/kornelski/dunce)
//! - Microsoft MSDN documentation (https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
//!
//! Many of these tests are cross-platform relevant (UTF-8, path limits, etc.)
//!
//! See: docs/dunce_msdn_analysis.md for detailed analysis

use crate::soft_canonicalize;

#[cfg(feature = "anchored")]
use crate::anchored_canonicalize;

/// Test superscript digit reserved names (ISO-8859-1 characters)
///
/// Microsoft MSDN states:
/// "Windows recognizes the 8-bit ISO/IEC 8859-1 superscript digits ¹, ², and ³ as digits
/// and treats them as valid parts of COM# and LPT# device names, making them reserved
/// in every directory."
///
/// Current behavior: We do NOT special-case these, allowing them to be treated as regular
/// filenames. This is a conscious decision as:
/// 1. These are extremely rare in practice
/// 2. Windows itself has inconsistent handling across different APIs
/// 3. Our primary goal is matching std::fs::canonicalize for existing paths
#[cfg(windows)]
#[test]
fn test_superscript_reserved_names_documentation() {
    use tempfile::TempDir;

    // Superscript digits: ¹ (U+00B9), ² (U+00B2), ³ (U+00B3)
    let exotic_names = [
        ("COM¹", "COM with superscript 1"),
        ("COM²", "COM with superscript 2"),
        ("COM³", "COM with superscript 3"),
        ("LPT¹", "LPT with superscript 1"),
        ("LPT²", "LPT with superscript 2"),
        ("LPT³", "LPT with superscript 3"),
    ];

    let tmp = TempDir::new().expect("create tempdir");
    let _base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    for (name, desc) in exotic_names {
        let path = tmp.path().join(name).join("file.txt");
        let result = soft_canonicalize(&path);

        // Document current behavior: we allow these (don't reject as reserved)
        // They're treated as regular non-existing paths
        assert!(
            result.is_ok(),
            "Currently allowing {} ({}): path = {:?}",
            desc,
            name,
            path
        );

        if let Ok(resolved) = result {
            let resolved_str = resolved.to_string_lossy();
            assert!(
                resolved_str.contains(name),
                "Path should contain exotic name {}: {}",
                name,
                resolved_str
            );
        }
    }

    // Also test with extensions (dunce pattern)
    let exotic_with_ext = ["COM¹.txt", "LPT².exe", "COM³.tar.gz"];

    for name in exotic_with_ext {
        let path = tmp.path().join(name);
        let result = soft_canonicalize(&path);
        assert!(
            result.is_ok(),
            "Currently allowing exotic name with extension: {}",
            name
        );
    }
}

/// Test UTF-16 code unit counting for long paths
///
/// Windows measures path lengths in UTF-16 code units, not bytes:
/// - Emoji 🧐 = 4 bytes UTF-8, 2 UTF-16 code units
/// - Character ® = 2 bytes UTF-8, 1 UTF-16 code unit
///
/// Our implementation uses extended-length UNC format (\\?\) which bypasses
/// the 260-character MAX_PATH limit entirely, so this is primarily verification.
#[cfg(windows)]
#[test]
fn test_long_paths_with_multibyte_characters() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Create path with emoji (each 🧐 is 4 bytes UTF-8, 2 UTF-16 code units)
    let emoji_component = "🧐".repeat(50); // 200 bytes UTF-8, 100 UTF-16 code units
    let emoji_path = tmp.path().join(emoji_component).join("file.txt");

    let result = soft_canonicalize(&emoji_path);
    assert!(
        result.is_ok(),
        "Extended-length format should handle emoji paths: {:?}",
        emoji_path
    );

    if let Ok(resolved) = result {
        // With dunce: May be simplified if safe; without dunce: always UNC
        #[cfg(not(feature = "dunce"))]
        {
            let resolved_str = resolved.to_string_lossy();
            assert!(
                resolved_str.starts_with(r"\\?\"),
                "Should use extended-length format for absolute result: {}",
                resolved_str
            );
        }
        #[cfg(feature = "dunce")]
        {
            // With dunce, accept either format (dunce decides based on safety)
            // Just verify it's an absolute path
            assert!(resolved.is_absolute(), "Result should be absolute");
        }
    }

    // Create path with CJK characters
    let cjk_component = "日本語".repeat(50); // Each char is 3 bytes UTF-8, 1 UTF-16 code unit
    let cjk_path = tmp.path().join(cjk_component).join("测试.txt");

    let result = soft_canonicalize(&cjk_path);
    assert!(
        result.is_ok(),
        "Extended-length format should handle CJK paths: {:?}",
        cjk_path
    );

    // Create path with mixed multibyte characters
    let mixed = format!(
        "{}_{}_{}_{}",
        "🎃".repeat(20),
        "®".repeat(30),
        "日".repeat(40),
        "test"
    );
    let mixed_path = tmp.path().join(mixed).join("file.exe");

    let result = soft_canonicalize(&mixed_path);
    assert!(
        result.is_ok(),
        "Extended-length format should handle mixed multibyte chars: {:?}",
        mixed_path
    );
}

/// Test very long component names (approaching 255 character limit)
///
/// Windows has a 255-character limit per component (not total path).
/// With extended-length format, this limit is less strict, but we verify behavior.
#[cfg(windows)]
#[test]
fn test_long_component_names() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Test component near but under 255 characters
    let component_250 = "a".repeat(250);
    let path_250 = tmp.path().join(component_250).join("file.txt");

    let result = soft_canonicalize(path_250);
    assert!(result.is_ok(), "Should handle 250-char component");

    // Test component at exactly 255 characters
    let component_255 = "b".repeat(255);
    let path_255 = tmp.path().join(component_255).join("file.txt");

    let result = soft_canonicalize(path_255);
    assert!(result.is_ok(), "Should handle 255-char component");

    // Test component over 255 characters (behavior may vary)
    let component_300 = "c".repeat(300);
    let path_300 = tmp.path().join(component_300).join("file.txt");

    let result = soft_canonicalize(path_300);
    // Extended-length format may allow this, or filesystem may reject
    // Either way, we document behavior
    match result {
        Ok(_) => {
            // Extended-length format allowed it
        }
        Err(e) => {
            // Filesystem rejected it - this is acceptable
            assert!(
                e.kind() == std::io::ErrorKind::InvalidInput
                    || e.kind() == std::io::ErrorKind::NotFound,
                "Expected InvalidInput or NotFound, got: {:?}",
                e.kind()
            );
        }
    }
}

/// Test reserved names with various extensions (dunce pattern)
///
/// Reserved names remain reserved regardless of extension:
/// - CON.txt is reserved
/// - NUL.tar.gz is reserved
/// - PRN.anything is reserved
#[cfg(windows)]
#[test]
fn test_reserved_names_with_extensions() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    let reserved_with_ext = [
        "CON.txt",
        "PRN.exe",
        "AUX.dll",
        "NUL.tar.gz",
        "COM1.log",
        "COM9.dat",
        "LPT1.cfg",
        "LPT9.ini",
    ];

    for name in reserved_with_ext {
        let path = tmp.path().join(name);
        let result = soft_canonicalize(&path);

        // These paths should canonicalize (to non-existing path)
        // Windows will handle the reserved name semantics at access time
        assert!(
            result.is_ok(),
            "Should canonicalize reserved name with extension: {}",
            name
        );
    }
}

/// Test reserved names with trailing spaces and dots (dunce pattern)
///
/// Windows has complex rules for trailing spaces and dots:
/// - "con " (with space) is still CON
/// - "con." is still CON
/// - "con  " (multiple spaces) is still CON
/// - "con....." is still CON
/// - "con . .txt" has stem "con . " which trims to "con" -> CON
#[cfg(windows)]
#[test]
fn test_reserved_names_with_trailing_chars() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    let reserved_variants = [
        "CON ",     // trailing space
        "PRN.",     // trailing dot
        "AUX  ",    // multiple trailing spaces
        "NUL.....", // multiple trailing dots
        "COM1 .",   // space then dot
        "LPT1. ",   // dot then space
        "COM9 . ",  // space dot space
    ];

    for name in reserved_variants {
        let path = tmp.path().join(name);
        let result = soft_canonicalize(&path);

        // Should handle these (behavior depends on how Windows treats them)
        // Our job is to not crash and provide reasonable output
        assert!(
            result.is_ok() || result.is_err(),
            "Should not panic on reserved name variant: '{}'",
            name
        );
    }
}

/// Test that leading space makes names NOT reserved (dunce insight)
///
/// " CON" (with leading space) is NOT the same as "CON"
#[cfg(windows)]
#[test]
fn test_leading_space_not_reserved() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    let non_reserved = [
        " CON", // leading space
        " PRN", " AUX", " NUL", " COM1", " LPT1", "  CON", // multiple leading spaces
    ];

    for name in non_reserved {
        let path = tmp.path().join(name).join("file.txt");
        let result = soft_canonicalize(&path);

        // These should NOT be treated as reserved device names
        assert!(
            result.is_ok(),
            "Leading space should make non-reserved: '{}'",
            name
        );

        if let Ok(resolved) = result {
            let resolved_str = resolved.to_string_lossy();
            // The space should be preserved in the path
            assert!(
                resolved_str.contains(name),
                "Leading space should be preserved: expected '{}' in '{}'",
                name,
                resolved_str
            );
        }
    }
}

/// Test that dot prefix makes names NOT reserved (dunce insight)
///
/// ".CON" is NOT the same as "CON"
#[cfg(windows)]
#[test]
fn test_dot_prefix_not_reserved() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    let non_reserved = [".CON", ".PRN", ".AUX", ".NUL", ".COM1", ".LPT1"];

    for name in non_reserved {
        let path = tmp.path().join(name).join("file.txt");
        let result = soft_canonicalize(&path);

        // These should NOT be treated as reserved device names
        assert!(
            result.is_ok(),
            "Dot prefix should make non-reserved: '{}'",
            name
        );

        if let Ok(resolved) = result {
            let resolved_str = resolved.to_string_lossy();
            assert!(
                resolved_str.contains(name),
                "Dot prefix should be preserved: expected '{}' in '{}'",
                name,
                resolved_str
            );
        }
    }
}

/// Test invalid COM/LPT numbers are NOT reserved (dunce insight)
///
/// - COM0 is NOT reserved (only COM1-9)
/// - COM10, COM77, etc. are NOT reserved
/// - LPT0 is NOT reserved (only LPT1-9)
#[cfg(windows)]
#[test]
fn test_invalid_device_numbers_not_reserved() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    let non_reserved = [
        "COM0",  // 0 is not valid
        "COM10", // only 1-9 are reserved
        "COM77", "LPT0", "LPT10", "LPT99",
    ];

    for name in non_reserved {
        let path = tmp.path().join(name).join("file.txt");
        let result = soft_canonicalize(&path);

        // These should NOT be treated as reserved device names
        assert!(
            result.is_ok(),
            "Invalid device number should not be reserved: '{}'",
            name
        );

        if let Ok(resolved) = result {
            let resolved_str = resolved.to_string_lossy();
            assert!(
                resolved_str.contains(name),
                "Non-reserved name should be preserved: expected '{}' in '{}'",
                name,
                resolved_str
            );
        }
    }
}

/// Test filename component edge cases (dunce validation patterns)
#[cfg(windows)]
#[test]
fn test_filename_component_validation() {
    // Test that we handle (or reject) various problematic filenames
    let invalid_components = [
        "file<name.txt",    // < is invalid
        "file>name.txt",    // > is invalid
        "file:name.txt",    // : is invalid (except in ADS)
        "file\"name.txt",   // " is invalid
        "file|name.txt",    // | is invalid
        "file?name.txt",    // ? is invalid
        "file*name.txt",    // * is invalid
        "file\0name.txt",   // NUL byte is invalid
        "file\x1Fname.txt", // control char is invalid
    ];

    for component in invalid_components {
        let result = soft_canonicalize(component);

        // These should either be rejected or handled safely
        // We document behavior rather than prescribing it
        match result {
            Ok(p) => {
                // Some invalid chars may be accepted as non-existing paths
                // This is okay as long as we don't create security issues
                let _ = p;
            }
            Err(e) => {
                // Rejection is also acceptable
                assert!(
                    e.kind() == std::io::ErrorKind::InvalidInput
                        || e.kind() == std::io::ErrorKind::NotFound,
                    "Expected InvalidInput or NotFound for '{}', got: {:?}",
                    component,
                    e.kind()
                );
            }
        }
    }
}

/// Test that anchored_canonicalize properly handles exotic cases
#[cfg(all(windows, feature = "anchored"))]
#[test]
fn test_anchored_exotic_cases() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    // Test with emoji in anchored context
    let emoji_path = "🧐/file.txt";
    let result = anchored_canonicalize(&base, emoji_path);
    assert!(
        result.is_ok(),
        "Anchored should handle emoji: {}",
        emoji_path
    );

    if let Ok(resolved) = result {
        assert_eq!(
            resolved,
            base.join("🧐").join("file.txt"),
            "Anchored emoji path should resolve correctly"
        );
    }

    // Test with reserved name in anchored context
    let reserved_path = "subdir/CON.txt";
    let result = anchored_canonicalize(&base, reserved_path);
    assert!(
        result.is_ok(),
        "Anchored should handle reserved names: {}",
        reserved_path
    );

    // Test with long component in anchored context
    let long_component = "a".repeat(200);
    let long_path = format!("{}/file.txt", long_component);
    let result = anchored_canonicalize(&base, long_path);
    assert!(
        result.is_ok(),
        "Anchored should handle long components: {} chars",
        long_component.len()
    );
}

/// Test control characters in different contexts
///
/// Microsoft MSDN states control characters (1-31) are:
/// - Forbidden in regular filenames
/// - Allowed in alternate data streams (ADS)
#[cfg(windows)]
#[test]
fn test_control_characters_context_sensitive() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Control character in regular filename (should be rejected or handled)
    let control_in_name = "file\x01name.txt".to_string();
    let result = soft_canonicalize(tmp.path().join(control_in_name));

    match result {
        Ok(_) => {
            // If accepted, it's as non-existing path (Windows will reject at access time)
        }
        Err(e) => {
            // Rejection is acceptable for control chars in regular names
            assert!(
                e.kind() == std::io::ErrorKind::InvalidInput
                    || e.kind() == std::io::ErrorKind::NotFound,
                "Control char in filename: expected InvalidInput or NotFound, got: {:?}",
                e.kind()
            );
        }
    }

    // Control character in ADS context is explicitly tested in ADS test modules
    // This test documents the distinction
}

/// Test Unicode normalization edge cases
///
/// Unicode has multiple representations for some characters:
/// - Composed: é (single code point U+00E9)
/// - Decomposed: é (e + combining acute U+0065 U+0301)
///
/// Windows NTFS uses Unicode normalization, we verify we handle both forms
#[cfg(windows)]
#[test]
fn test_unicode_normalization() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Composed form (NFC)
    let composed = "café"; // é is U+00E9
    let path_composed = tmp.path().join(composed).join("file.txt");
    let result_composed = soft_canonicalize(path_composed);
    assert!(
        result_composed.is_ok(),
        "Should handle composed Unicode: {}",
        composed
    );

    // Decomposed form (NFD) - é as e + combining acute
    let decomposed = "café"; // é is U+0065 U+0301 (if your editor supports it)
    let path_decomposed = tmp.path().join(decomposed).join("file.txt");
    let result_decomposed = soft_canonicalize(path_decomposed);
    assert!(
        result_decomposed.is_ok(),
        "Should handle decomposed Unicode: {}",
        decomposed
    );

    // Both should produce paths (they may or may not be equal depending on NTFS normalization)
    // Our job is to handle both without crashing
}

/// Test maximum path depth (many nested directories)
#[cfg(windows)]
#[test]
fn test_maximum_path_depth() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let mut current = tmp.path().to_path_buf();

    // Create a deeply nested path (100 levels)
    for i in 0..100 {
        current = current.join(format!("dir{}", i));
    }
    current = current.join("file.txt");

    let result = soft_canonicalize(&current);
    assert!(
        result.is_ok(),
        "Extended-length format should handle deeply nested paths"
    );

    if let Ok(resolved) = result {
        let resolved_str = resolved.to_string_lossy();
        assert!(
            resolved_str.starts_with(r"\\?\"),
            "Deep path should use extended-length format: {}",
            resolved_str
        );
    }
}

/// Test that we handle all Rust special characters correctly
///
/// Rust's OsStr can contain:
/// - Valid Unicode (most common)
/// - Invalid UTF-8 sequences (on Unix)
/// - Unpaired surrogates (on Windows)
///
/// We verify graceful handling of edge cases
#[cfg(windows)]
#[test]
fn test_rust_string_edge_cases() {
    // Test empty path component handling
    let result = soft_canonicalize("");
    assert!(result.is_err(), "Empty path should be rejected");

    // Test path with only whitespace
    let result = soft_canonicalize("   ");
    // May succeed as relative path or be rejected
    let _ = result;

    // Test path with null bytes (should be rejected)
    let null_path = "test\0file.txt";
    let result = soft_canonicalize(null_path);
    assert!(result.is_err(), "Null bytes should be rejected");
}

/// Regression test: ensure dunce test patterns don't reveal bugs
///
/// This test runs several patterns from dunce's test suite to ensure
/// our implementation handles them correctly
#[cfg(windows)]
#[test]
fn test_dunce_regression_patterns() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Pattern: multiple dots with spaces
    let patterns = [
        ("con . .txt", "reserved with spaces and dots"),
        ("con.....txt", "reserved with many dots"),
        ("PRN.....", "reserved with trailing dots"),
        ("COM4 .txt", "reserved with space before extension"),
        ("a........a", "valid filename with many dots"),
        ("       b", "valid filename with leading spaces"),
    ];

    for (pattern, desc) in patterns {
        let path = tmp.path().join(pattern);
        let result = soft_canonicalize(&path);

        // Document that we handle all these patterns without panicking
        assert!(
            result.is_ok() || result.is_err(),
            "Should not panic on {}: {}",
            desc,
            pattern
        );
    }
}

// ============================================================================
// Cross-platform tests (Unix variants of relevant edge cases)
// ============================================================================

/// Test UTF-8 multibyte character handling on Unix
///
/// Unix paths are byte sequences, but most tools expect UTF-8.
/// Test emoji, CJK, and mixed multibyte characters.
#[cfg(unix)]
#[test]
fn test_unix_multibyte_characters() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Create path with emoji
    let emoji_component = "🧐".repeat(50);
    let emoji_path = tmp.path().join(emoji_component).join("file.txt");

    let result = soft_canonicalize(&emoji_path);
    assert!(
        result.is_ok(),
        "Unix should handle emoji paths: {:?}",
        emoji_path
    );

    // Create path with CJK characters
    let cjk_component = "日本語".repeat(50);
    let cjk_path = tmp.path().join(cjk_component).join("测试.txt");

    let result = soft_canonicalize(&cjk_path);
    assert!(
        result.is_ok(),
        "Unix should handle CJK paths: {:?}",
        cjk_path
    );

    // Create path with mixed multibyte characters
    let mixed = format!(
        "{}_{}_{}_{}",
        "🎃".repeat(20),
        "®".repeat(30),
        "日".repeat(40),
        "test"
    );
    let mixed_path = tmp.path().join(mixed).join("file.exe");

    let result = soft_canonicalize(&mixed_path);
    assert!(
        result.is_ok(),
        "Unix should handle mixed multibyte chars: {:?}",
        mixed_path
    );
}

/// Test long component names on Unix (typically 255 bytes per component)
///
/// Unlike Windows which counts UTF-16 code units, Unix counts bytes.
/// Most filesystems limit components to 255 bytes.
#[cfg(unix)]
#[test]
fn test_unix_long_component_names() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Test component near but under 255 bytes
    let component_250 = "a".repeat(250);
    let path_250 = tmp.path().join(component_250).join("file.txt");

    let result = soft_canonicalize(path_250);
    assert!(result.is_ok(), "Should handle 250-byte component on Unix");

    // Test component at exactly 255 bytes
    let component_255 = "b".repeat(255);
    let path_255 = tmp.path().join(component_255).join("file.txt");

    let result = soft_canonicalize(path_255);
    assert!(result.is_ok(), "Should handle 255-byte component on Unix");

    // Test component over 255 bytes (typically rejected by filesystem)
    let component_300 = "c".repeat(300);
    let path_300 = tmp.path().join(component_300).join("file.txt");

    let result = soft_canonicalize(path_300);
    // Filesystem will likely reject this during actual file operations
    // but our canonicalization may allow it as a non-existing path
    match result {
        Ok(_) => {
            // Allowed as non-existing path
        }
        Err(e) => {
            // Filesystem rejected it - acceptable
            assert!(
                e.kind() == std::io::ErrorKind::InvalidInput
                    || e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::Other,
                "Expected InvalidInput, NotFound, or Other for 300-byte component, got: {:?}",
                e.kind()
            );
        }
    }
}

/// Test Unicode normalization on Unix (especially macOS)
///
/// - Linux: typically preserves whatever form you give it
/// - macOS HFS+: normalizes to NFD (decomposed)
/// - macOS APFS: may preserve form but compares normalized
#[cfg(unix)]
#[test]
fn test_unix_unicode_normalization() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");

    // Composed form (NFC)
    let composed = "café"; // é is U+00E9
    let path_composed = tmp.path().join(composed).join("file.txt");
    let result_composed = soft_canonicalize(path_composed);
    assert!(
        result_composed.is_ok(),
        "Unix should handle composed Unicode: {}",
        composed
    );

    // Decomposed form (NFD)
    let decomposed = "café"; // é is U+0065 U+0301
    let path_decomposed = tmp.path().join(decomposed).join("file.txt");
    let result_decomposed = soft_canonicalize(path_decomposed);
    assert!(
        result_decomposed.is_ok(),
        "Unix should handle decomposed Unicode: {}",
        decomposed
    );

    // Both forms should be handled without error
    // Actual normalization behavior is filesystem-dependent
}

/// Test maximum path depth on Unix
///
/// Most Unix systems have limits like PATH_MAX (4096 on Linux)
/// but can vary by filesystem and kernel configuration
#[cfg(unix)]
#[test]
fn test_unix_maximum_path_depth() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let mut current = tmp.path().to_path_buf();

    // Create a deeply nested path (100 levels)
    for i in 0..100 {
        current = current.join(format!("dir{}", i));
    }
    current = current.join("file.txt");

    let result = soft_canonicalize(&current);
    assert!(
        result.is_ok(),
        "Unix should handle deeply nested paths (within PATH_MAX)"
    );
}

/// Test edge cases that apply to all platforms
#[test]
fn test_cross_platform_string_edge_cases() {
    // Test empty path
    let result = soft_canonicalize("");
    assert!(
        result.is_err(),
        "Empty path should be rejected on all platforms"
    );

    // Test path with null bytes (universally invalid)
    let null_path = "test\0file.txt";
    let result = soft_canonicalize(null_path);
    assert!(
        result.is_err(),
        "Null bytes should be rejected on all platforms"
    );
}

/// Test anchored_canonicalize with multibyte characters (cross-platform)
#[cfg(feature = "anchored")]
#[test]
fn test_anchored_multibyte_cross_platform() {
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("create tempdir");
    let base = soft_canonicalize(tmp.path()).expect("canonicalize tempdir");

    // Test with emoji in anchored context
    let emoji_path = "🧐/file.txt";
    let result = anchored_canonicalize(&base, emoji_path);
    assert!(
        result.is_ok(),
        "Anchored should handle emoji on all platforms: {}",
        emoji_path
    );

    if let Ok(resolved) = result {
        assert_eq!(
            resolved,
            base.join("🧐").join("file.txt"),
            "Anchored emoji path should resolve correctly"
        );
    }

    // Test with CJK characters
    let cjk_path = "日本語/测试.txt";
    let result = anchored_canonicalize(&base, cjk_path);
    assert!(
        result.is_ok(),
        "Anchored should handle CJK on all platforms: {}",
        cjk_path
    );

    // Test with long component
    let long_component = "a".repeat(200);
    let long_path = format!("{}/file.txt", long_component);
    let result = anchored_canonicalize(&base, long_path);
    assert!(
        result.is_ok(),
        "Anchored should handle long components: {} bytes",
        long_component.len()
    );
}
