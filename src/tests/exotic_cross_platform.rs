//! Exotic edge cases for cross-platform and Unix-specific scenarios
//!
//! Covers rare edge cases discovered during comparison with:
//! - dunce crate (https://gitlab.com/kornelski/dunce)
//! - Microsoft MSDN documentation (https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
//!
//! Many of these tests are cross-platform relevant (UTF-8, path limits, etc.)
//!
//! See: docs/dunce_msdn_analysis.md for detailed analysis

use crate::soft_canonicalize;

#[cfg(feature = "anchored")]
use crate::anchored_canonicalize;

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
