//! Format verification tests
//!
//! These tests explicitly verify that output format matches expectations
//! for each feature combination.
//!
//! All tests in this module are Windows-specific.

#![cfg(windows)]

use crate::soft_canonicalize;

#[test]
fn verify_format_without_dunce_is_unc() {
    // This test should ONLY pass when dunce feature is NOT enabled
    let result = soft_canonicalize(r"C:\Test\Path").unwrap();

    #[cfg(not(feature = "dunce"))]
    {
        let result_str = result.to_string_lossy();
        assert!(
            result_str.starts_with(r"\\?\"),
            "Without dunce feature, output MUST have UNC prefix. Got: {}",
            result_str
        );
        // Also verify exact format
        assert_eq!(result, std::path::PathBuf::from(r"\\?\C:\Test\Path"));
    }

    #[cfg(feature = "dunce")]
    {
        // This branch ensures the test compiles with dunce feature
        // but doesn't enforce UNC format (dunce may simplify)
        let _ = result;
    }
}

#[cfg(feature = "dunce")]
#[test]
fn verify_format_with_dunce_simplifies_safe_paths() {
    // This test ONLY runs when dunce feature IS enabled
    let result = soft_canonicalize(r"C:\Test\Path").unwrap();
    let result_str = result.to_string_lossy();

    // Safe path (short, no reserved names, no ..) should be simplified
    assert!(
        !result_str.starts_with(r"\\?\"),
        "With dunce feature, safe paths should NOT have UNC prefix. Got: {}",
        result_str
    );

    // Should be in simplified format
    assert!(
        result_str.starts_with(r"C:\"),
        "Expected simplified format C:\\..., got: {}",
        result_str
    );
}

#[cfg(feature = "dunce")]
#[test]
fn verify_format_with_dunce_preserves_unsafe_long_paths() {
    // Long paths (>260 chars) should preserve UNC format even with dunce
    let long_path = format!(r"C:\{}\file.txt", "a".repeat(300));
    let result = soft_canonicalize(long_path).unwrap();
    let result_str = result.to_string_lossy();

    // Unsafe (long) path should keep UNC format
    assert!(
        result_str.starts_with(r"\\?\"),
        "With dunce feature, long paths should preserve UNC prefix. Got: {}",
        result_str
    );
}

#[cfg(feature = "dunce")]
#[test]
fn verify_format_with_dunce_resolves_dotdot_then_simplifies() {
    use tempfile::TempDir;

    // soft_canonicalize resolves .. BEFORE dunce sees the path
    // So dunce receives the resolved path and can simplify it if safe
    let temp_dir = TempDir::new().unwrap();
    let test_path = temp_dir
        .path()
        .join("a")
        .join("..")
        .join("b")
        .join("file.txt");

    let result = soft_canonicalize(test_path).unwrap();
    let result_str = result.to_string_lossy();

    // After resolving .., if the resulting path is safe, dunce simplifies it
    // This is CORRECT behavior: dunce operates on the canonicalized path
    assert!(
        !result_str.starts_with(r"\\?\"),
        "With dunce feature, resolved safe paths should be simplified. Got: {}",
        result_str
    );
}

#[cfg(feature = "dunce")]
#[test]
fn verify_format_with_dunce_preserves_reserved_names() {
    // Paths with reserved names should preserve UNC format
    let result = soft_canonicalize(r"C:\CON\file.txt").unwrap();
    let result_str = result.to_string_lossy();

    // Reserved name (CON) should keep UNC format
    assert!(
        result_str.starts_with(r"\\?\"),
        "With dunce feature, paths with reserved names should preserve UNC prefix. Got: {}",
        result_str
    );
}
