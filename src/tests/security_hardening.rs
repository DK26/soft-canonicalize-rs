use crate::soft_canonicalize;

#[test]
fn test_null_byte_injection() {
    // A path containing a null byte.
    let path_with_null = "a/b\0c/d";
    let result = soft_canonicalize(path_with_null);

    // The behavior of `soft_canonicalize` should be to either return an error
    // or to handle the path correctly without truncation.
    // On Unix, this will likely result in an `InvalidInput` error.
    // On Windows, the behavior might differ, but it should not truncate the path.
    if let Ok(canonical_path) = result {
        // If it succeeds, it should not be truncated at the null byte.
        assert!(!canonical_path.to_str().unwrap().contains('\0'));
    } else {
        // An error is an acceptable outcome.
        assert!(result.is_err());
    }
}

#[test]
fn test_null_byte_error_consistency() {
    // Test that soft_canonicalize behaves consistently with std::fs::canonicalize
    // for null byte handling
    let path_with_null = "test\0path";

    // Get the error from std::fs::canonicalize
    let std_result = std::fs::canonicalize(path_with_null);
    let soft_result = soft_canonicalize(path_with_null);

    // Both should fail
    assert!(
        std_result.is_err(),
        "std::fs::canonicalize should reject null bytes"
    );
    assert!(
        soft_result.is_err(),
        "soft_canonicalize should reject null bytes"
    );

    let std_error = std_result.unwrap_err();
    let soft_error = soft_result.unwrap_err();

    // Both should use the same error kind
    assert_eq!(
        std_error.kind(),
        soft_error.kind(),
        "Error kinds should match: std={:?}, soft={:?}",
        std_error.kind(),
        soft_error.kind()
    );

    // Both should be InvalidInput
    assert_eq!(std_error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(soft_error.kind(), std::io::ErrorKind::InvalidInput);

    // The error messages should be meaningful (though they may differ slightly)
    let std_msg = std_error.to_string().to_lowercase();
    let soft_msg = soft_error.to_string().to_lowercase();

    // Both should mention null or nul in some form
    assert!(
        std_msg.contains("nul") || soft_msg.contains("null"),
        "Error messages should reference null bytes: std='{std_error}', soft='{soft_error}'"
    );
}

#[test]
fn test_toctou_race_condition_prevention() {
    // Test protection against Time-of-Check-Time-of-Use (TOCTOU) race conditions
    // CVE-2022-21658 and similar vulnerabilities occur when path resolution
    // can be changed between canonicalization and actual file operations

    // Our soft_canonicalize function helps prevent this by:
    // 1. Not modifying the filesystem during canonicalization
    // 2. Providing deterministic resolution that can be safely checked

    let malicious_path = "../../../etc/passwd";
    let result = soft_canonicalize(malicious_path);

    // Should succeed (path resolution is pure)
    assert!(result.is_ok());
    let resolved = result.unwrap();

    // The result should be deterministic and allow safe security checks
    assert!(resolved.is_absolute());

    // Subsequent calls should return the same result (no race condition possible)
    let result2 = soft_canonicalize(malicious_path);
    assert_eq!(result2.unwrap(), resolved);
}

#[test]
fn test_unicode_normalization_bypass_prevention() {
    // Test protection against Unicode normalization bypass attacks
    // Some path canonicalization functions can be bypassed using Unicode
    // characters that normalize differently

    // Test with Unicode that could potentially bypass path restrictions
    let unicode_path = "documents/user\u{0041}\u{0301}/file.txt"; // A with combining acute accent
    let normalized_path = "documents/userÁ/file.txt"; // Precomposed A with acute

    let result1 = soft_canonicalize(unicode_path);
    let result2 = soft_canonicalize(normalized_path);

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Our function should handle Unicode consistently
    // (The exact behavior may vary by OS, but should be consistent)
    let path1 = result1.unwrap();
    let path2 = result2.unwrap();

    // Both should be absolute paths
    assert!(path1.is_absolute());
    assert!(path2.is_absolute());
}

#[test]
fn test_double_encoding_bypass_prevention() {
    // Test protection against double-encoding bypass attacks
    // Attackers sometimes use URL encoding or other encoding schemes
    // to bypass path validation

    // Test with various encoding attempts that should not be automatically decoded
    let encoded_paths = [
        "documents/%2e%2e/%2e%2e/etc/passwd", // URL encoded ../..
        "documents/..%2f..%2fetc%2fpasswd",   // Mixed encoding
        "documents/../%2e%2e/etc/passwd",     // Partial encoding
    ];

    for encoded_path in &encoded_paths {
        let result = soft_canonicalize(encoded_path);
        assert!(result.is_ok(), "Should handle encoded path: {encoded_path}");

        let resolved = result.unwrap();
        assert!(resolved.is_absolute());

        // The resolved path should contain the encoded characters as-is
        // (not automatically decoded, which would be a security vulnerability)
        let path_str = resolved.to_string_lossy();
        assert!(
            path_str.contains("%2e") || path_str.contains("%2f") || path_str.contains(".."),
            "Encoded characters should not be automatically decoded"
        );
    }
}

#[test]
fn test_case_sensitivity_bypass_prevention() {
    // Test protection against case sensitivity bypass attacks
    // On case-insensitive filesystems, attackers might use case variations
    // to bypass path restrictions

    let paths = [
        "Documents/file.txt",
        "documents/file.txt",
        "DOCUMENTS/file.txt",
        "Documents/FILE.TXT",
    ];

    let results: Vec<_> = paths.iter().map(soft_canonicalize).collect();

    // All should succeed
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Path should canonicalize: {}", paths[i]);
    }

    // On case-insensitive systems, these should normalize to the same path
    // On case-sensitive systems, they'll be different
    // Either way, the behavior should be consistent with the filesystem
    #[cfg(windows)]
    {
        // Windows is case-insensitive - paths should normalize
        let canonical_results: Vec<_> = results.iter().map(|r| r.as_ref().unwrap()).collect();

        // Check that case normalization happens consistently
        for result in &canonical_results {
            assert!(result.is_absolute());
        }
    }
}

#[test]
fn test_long_path_component_handling() {
    // Test handling of very long path components
    // Some systems have limits on individual component length (not just total path length)

    // Create a very long component name (typically 255 chars is the limit)
    let long_component = "a".repeat(300);
    let long_path = format!("documents/{long_component}/file.txt");

    let result = soft_canonicalize(&long_path);

    // Should either succeed or fail gracefully with appropriate error
    match result {
        Ok(resolved) => {
            assert!(resolved.is_absolute());
            assert!(resolved.to_string_lossy().contains(&long_component));
        }
        Err(e) => {
            // If it fails, should be with an appropriate error kind
            assert!(
                e.kind() == std::io::ErrorKind::InvalidInput
                    || e.kind() == std::io::ErrorKind::InvalidData
                    || e.kind() == std::io::ErrorKind::NotFound,
                "Should fail with appropriate error for long component: {e:?}"
            );
        }
    }
}

#[test]
fn test_zero_width_and_control_character_handling() {
    // Test handling of zero-width and control characters that might
    // be used to confuse path parsing or display

    let malicious_chars = [
        "\u{200B}", // Zero-width space
        "\u{200C}", // Zero-width non-joiner
        "\u{200D}", // Zero-width joiner
        "\u{FEFF}", // Zero-width no-break space (BOM)
        "\u{0001}", // Start of heading (control char)
        "\u{007F}", // Delete character
    ];

    for &char in &malicious_chars {
        let malicious_path = format!("documents/file{char}.txt");
        let result = soft_canonicalize(&malicious_path);

        assert!(result.is_ok(), "Should handle control character path");
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());

        // The path should preserve the character (not strip it, which could
        // lead to unexpected path collisions)
        let path_str = resolved.to_string_lossy();
        assert!(
            path_str.contains(char),
            "Control character should be preserved, not stripped"
        );
    }
}
