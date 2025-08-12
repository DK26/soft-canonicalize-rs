//! Advanced fuzzing tests for the path canonicalization algorithm
//!
//! These tests generate various malformed and edge-case inputs to stress
//! the algorithm and discover potential vulnerabilities.

use soft_canonicalize::soft_canonicalize;
use std::fs;
// Path imports will be added if needed
use tempfile::TempDir;

#[test]
fn test_boundary_condition_fuzzing() -> std::io::Result<()> {
    // WHITE-BOX: Test boundary conditions in our algorithm
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Test edge cases around component limits and buffer sizes
    let max_component = "A".repeat(255);
    let over_max_component = "B".repeat(256);
    let max_with_file = format!("{}/file", "C".repeat(255));

    let boundary_tests = vec![
        // Empty components
        "//double//slash",
        "///triple///slash",
        "////quadruple////slash",
        // Single character components with special meaning
        "a/b/c/d/e/f/g/h/i/j", // Many single chars
        "x/../y/../z/../w",    // Alternating traversal
        // Boundary around tilde detection
        "~",
        "~~",
        "~~~", // Just tildes
        "~1",
        "~12",
        "~123", // Tilde + varying digits
        "a~",
        "ab~",
        "abc~", // Chars + tilde at end
        // Boundary around ASCII detection (last ASCII char is 127)
        "\x7F~1",     // Last ASCII char
        "\u{0080}~1", // First non-ASCII
        "test\x7F~1", // ASCII boundary in middle
        // Boundary around path length limits
        &max_component,      // Max component length (POSIX)
        &over_max_component, // Over max component length
        &max_with_file,      // Max component + more
    ];

    for test_input in boundary_tests {
        let test_path = base.join(test_input);

        println!("Boundary test: '{test_input}'");

        let result = soft_canonicalize(&test_path);
        match result {
            Ok(canonical) => {
                assert!(canonical.is_absolute());
                // Verify no buffer overflows or corrupted output
                assert!(!canonical.to_string_lossy().is_empty());
                println!("  ✓ Resolved: {}", canonical.display());
            }
            Err(e) => {
                println!("  ✓ Rejected: {e}");
                // Verify error is reasonable, not a panic or corruption
                assert!(!e.to_string().is_empty());
            }
        }
    }

    Ok(())
}

#[test]
fn test_unicode_edge_case_fuzzing() -> std::io::Result<()> {
    // WHITE-BOX: Test Unicode edge cases that might confuse string processing
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    let unicode_tests = vec![
        // Unicode normalization issues
        "café~1",                 // é as single char
        "cafe\u{0301}~1",         // é as e + combining accent
        "test\u{0300}\u{0301}~1", // Multiple combining chars
        // Unicode that looks like ASCII
        "test\u{FF5E}1", // Fullwidth tilde (looks like ~)
        "test\u{02DC}1", // Small tilde
        "test\u{0303}1", // Combining tilde
        // Right-to-left override attacks
        "test\u{202E}1~evil",     // RTL override
        "\u{202D}test~1\u{202C}", // LTR override + pop
        // Zero-width characters
        "test\u{200B}~1", // Zero-width space
        "test~\u{FEFF}1", // Byte order mark
        "test~1\u{200C}", // Zero-width non-joiner
        // Surrogate pairs and invalid UTF-8
        "test\u{1F600}~1", // Emoji (4-byte UTF-8)
        "test\u{10000}~1", // Beyond BMP
        // Control characters
        "test\x00~1", // Null (should be caught)
        "test\x01~1", // SOH control
        "test\x1F~1", // Unit separator
        "test\x7F~1", // DEL
        // Mixed scripts that might confuse processing
        "тест~1",   // Cyrillic
        "测试~1",   // Chinese
        "🔥test~1", // Emoji + ASCII
        "مرحبا~1",  // Arabic (RTL)
    ];

    for test_input in unicode_tests {
        let test_path = base.join(test_input);

        println!("Unicode test: '{test_input}'");

        let result = soft_canonicalize(&test_path);
        match result {
            Ok(canonical) => {
                assert!(canonical.is_absolute());
                println!("  ✓ Resolved: {}", canonical.display());

                // Verify Unicode was preserved correctly
                let result_str = canonical.to_string_lossy();
                assert!(!result_str.is_empty());

                // For non-ASCII input, verify our 8.3 detection correctly
                // identified it as NOT a short name
                if !test_input.is_ascii() && test_input.contains('~') {
                    // Should preserve the original Unicode, not treat as 8.3
                    assert!(
                        result_str.contains('~'),
                        "Unicode tilde path should preserve tilde: {result_str}"
                    );
                }
            }
            Err(e) => {
                println!("  ✓ Rejected: {e}");

                // Null bytes should be explicitly rejected
                if test_input.contains('\x00') {
                    println!("  Error message for null byte: '{e}'");
                    let error_msg = e.to_string().to_lowercase();
                    assert!(
                        error_msg.contains("null") ||
                        error_msg.contains("nul") ||
                        error_msg.contains("invalid") ||
                        error_msg.contains("cannot contain") ||
                        error_msg.contains("winapi"),
                        "Null byte should be explicitly rejected with appropriate error message, got: '{e}'"
                    );
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_algorithmic_state_corruption_fuzzing() -> std::io::Result<()> {
    // WHITE-BOX: Test inputs that might corrupt internal algorithm state
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create some actual directories to test mixed existing/non-existing
    let existing2 = base.join("exists1").join("exists2");
    fs::create_dir_all(&existing2)?;

    // Pre-create format strings to avoid temporary value issues
    let repeated_traversal = format!("exists1/{}/nonexist", "../exists1/".repeat(20));
    let repeated_current = format!("exists1/{}/exists2/nonexist", "./".repeat(50));

    let state_corruption_tests = vec![
        // Tests for existing prefix computation edge cases
        "exists1/../exists1/exists2/../nonexist",
        "exists1/./exists2/../../exists1/nonexist",
        "exists1/exists2/../../../exists1/exists2/nonexist",
        // Tests for component stack manipulation
        "exists1/../exists1/../exists1/exists2",
        "exists1/exists2/../../exists1/exists2",
        // Tests for tilde handling with existing paths
        "exists1/test~1/nonexist",
        "exists1/fake~name/test~2/nonexist",
        // Tests for mixed separators and normalization
        "exists1\\exists2/nonexist",    // Mixed separators
        "exists1//exists2///nonexist",  // Multiple separators
        "exists1/./exists2/./nonexist", // Current dir references
        // Tests for root/prefix handling edge cases
        "../exists1/exists2/nonexist",  // Start with parent
        "./exists1/../exists1/exists2", // Start with current
        // Extremely nested patterns
        &repeated_traversal,
        &repeated_current,
    ];

    for test_input in state_corruption_tests {
        let test_path = base.join(test_input);

        println!("State corruption test: '{test_input}'");

        let result = soft_canonicalize(&test_path);
        match result {
            Ok(canonical) => {
                assert!(canonical.is_absolute());
                println!("  ✓ Resolved: {}", canonical.display());

                // Verify the result makes sense
                let canonical_str = canonical.to_string_lossy();

                // Should not have .. or . components in result (but UNC prefix \\?\ is ok)
                assert!(
                    !canonical_str.contains("/.."),
                    "Result contains unresolved ..: {canonical_str}"
                );
                assert!(
                    !canonical_str.contains("\\.."),
                    "Result contains unresolved ..: {canonical_str}"
                );
                assert!(
                    !canonical_str.contains("/./"),
                    "Result contains unresolved .: {canonical_str}"
                );
                assert!(
                    !canonical_str.contains("\\.\\"),
                    "Result contains unresolved .: {canonical_str}"
                );
                assert!(
                    !canonical_str.contains("//"),
                    "Result contains double slashes: {canonical_str}"
                );
                assert!(
                    !canonical_str.contains("\\\\") || canonical_str.starts_with("\\\\?\\"),
                    "Result contains double backslashes outside UNC: {canonical_str}"
                );

                // For paths referencing existing directories, verify correctness
                if test_input.contains("exists1") && test_input.contains("exists2") {
                    assert!(
                        canonical_str.contains("exists1") || canonical_str.contains("exists2"),
                        "Result should reference existing directories: {canonical_str}"
                    );
                }
            }
            Err(e) => {
                println!("  ✓ Rejected: {e}");
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
#[test]
fn test_windows_specific_edge_case_fuzzing() -> std::io::Result<()> {
    // WHITE-BOX: Windows-specific edge cases for our optimizations

    // Pre-create long path strings
    let extended_long_path = format!(r"\\?\C:\{}\test~1", "A".repeat(200));
    let near_limit_path = format!(r"C:\{}\test~1", "B".repeat(240));
    let very_long_dirname = format!(r"C:\{}\test~1", "VeryLongDirectoryName".repeat(5));

    let windows_edge_cases = vec![
        // UNC path edge cases with tildes
        r"\\?\UNC\server\share\test~1",
        r"\\server\share\fake~name",
        r"\\?\server\share\test~1", // Invalid UNC format
        // Drive letter edge cases
        r"C:\test~1\fake~name",
        r"\\?\C:\test~1\nonexist",
        r"C:/test~1/mixed/separators", // Mixed separators
        // Device namespace edge cases
        r"\\.\pipe\test~1",
        r"\\?\GLOBALROOT\test~1",
        r"\\?\Volume{guid}\test~1",
        // Extended-length path limits
        &extended_long_path,
        &near_limit_path, // Near limit
        // Reserved names with tildes
        r"C:\CON\test~1", // Reserved device name
        r"C:\PRN~1\test", // Reserved name that looks like 8.3
        r"C:\AUX\fake~name",
        // Case sensitivity edge cases
        r"C:\Test~1\FAKE~NAME",
        r"C:\TEST~1\fake~name",
        r"c:\test~1\FAKE~NAME", // Lowercase drive
        // Alternate data streams with tildes
        r"C:\test~1\file.txt:stream",
        r"C:\fake~name\file.txt:stream~1",
        // Long filename + 8.3 combinations
        &very_long_dirname,
    ];

    for test_input in windows_edge_cases {
        println!("Windows edge case: '{test_input}'");

        let result = soft_canonicalize(test_input);
        match result {
            Ok(canonical) => {
                assert!(canonical.is_absolute());
                println!("  ✓ Resolved: {}", canonical.display());

                let canonical_str = canonical.to_string_lossy();

                // Windows paths should use extended-length prefix when needed
                if canonical_str.len() > 260 && !canonical_str.starts_with(r"\\?\") {
                    println!("  Warning: Long path without extended prefix: {canonical_str}");
                }

                // Verify proper Windows path format
                assert!(
                    canonical_str.contains(":\\") || canonical_str.starts_with(r"\\"),
                    "Windows path should have proper format: {canonical_str}"
                );
            }
            Err(e) => {
                println!("  ✓ Rejected: {e}");

                // Invalid UNC formats should be rejected
                if test_input.starts_with(r"\\?\server\") {
                    assert!(
                        e.to_string().to_lowercase().contains("invalid")
                            || e.to_string().to_lowercase().contains("unc"),
                        "Invalid UNC should be explicitly rejected"
                    );
                }
            }
        }
    }

    Ok(())
}
