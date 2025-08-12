//! White-box tests for Windows 8.3 short filename detection bypasses
//!
//! Tests for potential exploits in the is_likely_8_3_short_name function
//! and related optimization logic.

#[cfg(windows)]
#[cfg(test)]
mod short_filename_tests {
    use crate::soft_canonicalize;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_short_filename_detection_bypass_attempts() {
        // WHITE-BOX: Try to fool the 8.3 detection with crafted names
        let bypass_attempts = vec![
            // Edge cases for our ASCII-only check
            "test~1\u{0080}", // Non-ASCII after tilde+digits
            "test~1\u{00FF}", // Latin-1 supplement
            "тест~1",         // Cyrillic characters
            "测试~1",         // Chinese characters
            // Edge cases for tilde position
            "~1",    // Tilde at start (empty before_tilde)
            "~",     // Just tilde
            "~~1",   // Double tilde
            "test~", // Tilde at end (empty after_tilde)
            // Edge cases for digit detection
            "test~a",      // Letter after tilde
            "test~1a",     // Mixed digits and letters
            "test~01",     // Leading zero (valid)
            "test~999999", // Very long number
            // Extension edge cases
            "test~1.",     // Empty extension
            "test~1..txt", // Double dot
            "test~1.very.long.extension",
            "test~1.ВЕРХ", // Non-ASCII extension
            // Path separator injection attempts
            "test~1\\malicious", // Backslash injection
            "test~1/malicious",  // Forward slash injection
            "test~1\0hidden",    // Null byte injection
            // Unicode normalization attacks
            "test\u{0303}~1", // Combining character before tilde
            "test~\u{0303}1", // Combining character after tilde
        ];

        for attempt in bypass_attempts {
            // Test the detection function behavior
            println!("Testing short filename detection bypass: '{attempt}'");

            // If our detection is working correctly, these should either:
            // 1. Be correctly identified as NOT 8.3 short names
            // 2. Be safely handled even if misclassified

            let test_path = format!("C:\\temp\\{attempt}");
            let result = soft_canonicalize(&test_path);

            // Should not crash or cause undefined behavior
            match result {
                Ok(canonical) => {
                    assert!(canonical.is_absolute());
                    println!("  ✓ Resolved to: {}", canonical.display());
                }
                Err(e) => {
                    println!("  ✓ Rejected: {e}");
                }
            }
        }
    }

    #[test]
    fn test_short_filename_canonicalization_timing_attack() -> std::io::Result<()> {
        // WHITE-BOX: Test if 8.3 detection creates timing side channels
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a real directory that might get 8.3 short name
        let long_name_dir = base.join("VeryLongDirectoryNameThatWillGetShortName");
        fs::create_dir(&long_name_dir)?;

        let test_cases = vec![
            // Real 8.3 patterns (should trigger canonicalization)
            "VERYLO~1",
            "PROGRA~1",
            "DOCUME~1",
            // Fake 8.3 patterns (should NOT trigger canonicalization)
            "hello~world",
            "test~file",
            "backup~old",
        ];

        for case in test_cases {
            let test_path = base.join(case);

            let start = std::time::Instant::now();
            let _result = soft_canonicalize(&test_path);
            let duration = start.elapsed();

            // Timing should be consistent regardless of whether it's a real 8.3 name
            assert!(
                duration.as_millis() < 100,
                "Timing attack potential: {case} took {duration:?}"
            );
            println!("Case '{case}' took {duration:?}");
        }

        Ok(())
    }

    #[test]
    fn test_short_filename_utf16_bypass() {
        // WHITE-BOX: Test if UTF-16 encoding can bypass our ASCII checks
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        // Create OsString with embedded UTF-16 that might confuse string processing
        let utf16_bypass_attempts = vec![
            // UTF-16 surrogate pairs
            vec![0xD800, 0xDC00, 0x007E, 0x0031], // High+low surrogate + ~1
            // BOM injection
            vec![0xFEFF, 0x0074, 0x0065, 0x007E, 0x0031], // BOM + te~1
            // Null in UTF-16
            vec![0x0074, 0x0000, 0x007E, 0x0031], // t\0~1
        ];

        for utf16_data in utf16_bypass_attempts {
            let os_string = OsString::from_wide(&utf16_data);
            let test_path = format!("C:\\temp\\{}", os_string.to_string_lossy());

            println!("Testing UTF-16 bypass: {os_string:?}");

            let result = soft_canonicalize(&test_path);
            match result {
                Ok(canonical) => {
                    assert!(canonical.is_absolute());
                    println!("  ✓ Resolved: {}", canonical.display());
                }
                Err(e) => {
                    println!("  ✓ Rejected: {e}");
                }
            }
        }
    }
}

#[cfg(not(windows))]
#[cfg(test)]
mod non_windows_tests {
    use crate::soft_canonicalize;

    #[test]
    fn test_tilde_handling_on_non_windows() {
        // On non-Windows, tildes should be treated as regular characters
        let tilde_paths = vec![
            "/tmp/test~1",
            "/home/user/PROGRA~1",
            "./backup~file.txt",
            "~/test~world.txt",
        ];

        for path in tilde_paths {
            println!("Testing tilde path on non-Windows: '{path}'");

            let result = soft_canonicalize(path);
            match result {
                Ok(canonical) => {
                    // Should preserve tildes as regular characters
                    assert!(canonical.to_string_lossy().contains('~') || path.starts_with("~/"));
                    println!("  ✓ Preserved tilde: {}", canonical.display());
                }
                Err(e) => {
                    println!("  ✓ Rejected: {e}");
                }
            }
        }
    }
}
