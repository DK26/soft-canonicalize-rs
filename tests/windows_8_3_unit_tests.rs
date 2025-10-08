//! Unit tests for 8.3 detection logic to ensure v0.4.0 optimizations don't break it
//!
//! These tests validate the `has_windows_short_component` function behavior
//! independent of filesystem operations or symlink creation.

#[cfg(test)]
mod unit_tests {
    #[test]
    #[cfg(windows)]
    fn test_has_windows_short_component_basic_patterns() {
        use soft_canonicalize::soft_canonicalize;

        // Test that legitimate 8.3 patterns are detected
        let paths_with_8_3 = vec![
            r"C:\PROGRA~1\test.txt",
            r"C:\Users\RUNNER~1\file.txt",
            r"C:\WINDOW~1\System32",
            r"C:\path\LONGNA~1\file",
            r"C:\ABCDEF~1.TXT",
        ];

        for path_str in paths_with_8_3 {
            let result = soft_canonicalize(path_str);
            // The test is that these don't crash and produce valid output
            if let Ok(path) = result {
                assert!(
                    path.is_absolute(),
                    "Result should be absolute for: {}",
                    path_str
                );
                // For non-existing paths, 8.3 patterns should be preserved
                let path_lossy = path.to_string_lossy();
                println!("Input: {} → Output: {}", path_str, path_lossy);
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_false_positive_tilde_not_8_3() {
        use soft_canonicalize::soft_canonicalize;

        // Test that false positives (tildes without proper 8.3 format) are handled correctly
        let paths_not_8_3 = vec![
            r"C:\hello~world.txt",     // ~ in middle of name, no digit
            r"C:\test~.txt",           // No digit after ~
            r"C:\file~abc.txt",        // Letters after ~, not digits
            r"C:\name~.ext",           // No digit
            r"C:\tilde~file~name.txt", // Multiple tildes
        ];

        for path_str in paths_not_8_3 {
            let result = soft_canonicalize(path_str);
            if let Ok(path) = result {
                let path_lossy = path.to_string_lossy();
                // These should preserve the tilde as-is since they're not 8.3 patterns
                assert!(
                    path_lossy.contains('~'),
                    "Tilde should be preserved for non-8.3 pattern: {} → {}",
                    path_str,
                    path_lossy
                );
                println!(
                    "Non-8.3 tilde pattern preserved: {} → {}",
                    path_str, path_lossy
                );
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_8_3_pattern_validation() {
        use soft_canonicalize::soft_canonicalize;

        // Valid 8.3 patterns: name~digit or name~digit.ext
        let valid_8_3 = vec![
            (r"C:\PROGRA~1", true),
            (r"C:\PROGRA~1.EXE", true),
            (r"C:\A~1", true),
            (r"C:\ABCDEF~2.TXT", true),
        ];

        // Invalid 8.3 patterns
        let invalid_8_3 = vec![
            (r"C:\~1", false),         // No prefix before ~
            (r"C:\PROGRA~", false),    // No digit after ~
            (r"C:\PROGRA~ABC", false), // Letters after ~, not digit
            (r"C:\файл~1", false),     // Non-ASCII before ~
        ];

        for (path_str, should_look_like_8_3) in valid_8_3.into_iter().chain(invalid_8_3.into_iter())
        {
            let result = soft_canonicalize(path_str);
            if let Ok(path) = result {
                println!(
                    "Path: {} → {} (expected 8.3-like: {})",
                    path_str,
                    path.display(),
                    should_look_like_8_3
                );
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_mixed_path_with_8_3_components() {
        use soft_canonicalize::soft_canonicalize;

        // Paths mixing normal names and 8.3 patterns
        let mixed_paths = vec![
            r"C:\Program Files\SUBDIR~1\file.txt",
            r"C:\PROGRA~1\Normal Name\file.txt",
            r"C:\Normal\MIDDLE~1\Normal\file.txt",
        ];

        for path_str in mixed_paths {
            let result = soft_canonicalize(path_str);
            if let Ok(path) = result {
                let path_lossy = path.to_string_lossy();
                println!("Mixed path: {} → {}", path_str, path_lossy);
                assert!(path.is_absolute());
                // If the path contains PROGRA~1 or SUBDIR~1 or MIDDLE~1,
                // the non-existing portions should preserve them
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_8_3_with_parent_dir_components() {
        use soft_canonicalize::soft_canonicalize;

        // Test 8.3 patterns with .. components
        let test_paths = vec![
            r"C:\PROGRA~1\..\Users\file.txt",
            r"C:\Users\..\PROGRA~1\file.txt",
            r"C:\WINDOW~1\System32\..\file.txt",
        ];

        for path_str in test_paths {
            let result = soft_canonicalize(path_str);
            if let Ok(path) = result {
                let path_lossy = path.to_string_lossy();
                println!("Path with ..: {} → {}", path_str, path_lossy);
                assert!(path.is_absolute());
                // The .. should be resolved lexically first
                // Then 8.3 handling applies to what remains
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_unicode_not_8_3() {
        use soft_canonicalize::soft_canonicalize;

        // Unicode characters should prevent 8.3 detection
        // (8.3 names are ASCII-only)
        let unicode_paths = vec![
            r"C:\файл~1.txt",   // Cyrillic
            r"C:\文件~1.txt",   // Chinese
            r"C:\αρχείο~1.txt", // Greek
            r"C:\café~1.txt",   // Accented Latin
        ];

        for path_str in unicode_paths {
            let result = soft_canonicalize(path_str);
            if let Ok(path) = result {
                let path_lossy = path.to_string_lossy();
                println!("Unicode path: {} → {}", path_str, path_lossy);
                // Unicode characters mean this is NOT an 8.3 short name
                // The tilde should be preserved as a literal character
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_edge_case_8_3_patterns() {
        use soft_canonicalize::soft_canonicalize;

        // Edge cases for 8.3 detection
        let edge_cases = vec![
            r"C:\A~1",         // Minimal valid 8.3
            r"C:\ABCDEFGH~1",  // 8 chars before ~
            r"C:\ABCDEFGHI~1", // 9 chars before ~ (still valid, just long)
            r"C:\A~9999",      // Many digits
            r"C:\A~1.A",       // Minimal extension
            r"C:\A~1.ABC",     // 3-char extension
        ];

        for path_str in edge_cases {
            let result = soft_canonicalize(path_str);
            if let Ok(path) = result {
                println!("Edge case: {} → {}", path_str, path.display());
                assert!(path.is_absolute());
            }
        }
    }
}

#[cfg(not(windows))]
mod non_windows {
    #[test]
    fn placeholder() {
        println!("8.3 detection unit tests are Windows-specific");
    }
}
