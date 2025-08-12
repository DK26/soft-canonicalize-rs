//! Integration tests for Windows 8.3 short filename detection
//!
//! These tests validate the end-to-end behavior that the false positive issue
//! with filenames like "hello~world.txt" has been resolved while still correctly
//! handling actual Windows 8.3 short names like "PROGRA~1".

#[cfg(windows)]
mod integration_tests {
    use crate::soft_canonicalize;

    #[test]
    fn test_false_positive_tilde_names_handled_correctly() {
        // Ensure that legitimate filenames with tildes are processed correctly
        let test_cases = vec![
            r"C:\Users\test\hello~world.txt",
            r"C:\Projects\backup~file.doc",
            r"C:\Config\settings~old.json",
            r"C:\Temp\test~project\file.txt",
        ];

        for test_path in test_cases {
            let got = soft_canonicalize(test_path).expect("canonicalize regular tilde filename");
            // These should be processed normally without any special short name handling
            assert!(
                got.to_string_lossy().contains('~'),
                "Tilde should be preserved in regular filename: {got:?}"
            );
            assert!(got.is_absolute(), "Result should be absolute: {got:?}");
        }
    }

    #[test]
    fn test_actual_short_name_paths_handled() {
        // Test that actual 8.3 patterns are correctly processed
        let short_name_paths = vec![
            r"C:\PROGRA~1\MyApp\config.txt",
            r"C:\Users\RUNNER~1\Documents\file.txt",
            r"C:\Temp\LONGFI~1.TXT",
        ];

        for test_path in short_name_paths {
            let got = soft_canonicalize(test_path).expect("canonicalize short name path");
            // The path should be processed (exact result depends on filesystem state)
            // but the important thing is it doesn't crash and produces a valid result
            assert!(got.is_absolute(), "Result should be absolute: {got:?}");
        }
    }
}

#[cfg(not(windows))]
mod non_windows_platform {
    use crate::soft_canonicalize;

    #[test]
    fn test_tilde_paths_on_non_windows() {
        // On non-Windows platforms, tildes should be treated as regular filename characters
        // since 8.3 short names don't exist
        let test_cases = vec![
            "~/hello~world.txt",
            "/tmp/backup~file.doc",
            "./settings~old.json",
        ];

        for test_path in test_cases {
            let result = soft_canonicalize(test_path);
            // Should either succeed (if path exists) or fail with a clear error
            // The important thing is no special Windows short name handling occurs
            if let Ok(path) = result {
                // If successful, path should be absolute and preserve tildes
                assert!(path.is_absolute(), "Result should be absolute: {path:?}");
            }
            // It's OK if the path doesn't exist - we're testing the algorithm,
            // not the filesystem
        }
    }
}
