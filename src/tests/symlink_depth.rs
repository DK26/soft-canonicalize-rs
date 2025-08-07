use crate::soft_canonicalize;
use tempfile::TempDir;

#[test]
fn test_symlink_depth_limit() {
    // This test verifies our symlink depth constants match expected OS limits

    // Test that our constants are reasonable and match OS expectations
    #[cfg(target_os = "windows")]
    assert_eq!(crate::MAX_SYMLINK_DEPTH, 63);

    #[cfg(not(target_os = "windows"))]
    assert_eq!(crate::MAX_SYMLINK_DEPTH, 40);
}

#[test]
fn test_symlink_depth_documentation() {
    // Test that our error message matches std::fs::canonicalize for symlink issues
    let _tmpdir = TempDir::new().expect("Failed to create temp dir");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link1 = _tmpdir.path().join("link1");
        let link2 = _tmpdir.path().join("link2");

        // Create a simple cycle to test error message
        if symlink(&link2, &link1).is_ok() && symlink(&link1, &link2).is_ok() {
            let result = soft_canonicalize(&link1);
            assert!(result.is_err());

            let error = result.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error
                .to_string()
                .contains("Too many levels of symbolic links"));
        }
    }

    #[cfg(windows)]
    {
        // Windows symlink creation requires admin privileges in most cases,
        // so we'll just verify the constant exists and behavior is correct
        let _depth = crate::MAX_SYMLINK_DEPTH;

        // Test that we handle Windows path edge cases
        let result = soft_canonicalize("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}

#[test]
fn test_python_style_edge_cases() {
    use std::env;
    use tempfile::TempDir;

    // Test edge cases inspired by Python's pathlib.Path.resolve() robustness

    // Empty path - should fail gracefully
    let result = soft_canonicalize("");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);

    // Test in controlled environment for predictable directory operations
    let temp_dir = TempDir::new().unwrap();
    let original_cwd = env::current_dir().unwrap();

    let test_result = std::panic::catch_unwind(|| {
        // Only change directory if it exists and is accessible
        if temp_dir.path().exists() {
            env::set_current_dir(temp_dir.path()).unwrap();
        }

        // Single dot - should resolve to current directory
        let result = soft_canonicalize(".");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());

        // Double dot - should resolve to parent directory
        let result = soft_canonicalize("..");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());

        // Multiple dots and slashes - should normalize
        let result = soft_canonicalize("./././../.");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
    });

    // Always try to restore the original directory
    let _ = env::set_current_dir(original_cwd);

    // Re-raise any panic that occurred during the test
    if let Err(e) = test_result {
        std::panic::resume_unwind(e);
    }

    // Test with existing temp directory + non-existing suffix (Python-style)
    let tmpdir = TempDir::new().expect("Failed to create temp dir");
    let test_path = tmpdir.path().join("non").join("existing").join("path.txt");

    let result = soft_canonicalize(test_path);
    assert!(result.is_ok());
    let resolved = result.unwrap();

    // Should start with the canonicalized temp directory
    let canonical_tmp = std::fs::canonicalize(tmpdir.path()).unwrap();
    assert!(resolved.starts_with(canonical_tmp));

    // Should end with our non-existing suffix
    assert!(resolved.to_string_lossy().contains("non"));
    assert!(resolved.to_string_lossy().contains("existing"));
    assert!(resolved.to_string_lossy().contains("path.txt"));
}
