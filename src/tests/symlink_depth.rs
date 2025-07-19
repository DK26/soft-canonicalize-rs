use crate::soft_canonicalize;
use tempfile::TempDir;

#[test]
fn test_symlink_depth_limit() {
    // This test creates a very long symlink chain to test depth limiting
    // We won't actually create 60+ symlinks due to test performance,
    // but we can verify the constant exists and is used

    // Test that our constants are reasonable
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
        // so we'll just verify the constant exists
        let _depth = crate::MAX_SYMLINK_DEPTH;
    }
}
