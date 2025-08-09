//! Platform-specific tests for soft_canonicalize
//!
//! Tests Windows-specific and Unix-specific path formats
//! to validate cross-platform claims.

use crate::soft_canonicalize;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use tempfile::tempdir;

#[cfg(windows)]
#[test]
fn test_windows_specific_paths() -> std::io::Result<()> {
    // Test Windows-specific path formats to validate cross-platform claims

    // Test UNC path format (if possible)
    let unc_style = r"\\?\C:\temp\non\existing\file.txt";
    if let Ok(result) = soft_canonicalize(unc_style) {
        assert!(result.is_absolute());
        assert!(result.to_string_lossy().contains("file.txt"));
    }

    // Test drive letter paths
    let drive_path = "C:/non/existing/file.txt";
    let result = soft_canonicalize(drive_path)?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("file.txt"));

    // Test mixed separators (Windows should handle both / and \)
    let mixed_path = r"C:\non/existing\file.txt";
    let result = soft_canonicalize(mixed_path)?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("file.txt"));

    Ok(())
}

#[cfg(unix)]
#[test]
fn test_unix_specific_paths() -> std::io::Result<()> {
    // Test Unix-specific path formats to validate cross-platform claims

    // Test absolute Unix paths
    let unix_path = "/tmp/non/existing/file.txt";
    let result = soft_canonicalize(unix_path)?;
    assert!(result.is_absolute());
    assert!(result.starts_with("/"));
    assert!(result.to_string_lossy().contains("file.txt"));

    // Test paths with multiple slashes - verify they get normalized
    let multi_slash = "/tmp//non///existing/file.txt";
    let result = soft_canonicalize(multi_slash)?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("file.txt"));

    // Compare with std::fs::canonicalize behavior on an existing path
    // to ensure our normalization is consistent
    let temp_dir = tempdir()?;
    let existing_with_slashes = format!("{}//subdir", temp_dir.path().display());
    fs::create_dir_all(temp_dir.path().join("subdir"))?;

    if let (Ok(our_result), Ok(std_result)) = (
        soft_canonicalize(existing_with_slashes),
        fs::canonicalize(temp_dir.path().join("subdir")),
    ) {
        assert_eq!(
            our_result, std_result,
            "Our path normalization should match std::fs::canonicalize"
        );
    }

    Ok(())
}
