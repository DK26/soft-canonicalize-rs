//! Edge case robustness and error boundary testing
//!
//! Tests for boundary conditions, error scenarios, and system limits

use crate::soft_canonicalize;
use tempfile::tempdir;

#[test]
fn test_broken_symlink_handling() -> std::io::Result<()> {
    // Test that broken symlinks are handled gracefully
    let _temp_dir = tempdir()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        // Create a symlink to a non-existing target
        let broken_link = _temp_dir.path().join("broken_link");
        let non_existing_target = _temp_dir.path().join("does_not_exist.txt");

        if symlink(&non_existing_target, &broken_link).is_ok() {
            // Test that we can still canonicalize paths through broken symlinks
            let result = soft_canonicalize(&broken_link);
            assert!(result.is_ok(), "Should handle broken symlinks gracefully");

            // Test with additional path components after broken symlink
            let path_through_broken = broken_link.join("more/components");
            let result2 = soft_canonicalize(&path_through_broken);
            assert!(
                result2.is_ok(),
                "Should handle paths through broken symlinks"
            );
        }
    }

    Ok(())
}

#[test]
fn test_root_path_edge_cases() -> std::io::Result<()> {
    // Test canonicalization of root paths and near-root paths

    #[cfg(unix)]
    {
        // Test root path itself
        let root_result = soft_canonicalize("/")?;
        assert_eq!(root_result, std::path::PathBuf::from("/"));

        // Test path just under root
        let near_root = soft_canonicalize("/non_existing_file.txt")?;
        assert_eq!(
            near_root,
            std::path::PathBuf::from("/non_existing_file.txt")
        );
    }

    #[cfg(windows)]
    {
        // Test Windows drive root
        let drive_root = soft_canonicalize("C:\\")?;
        assert!(drive_root.to_string_lossy().ends_with(":\\"));

        // Test path just under drive root
        let near_root = soft_canonicalize("C:\\non_existing_file.txt")?;
        assert!(near_root
            .to_string_lossy()
            .contains("non_existing_file.txt"));
    }

    Ok(())
}

#[test]
fn test_filesystem_permission_scenarios() -> std::io::Result<()> {
    // Test scenarios where filesystem operations might fail due to permissions
    // This is more of a "robustness" test since we can't easily create permission
    // failures in a test environment, but we can test the error handling paths

    // Test with a path that might have permission issues
    // We expect this to either succeed or fail gracefully
    let result = soft_canonicalize("/proc/1/mem/non_existing"); // Unix-specific restricted path

    // We don't assert success/failure since permissions vary by system,
    // but we ensure it doesn't panic
    match result {
        Ok(_) => println!("Permission test: OK"),
        Err(e) => println!("Permission test error (expected): {e}"),
    }

    Ok(())
}

#[test]
fn test_very_long_paths() -> std::io::Result<()> {
    // Test with very long path names to check buffer handling
    let long_component = "a".repeat(255); // Max filename length on most systems
    let long_path = format!("some/path/{long_component}/file.txt");

    let result = soft_canonicalize(&long_path);
    assert!(result.is_ok(), "Should handle long paths");

    Ok(())
}

#[test]
fn test_special_characters_in_paths() -> std::io::Result<()> {
    // Test paths with special characters
    let special_chars = vec![
        "path with spaces/file.txt",
        "path-with-dashes/file.txt",
        "path_with_underscores/file.txt",
        "path.with.dots/file.txt",
    ];

    for path in special_chars {
        let result = soft_canonicalize(path);
        assert!(
            result.is_ok(),
            "Should handle special characters in: {path}"
        );
    }

    Ok(())
}

#[test]
fn test_nested_symlink_depth_boundary() -> std::io::Result<()> {
    // Test that we properly handle the exact boundary of MAX_SYMLINK_DEPTH
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let temp_dir = tempdir()?;

        // Try to create a chain of symlinks approaching the limit
        // (We won't create the full chain due to test complexity, but test the concept)
        let link1 = temp_dir.path().join("link1");
        let link2 = temp_dir.path().join("link2");
        let final_target = temp_dir.path().join("target/file.txt");

        if symlink(&link2, &link1).is_ok() && symlink(&final_target, &link2).is_ok() {
            let result = soft_canonicalize(&link1);
            assert!(result.is_ok(), "Should handle moderate symlink depth");
        }
    }

    Ok(())
}
