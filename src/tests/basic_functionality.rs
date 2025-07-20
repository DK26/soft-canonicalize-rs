//! Basic functionality tests for soft_canonicalize
//!
//! Tests core functionality including existing paths, non-existing paths,
//! and deeply nested paths.

use crate::soft_canonicalize;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_existing_path() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test with existing directory
    let result = soft_canonicalize(temp_dir.path())?;
    let expected = fs::canonicalize(temp_dir.path())?;

    assert_eq!(result, expected);
    Ok(())
}

#[test]
fn test_non_existing_path() -> std::io::Result<()> {
    let temp_dir = tempdir()?;
    let non_existing = temp_dir.path().join("non_existing_file.txt");

    let result = soft_canonicalize(&non_existing)?;
    let expected = fs::canonicalize(temp_dir.path())?.join("non_existing_file.txt");

    assert_eq!(result, expected);
    Ok(())
}

#[test]
fn test_relative_path() -> std::io::Result<()> {
    let result = soft_canonicalize(Path::new("non/existing/relative/path.txt"))?;

    // Calculate the expected result: current_dir + "non/existing/relative/path.txt"
    let current_dir = std::env::current_dir()?;
    let expected = fs::canonicalize(&current_dir)?
        .join("non")
        .join("existing")
        .join("relative")
        .join("path.txt");

    // The result should be exactly current_dir/non/existing/relative/path.txt
    assert_eq!(result, expected);

    Ok(())
}

#[test]
fn test_no_filesystem_modification() -> std::io::Result<()> {
    // Test that soft_canonicalize creates no temporary files during operation
    // This validates the "Pure algorithm - No filesystem modification" claim
    let temp_dir = tempdir()?;
    let initial_contents: Vec<_> = fs::read_dir(temp_dir.path())?.collect();
    let initial_count = initial_contents.len();

    // Test canonicalization of non-existing path
    let _result = soft_canonicalize(temp_dir.path().join("non/existing/deep/path.txt"))?;

    // Verify no new files were created
    let final_contents: Vec<_> = fs::read_dir(temp_dir.path())?.collect();
    let final_count = final_contents.len();

    assert_eq!(
        initial_count, final_count,
        "soft_canonicalize should not create any files during operation"
    );

    Ok(())
}

#[test]
fn test_readme_examples() -> std::io::Result<()> {
    // Test that all examples from README.md actually work
    // This ensures documentation promises are backed by working code

    // Example 1: Basic usage from README
    let _path = soft_canonicalize("some/path/../other/file.txt")?;

    // Example 2: Security validation function from README
    fn is_safe_path(user_path: &str, jail: &std::path::Path) -> std::io::Result<bool> {
        let canonical_user = soft_canonicalize(user_path)?;
        let canonical_jail = std::fs::canonicalize(jail)?;
        Ok(canonical_user.starts_with(canonical_jail))
    }

    // Test the security function with tempdir
    let temp_dir = tempdir()?;
    let jail_path = temp_dir.path();

    // Safe path (inside jail)
    let safe_user_path = format!("{}/safe/file.txt", jail_path.display());
    let is_safe = is_safe_path(&safe_user_path, jail_path)?;
    assert!(is_safe, "Path inside jail should be safe");

    // Potentially unsafe path (tries to escape jail with ..)
    let unsafe_user_path = format!("{}/../escape.txt", jail_path.display());
    let is_unsafe = is_safe_path(&unsafe_user_path, jail_path)?;
    assert!(
        !is_unsafe,
        "Path escaping jail should be detected as unsafe"
    );

    Ok(())
}
