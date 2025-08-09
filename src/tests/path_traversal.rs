//! Path traversal tests for soft_canonicalize
//!
//! Tests directory traversal handling with .. components,
//! mixed existing/non-existing paths, and traversal beyond root.

use crate::soft_canonicalize;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tempfile::tempdir;

// Synchronize tests that depend on current working directory
static WORKING_DIR_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_relative_path_with_traversal() -> std::io::Result<()> {
    // Serialize tests that depend on current working directory
    let _lock = WORKING_DIR_MUTEX.lock().unwrap();

    // Test the specific case: "non/existing/../../part"
    // This should resolve to current_dir/part, cancelling out the non/existing parts
    let result = soft_canonicalize(Path::new("non/existing/../../part"))?;

    // Calculate the expected result: current_dir + "part"
    let current_dir = std::env::current_dir()?;
    let expected = fs::canonicalize(current_dir)?.join("part");

    // The result should be exactly current_dir/part
    assert_eq!(result, expected);

    Ok(())
}

#[test]
fn test_mixed_existing_and_nonexisting_with_traversal() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Create: temp_dir/existing/
    let existing_dir = temp_dir.path().join("existing");
    fs::create_dir(&existing_dir)?;

    // Test: temp_dir/existing/nonexisting/../sibling.txt
    // Should resolve to: temp_dir/existing/sibling.txt
    let test_path = existing_dir
        .join("nonexisting")
        .join("..")
        .join("sibling.txt");

    let result = soft_canonicalize(test_path)?;
    let expected = fs::canonicalize(&existing_dir)?.join("sibling.txt");

    assert_eq!(result, expected);
    Ok(())
}

#[test]
fn test_traversal_beyond_root() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test path with more .. than depth (should stop at root)
    let test_path = temp_dir
        .path()
        .join("../../../../../../../../../root_file.txt");

    let result = soft_canonicalize(test_path)?;

    // Should not escape beyond the filesystem root
    assert!(result.is_absolute());
    assert!(!result.starts_with(temp_dir.path()));
    Ok(())
}
