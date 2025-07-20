//! Optimization tests for soft_canonicalize
//!
//! Tests related to future optimization strategies,
//! particularly the hybrid optimization approach.

use crate::soft_canonicalize;
use tempfile::tempdir;

#[test]
fn test_hybrid_optimization_compatibility() -> std::io::Result<()> {
    // This test validates that our current implementation would be
    // compatible with a future hybrid optimization approach
    let temp_dir = tempdir()?;
    let base = temp_dir.path();

    // Create test cases that exercise different optimization strategies
    let existing_dir = base.join("existing");
    std::fs::create_dir_all(&existing_dir)?;
    std::fs::File::create(existing_dir.join("file"))?;

    // Test existing path (would use std::fs::canonicalize in hybrid approach)
    let existing_path = existing_dir.join("file");
    let result = soft_canonicalize(&existing_path)?;
    let std_result = std::fs::canonicalize(&existing_path)?;
    assert_eq!(result, std_result);

    // Test non-existing path (would use lexical approach in hybrid)
    let non_existing_path = base.join("non_existing/file.txt");
    let result = soft_canonicalize(&non_existing_path)?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("non_existing"));

    Ok(())
}
