// Memory/resource exhaustion and stress tests
use crate::soft_canonicalize;
use tempfile::TempDir;

#[test]
fn test_memory_exhaustion_attempt() -> std::io::Result<()> {
    // WHITE-BOX: Try to cause memory issues with very long paths
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create a very long path with many components
    let mut long_path = base.to_path_buf();
    for i in 0..1000 {
        long_path.push(format!("component_{i:04}"));
    }
    long_path.push("final_file.txt");

    // This should handle long paths without memory issues
    let result = soft_canonicalize(&long_path);
    assert!(result.is_ok(), "Should handle very long paths");

    // Verify the result has the expected structure
    let result = result?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("component_0999"));
    assert!(result.to_string_lossy().ends_with("final_file.txt"));

    Ok(())
}

#[test]
fn test_hashset_cycle_detection_exhaustion() -> std::io::Result<()> {
    // WHITE-BOX: Try to exploit HashSet-based cycle detection by creating
    // paths that might cause memory pressure or performance degradation
    let temp_dir = TempDir::new()?;
    let _base = temp_dir.path();

    #[cfg(unix)]
    {
        // Create symlinks with moderately long paths to stress the HashSet
        // Use a length that's unlikely to hit filesystem limits
        let long_component = "a".repeat(100); // Reasonable length to avoid filesystem limits
        let target_dir = _base.join("target");
        std::fs::create_dir(&target_dir)?;

        for i in 0..20 {
            let link_path = _base.join(format!("{long_component}_{i}"));

            // Try to create the symlink, but gracefully handle filesystem limits
            match std::os::unix::fs::symlink(&target_dir, &link_path) {
                Ok(()) => {
                    // Test resolution with these long paths
                    let test_path = link_path.join("nonexistent");
                    let result = soft_canonicalize(test_path);

                    match result {
                        Ok(_) => {
                            // Good - should handle long paths correctly
                        }
                        Err(e)
                            if e.to_string().contains("name too long")
                                || e.to_string().contains("File name too long") =>
                        {
                            // Acceptable - hit filesystem limits
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e)
                    if e.to_string().contains("name too long")
                        || e.to_string().contains("File name too long") =>
                {
                    // Hit filesystem limit during creation, test accomplished its goal
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}
