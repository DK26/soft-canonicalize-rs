// Platform-specific edge case tests
use crate::soft_canonicalize;
use tempfile::TempDir;

#[test]
fn test_platform_specific_path_limits() -> std::io::Result<()> {
    // WHITE-BOX: Test platform-specific path length limits
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create a path approaching system limits
    #[cfg(windows)]
    let max_component_len = 255; // NTFS limit
    #[cfg(unix)]
    let max_component_len = 255; // Common Unix limit

    // Create component at exactly the limit
    let long_component = "a".repeat(max_component_len);
    let long_path = base.join(&long_component).join("file.txt");

    // This might fail due to filesystem limits, but shouldn't crash
    let result = soft_canonicalize(long_path);
    match result {
        Ok(canonical) => {
            assert!(canonical.is_absolute());
            assert!(canonical.to_string_lossy().contains(&long_component));
        }
        Err(e) => {
            // Filesystem rejection is acceptable
            println!("Long component rejected by filesystem: {e}");
        }
    }

    Ok(())
}
