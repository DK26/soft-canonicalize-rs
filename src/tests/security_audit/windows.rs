/// Windows-specific white-box security audit tests for soft_canonicalize
//
// These tests cover Windows-only edge cases, such as 8.3 short name symlink expansion.
#[cfg(windows)]
#[test]
fn test_windows_short_name_symlink_expansion() -> std::io::Result<()> {
    use std::fs;
    use std::os::windows::fs::symlink_dir;
    use tempfile::TempDir;

    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create a directory with a long name and a file inside
    let long_dir = base.join("LongDirectoryNameForShortNameTest");
    fs::create_dir(&long_dir)?;
    let file = long_dir.join("file.txt");
    fs::write(&file, "test")?;

    // Create a symlink with a short name to the long directory
    let short_symlink = base.join("LONGDI~1");
    if short_symlink.exists() {
        eprintln!(
            "Skipping test_windows_short_name_symlink_expansion: short symlink already exists"
        );
        return Ok(());
    }
    symlink_dir(&long_dir, &short_symlink)?;

    // Canonicalize a path through the short symlink
    let test_path = short_symlink.join("file.txt");
    let result = crate::soft_canonicalize(test_path)?;
    let expected = fs::canonicalize(&file)?;
    assert_eq!(result, expected);
    Ok(())
}
