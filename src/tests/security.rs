//! Security tests for soft_canonicalize
//!
//! Tests symlink jail break prevention and other security-related
//! functionality to validate security claims.

use crate::soft_canonicalize;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_symlink_jail_break_prevention() -> std::io::Result<()> {
    // Test that symlink resolution properly prevents jail breaks
    // This validates the security claim about symlink jail break prevention
    let temp_dir = tempdir()?;

    // Create a jail directory
    let jail = temp_dir.path().join("jail");
    fs::create_dir(&jail)?;

    // Create a target outside the jail that we want to protect
    let secret_file = temp_dir.path().join("secret.txt");
    fs::write(&secret_file, "sensitive data")?;

    // Create a symlink inside jail that tries to escape to the secret file
    let escape_link = jail.join("escape_link");

    // Try to create symlink (may fail on Windows without permissions)
    #[cfg(unix)]
    let symlink_result = std::os::unix::fs::symlink(&secret_file, &escape_link);
    #[cfg(windows)]
    let symlink_result = std::os::windows::fs::symlink_file(&secret_file, &escape_link);

    if symlink_result.is_ok() {
        // If symlink creation succeeded, test that soft_canonicalize resolves it
        let result = soft_canonicalize(&escape_link)?;
        let canonical_secret = fs::canonicalize(&secret_file)?;

        // The result should be the actual target (outside jail)
        assert_eq!(result, canonical_secret);

        // Verify that a security check would catch this
        let canonical_jail = fs::canonicalize(&jail)?;
        assert!(
            !result.starts_with(&canonical_jail),
            "Symlink should resolve to location outside jail, enabling detection"
        );
    }

    Ok(())
}
