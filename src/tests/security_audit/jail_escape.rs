//! High-level security validation tests
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
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(result, canonical_secret);
        }

        #[cfg(feature = "dunce")]
        {
            // With dunce: our result is simplified, std is UNC
            #[cfg(windows)]
            {
                let result_str = result.to_string_lossy();
                let canonical_str = canonical_secret.to_string_lossy();
                assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
                assert!(canonical_str.starts_with(r"\\?\"), "std returns UNC");
                assert_eq!(
                    result_str.as_ref(),
                    canonical_str.trim_start_matches(r"\\?\")
                );
            }
            #[cfg(not(windows))]
            {
                assert_eq!(result, canonical_secret);
            }
        }

        // Verify that a security check would catch this
        let canonical_jail = fs::canonicalize(&jail)?;
        assert!(
            !result.starts_with(canonical_jail),
            "Symlink should resolve to location outside jail, enabling detection"
        );
    }

    Ok(())
}

#[test]
fn test_symlinked_directory_jail_break_with_new_file() -> std::io::Result<()> {
    // Test symlinked directory that points outside jail, with new file appended
    let temp_dir = tempdir()?;

    // Create jail directory
    let jail = temp_dir.path().join("jail");
    fs::create_dir(&jail)?;

    // Create external directory
    let external_dir = temp_dir.path().join("external");
    fs::create_dir(&external_dir)?;

    // Create symlink from jail to external directory
    let symlinked_dir = jail.join("symlinked_external");

    #[cfg(unix)]
    let symlink_result = std::os::unix::fs::symlink(&external_dir, &symlinked_dir);
    #[cfg(windows)]
    let symlink_result = std::os::windows::fs::symlink_dir(&external_dir, &symlinked_dir);

    if symlink_result.is_ok() {
        // Test path through symlinked directory to new file
        let path_through_symlink = symlinked_dir.join("new_file.txt");
        let result = soft_canonicalize(path_through_symlink)?;
        let expected = fs::canonicalize(&external_dir)?.join("new_file.txt");

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(result, expected);
        }

        #[cfg(feature = "dunce")]
        {
            // With dunce: our result is simplified, std is UNC
            #[cfg(windows)]
            {
                let result_str = result.to_string_lossy();
                let expected_str = expected.to_string_lossy();
                assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
                assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
                assert_eq!(
                    result_str.as_ref(),
                    expected_str.trim_start_matches(r"\\?\")
                );
            }
            #[cfg(not(windows))]
            {
                assert_eq!(result, expected);
            }
        }

        // Verify this points outside jail (security check would catch this)
        let canonical_jail = fs::canonicalize(&jail)?;
        assert!(
            !result.starts_with(&canonical_jail),
            "Result should point outside jail: {result:?} vs jail: {canonical_jail:?}"
        );
    }

    Ok(())
}

#[test]
fn test_nested_symlinked_directory_attack() -> std::io::Result<()> {
    // Test complex nested symlink attack where multiple levels try to escape
    let temp_dir = tempdir()?;

    // Create jail
    let jail = temp_dir.path().join("jail");
    fs::create_dir(&jail)?;

    // Create external target
    let external_target = temp_dir.path().join("external_target");
    fs::create_dir(&external_target)?;
    fs::write(external_target.join("secret.txt"), "secret content")?;

    // Create intermediate directory in jail
    let intermediate = jail.join("intermediate");
    fs::create_dir(&intermediate)?;

    // Create symlink from intermediate to external
    let escape_link = intermediate.join("escape");

    #[cfg(unix)]
    let symlink_result = std::os::unix::fs::symlink(&external_target, &escape_link);
    #[cfg(windows)]
    let symlink_result = std::os::windows::fs::symlink_dir(&external_target, &escape_link);

    if symlink_result.is_ok() {
        // Test path: jail/intermediate/escape/secret.txt
        let attack_path = escape_link.join("secret.txt");
        let result = soft_canonicalize(attack_path)?;
        let expected = fs::canonicalize(external_target.join("secret.txt"))?;

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(result, expected);
        }

        #[cfg(feature = "dunce")]
        {
            // With dunce: our result is simplified, std is UNC
            #[cfg(windows)]
            {
                let result_str = result.to_string_lossy();
                let expected_str = expected.to_string_lossy();
                assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
                assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
                assert_eq!(
                    result_str.as_ref(),
                    expected_str.trim_start_matches(r"\\?\")
                );
            }
            #[cfg(not(windows))]
            {
                assert_eq!(result, expected);
            }
        }

        // Verify escape detection
        let canonical_jail = fs::canonicalize(&jail)?;
        assert!(
            !result.starts_with(canonical_jail),
            "Nested symlink attack should be detectable by checking if result is outside jail"
        );
    }

    Ok(())
}
