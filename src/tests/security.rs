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

#[test]
fn test_symlinked_directory_jail_break_with_new_file() -> std::io::Result<()> {
    // Test the specific scenario described in the README:
    // 1. /jail/safe_dir/ exists and is a symlink to /outside/dangerous/
    // 2. User requests: "safe_dir/new_file.txt" (new_file.txt doesn't exist)
    // 3. soft_canonicalize should resolve to: /outside/dangerous/new_file.txt
    // 4. Security check can then detect this escapes the jail

    let temp_dir = tempdir()?;

    // Create jail directory
    let jail = temp_dir.path().join("jail");
    fs::create_dir(&jail)?;

    // Create dangerous directory outside jail
    let outside_dangerous = temp_dir.path().join("outside").join("dangerous");
    fs::create_dir_all(&outside_dangerous)?;

    // Create a symlinked directory inside jail that points to dangerous location
    let symlinked_dir = jail.join("safe_dir");

    // Try to create directory symlink (may fail on Windows without permissions)
    #[cfg(unix)]
    let symlink_result = std::os::unix::fs::symlink(&outside_dangerous, &symlinked_dir);
    #[cfg(windows)]
    let symlink_result = std::os::windows::fs::symlink_dir(&outside_dangerous, &symlinked_dir);

    if symlink_result.is_ok() {
        // Test the attack scenario: accessing new file through symlinked directory
        let attack_path = symlinked_dir.join("new_upload.txt");

        // Verify the attack path doesn't exist yet
        assert!(!attack_path.exists());

        // soft_canonicalize should resolve the symlinked directory
        let result = soft_canonicalize(&attack_path)?;

        // The result should point to the dangerous location outside jail
        let expected = outside_dangerous.join("new_upload.txt");
        let canonical_expected = soft_canonicalize(&expected)?;
        assert_eq!(result, canonical_expected);

        // Verify security check would catch this jail break attempt
        let canonical_jail = fs::canonicalize(&jail)?;
        assert!(
            !result.starts_with(&canonical_jail),
            "Attack should resolve to location outside jail: {} vs {}",
            result.display(),
            canonical_jail.display()
        );

        // Verify the dangerous path is indeed outside jail
        let canonical_dangerous = fs::canonicalize(&outside_dangerous)?;
        assert!(
            result.starts_with(&canonical_dangerous),
            "Result should be in dangerous directory: {} vs {}",
            result.display(),
            canonical_dangerous.display()
        );

        println!("✅ Symlinked directory jail break properly detected:");
        println!("   Attack path: {}", attack_path.display());
        println!("   Resolved to: {}", result.display());
        println!("   Jail boundary: {}", canonical_jail.display());
        println!("   Escapes jail: {}", !result.starts_with(&canonical_jail));
    } else {
        println!("⚠️  Skipping symlinked directory test (symlink creation failed - likely Windows permissions)");
    }

    Ok(())
}

#[test]
fn test_nested_symlinked_directory_attack() -> std::io::Result<()> {
    // Test a more complex scenario with nested symlinked directories
    let temp_dir = tempdir()?;

    // Create jail directory structure
    let jail = temp_dir.path().join("jail");
    let user_uploads = jail.join("uploads");
    fs::create_dir_all(&user_uploads)?;

    // Create dangerous target outside jail
    let secret_docs = temp_dir.path().join("secret_documents");
    fs::create_dir_all(&secret_docs)?;
    fs::write(secret_docs.join("classified.txt"), "TOP SECRET DATA")?;

    // Create symlinked subdirectory: jail/uploads/user123 -> /secret_documents
    let user_dir = user_uploads.join("user123");

    #[cfg(unix)]
    let symlink_result = std::os::unix::fs::symlink(&secret_docs, &user_dir);
    #[cfg(windows)]
    let symlink_result = std::os::windows::fs::symlink_dir(&secret_docs, &user_dir);

    if symlink_result.is_ok() {
        // Attack: try to upload a new file that would end up in secret location
        let attack_path = user_dir.join("my_innocent_file.txt");
        let result = soft_canonicalize(&attack_path)?;

        // Should resolve to secret location
        let expected_dangerous_path = secret_docs.join("my_innocent_file.txt");
        let canonical_expected = soft_canonicalize(&expected_dangerous_path)?;
        assert_eq!(result, canonical_expected);

        // Security validation should catch this
        let canonical_jail = fs::canonicalize(&jail)?;
        assert!(!result.starts_with(&canonical_jail));

        // Also test accessing existing file through symlink
        let existing_attack = user_dir.join("classified.txt");
        let existing_result = soft_canonicalize(&existing_attack)?;
        let canonical_secret = fs::canonicalize(secret_docs.join("classified.txt"))?;
        assert_eq!(existing_result, canonical_secret);
        assert!(!existing_result.starts_with(&canonical_jail));

        println!("✅ Nested symlinked directory attack properly detected");
    }

    Ok(())
}
