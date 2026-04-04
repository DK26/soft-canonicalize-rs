//! Black-box security tests for soft_canonicalize — symlink escape attempts
//! and race condition simulations.
//!
//! These tests treat soft_canonicalize as a black box and try to break it
//! through the public API without knowledge of internal implementation.
//! Focus is on discovering vulnerabilities through external behavior.

#[cfg(unix)]
use soft_canonicalize::soft_canonicalize;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_symlink_escape_attempts() -> std::io::Result<()> {
    // BLACK-BOX: Test various symlink-based escape attempts

    #[cfg(unix)]
    {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a jail directory
        let jail = base.join("jail");
        fs::create_dir(&jail)?;

        // Create sensitive area outside jail
        let secrets = base.join("secrets");
        fs::create_dir(&secrets)?;
        fs::write(secrets.join("secret.txt"), "TOP SECRET")?;

        // Create various symlink escape attempts
        let traversal_target = std::path::PathBuf::from("../secrets");
        let escape_attempts = vec![
            // Direct symlink to outside
            ("direct_escape", &secrets),
            // Symlink with traversal
            ("traversal_escape", &traversal_target),
            // Nested directory symlink
            ("nested", &secrets),
        ];

        for (link_name, target) in escape_attempts {
            let link_path = jail.join(link_name);

            // Try to create symlink (might fail on some systems)
            let symlink_result = std::os::unix::fs::symlink(target, &link_path);

            if symlink_result.is_ok() {
                // Test accessing file through symlink
                let attack_path = link_path.join("secret.txt");
                let result = soft_canonicalize(&attack_path);

                match result {
                    Ok(canonical) => {
                        println!(
                            "Symlink escape succeeded: {} -> {}",
                            attack_path.display(),
                            canonical.display()
                        );

                        // Verify it points outside jail (enabling detection)
                        let canonical_jail = fs::canonicalize(&jail)?;

                        #[cfg(not(feature = "dunce"))]
                        let escapes_jail = !canonical.starts_with(&canonical_jail);

                        #[cfg(feature = "dunce")]
                        let escapes_jail = {
                            let canonical_str = canonical.to_string_lossy();
                            let jail_str = canonical_jail.to_string_lossy();
                            let jail_simplified = jail_str.trim_start_matches(r"\\?\");
                            !canonical_str.starts_with(jail_simplified)
                        };

                        if escapes_jail {
                            println!(
                                "⚠️ Symlink escape detected: {} escapes {}",
                                canonical.display(),
                                canonical_jail.display()
                            );
                        }

                        // Should resolve to actual target location
                        let expected_target = secrets.join("secret.txt");
                        if expected_target.exists() {
                            let canonical_target = fs::canonicalize(&expected_target)?;

                            #[cfg(not(feature = "dunce"))]
                            {
                                assert_eq!(canonical, canonical_target);
                            }
                            #[cfg(feature = "dunce")]
                            {
                                let canonical_str = canonical.to_string_lossy();
                                let target_str = canonical_target.to_string_lossy();
                                #[cfg(windows)]
                                {
                                    assert!(
                                        !canonical_str.starts_with(r"\\?\"),
                                        "dunce should simplify"
                                    );
                                    assert!(target_str.starts_with(r"\\?\"), "std returns UNC");
                                    assert_eq!(
                                        canonical_str.as_ref(),
                                        target_str.trim_start_matches(r"\\?\")
                                    );
                                }
                                #[cfg(not(windows))]
                                {
                                    // On non-Windows, dunce has no effect; paths must be equal
                                    assert_eq!(canonical_str.as_ref(), target_str.as_ref());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "Symlink escape rejected: {} -> {}",
                            attack_path.display(),
                            e
                        );
                    }
                }

                // Test with non-existing file through symlink
                let nonexist_attack = link_path.join("nonexistent.txt");
                let result2 = soft_canonicalize(&nonexist_attack);

                match result2 {
                    Ok(canonical) => {
                        // Should still enable escape detection
                        let canonical_jail = fs::canonicalize(&jail)?;

                        #[cfg(not(feature = "dunce"))]
                        {
                            assert!(
                                !canonical.starts_with(&canonical_jail),
                                "Non-existing file through symlink should enable escape detection"
                            );
                        }
                        #[cfg(feature = "dunce")]
                        {
                            let canonical_str = canonical.to_string_lossy();
                            let jail_str = canonical_jail.to_string_lossy();
                            let jail_simplified = jail_str.trim_start_matches(r"\\?\");
                            assert!(
                                !canonical_str.starts_with(jail_simplified),
                                "Non-existing file through symlink should enable escape detection"
                            );
                        }
                        println!("✓ Non-existing symlink escape properly resolved for detection");
                    }
                    Err(e) => {
                        println!("Non-existing symlink attack rejected: {e}");
                    }
                }
            } else if let Err(e) = symlink_result {
                println!("Symlink creation failed for {}: {}", link_name, e);
            }
        }
    }

    Ok(())
}

#[test]
fn test_race_condition_simulations() -> std::io::Result<()> {
    // BLACK-BOX: Simulate race conditions during path resolution
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create initial structure
    let target_dir = base.join("target");
    fs::create_dir(target_dir)?;

    #[cfg(unix)]
    {
        let symlink = base.join("racing_link");
        std::os::unix::fs::symlink(base.join("target"), &symlink)?;

        // Spawn thread to modify filesystem during resolution
        let symlink_clone = symlink.clone();
        let base_clone = base.to_path_buf();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1));

            // Try to replace symlink during resolution
            let _ = fs::remove_file(&symlink_clone);
            let _ = std::os::unix::fs::symlink(base_clone.join("other"), &symlink_clone);

            std::thread::sleep(std::time::Duration::from_millis(1));

            // Create/delete directories
            let _ = fs::create_dir(base_clone.join("other"));
            let _ = fs::remove_dir(base_clone.join("other"));
        });

        // Try to canonicalize during modifications
        for i in 0..10 {
            let test_path = symlink.join(format!("file_{i}.txt"));
            let result = soft_canonicalize(&test_path);

            // Should handle race conditions gracefully
            match result {
                Ok(canonical) => {
                    assert!(canonical.is_absolute());
                    println!("Race test {}: OK -> {}", i, canonical.display());
                }
                Err(e) => {
                    println!("Race test {i}: Error -> {e}");
                    // Errors are acceptable due to race conditions
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        handle.join().unwrap();
    }

    Ok(())
}
