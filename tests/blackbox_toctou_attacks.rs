//! Black-box Time-of-Check-to-Time-of-Use (TOCTOU) race condition attack tests.
//!
//! These tests are designed to find vulnerabilities by creating race conditions
//! where the nature of the filesystem changes during the canonicalization process.

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;
use tempfile::{Builder, TempDir};

/// Helper to create a temporary directory for testing
fn tmpdir() -> TempDir {
    Builder::new()
        .prefix("soft_canonicalize_toctou_attacks")
        .tempdir()
        .unwrap()
}

/// Check if we have symlink permissions (mainly for Windows)
fn got_symlink_permission(tmpdir: &TempDir) -> bool {
    #[cfg(windows)]
    {
        let link = tmpdir.path().join("symlink_test");
        let target = tmpdir.path().join("target");
        let _ = fs::File::create(&target);
        std::os::windows::fs::symlink_file(&target, link).is_ok()
    }
    #[cfg(not(windows))]
    {
        let _ = tmpdir;
        true
    }
}

/// Helper to create directory symlinks in a cross-platform way
fn symlink_dir(original: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    return std::os::windows::fs::symlink_dir(original, link);
    #[cfg(not(windows))]
    return std::os::unix::fs::symlink(original, link);
}

/// This test creates a TOCTOU race condition where a directory component of a path
/// is atomically replaced by a symlink while the canonicalization is in progress.
/// This is a creative pentest to check for inconsistent state handling.
#[test]
fn test_toctou_directory_to_symlink_type_change() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    if !got_symlink_permission(&tmpdir) {
        println!("Skipping test_toctou_directory_to_symlink_type_change: no symlink permission");
        return Ok(());
    }

    // Setup:
    // {tmpdir}/a/
    // {tmpdir}/b/
    // The path to be canonicalized is {tmpdir}/a/c
    let a_dir = tmpdir.path().join("a");
    let b_dir = tmpdir.path().join("b");
    fs::create_dir(&a_dir)?;
    fs::create_dir(&b_dir)?;

    let test_path = a_dir.join("c");

    // Store the paths for later comparison
    let b_dir_for_expected = b_dir.clone();
    let tmpdir_path_clone = tmpdir.path().to_path_buf();

    let handle = thread::spawn(move || {
        // Give the main thread a moment to start processing 'a' as a directory
        thread::sleep(Duration::from_millis(5));

        // Atomically replace the directory 'a' with a symlink to 'b'
        let temp_a_path = tmpdir_path_clone.join("a_temp_rename");
        if fs::rename(&a_dir, &temp_a_path).is_ok() && symlink_dir(&b_dir, &a_dir).is_ok() {
            // Clean up the renamed original directory
            let _ = fs::remove_dir_all(&temp_a_path);
        }
    });

    // Call soft_canonicalize while the attacker thread is running
    let result = soft_canonicalize(test_path);

    handle.join().unwrap();

    // The function must not panic. It should either return an error or a
    // valid, resolved path based on the state of the filesystem at some point
    // during the operation.
    match result {
        Ok(canonical_path) => {
            // If it succeeds, the path should be correctly resolved based on either
            // the initial or final state of the filesystem.
            let expected_final = fs::canonicalize(b_dir_for_expected)?.join("c");
            let expected_initial = fs::canonicalize(tmpdir.path())?.join("a").join("c");

            println!("Resolved path: {}", canonical_path.display());
            println!("Expected (final state): {}", expected_final.display());
            println!("Expected (initial state): {}", expected_initial.display());

            // The result must be one of the valid resolutions, depending on timing.
            // The most important outcome is that it doesn't crash or produce an invalid/inconsistent path.
            #[cfg(not(feature = "dunce"))]
            {
                assert!(
                    canonical_path == expected_final || canonical_path == expected_initial,
                    "Resolved path is not one of the valid expected outcomes."
                );
            }
            #[cfg(feature = "dunce")]
            {
                #[cfg(windows)]
                {
                    let result_str = canonical_path.to_string_lossy();
                    let final_str = expected_final.to_string_lossy();
                    let initial_str = expected_initial.to_string_lossy();

                    // dunce simplifies, std returns UNC
                    assert!(
                        !result_str.starts_with(r"\\?\"),
                        "dunce should simplify path"
                    );
                    assert!(final_str.starts_with(r"\\?\"), "std returns UNC for final");
                    assert!(
                        initial_str.starts_with(r"\\?\"),
                        "std returns UNC for initial"
                    );

                    let final_simplified = final_str.trim_start_matches(r"\\?\");
                    let initial_simplified = initial_str.trim_start_matches(r"\\?\");

                    assert!(
                        result_str.as_ref() == final_simplified
                            || result_str.as_ref() == initial_simplified,
                        "Resolved path is not one of the valid expected outcomes."
                    );
                }
                #[cfg(not(windows))]
                {
                    assert!(
                        canonical_path == expected_final || canonical_path == expected_initial,
                        "Resolved path is not one of the valid expected outcomes."
                    );
                }
            }
        }
        Err(e) => {
            // An error is also an acceptable outcome, as the filesystem state changed
            // during the operation, which can lead to NotFound or other errors.
            println!("Function returned an error (acceptable for a race condition): {e}");
            assert!(
                e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::Other,
                "Error should be NotFound or a generic I/O error."
            );
        }
    }

    Ok(())
}
