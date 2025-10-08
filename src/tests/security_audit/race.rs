// Race condition and TOCTOU tests

#[test]
fn test_concurrent_symlink_modification() -> std::io::Result<()> {
    // WHITE-BOX: Try to cause race conditions in the boundary detection

    #[cfg(unix)]
    {
        use crate::soft_canonicalize;
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        let target1 = base.join("target1");
        let target2 = base.join("target2");
        fs::create_dir(&target1)?;
        fs::create_dir(&target2)?;

        let symlink = base.join("racing_symlink");
        std::os::unix::fs::symlink(&target1, &symlink)?;

        // Quickly change the symlink target while processing
        std::thread::spawn({
            let symlink = symlink.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(1));
                let _ = fs::remove_file(&symlink);
                let _ = std::os::unix::fs::symlink(&target2, &symlink);
            }
        });

        // The function should handle this gracefully
        let result = soft_canonicalize(symlink.join("nonexistent.txt"));

        // Race conditions may cause different outcomes on different platforms
        // The important thing is that it doesn't crash or hang
        match result {
            Ok(_) => {
                // Successfully resolved despite race condition
                println!("Concurrent modification handled successfully");
            }
            Err(e) => {
                // Error is also acceptable due to race condition
                println!("Concurrent modification resulted in error (acceptable): {e}");
                // Ensure it's a reasonable error, not a crash
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("No such file")
                        || error_msg.contains("symbolic links")
                        || error_msg.contains("not found")
                        || error_msg.contains("Invalid"),
                    "Should be a reasonable filesystem error, got: {error_msg}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_toctou_race_condition_prevention() {
    // Test protection against Time-of-Check-Time-of-Use (TOCTOU) race conditions
    // CVE-2022-21658 and similar vulnerabilities occur when path resolution
    // can be changed between canonicalization and actual file operations

    // Our soft_canonicalize function helps prevent this by:
    // 1. Not modifying the filesystem during canonicalization
    // 2. Providing deterministic resolution that can be safely checked

    use crate::soft_canonicalize;
    use std::env;

    // Use an absolute base to ensure deterministic results regardless of cwd
    let base = env::temp_dir();
    let malicious_path = base.join("../../../etc/passwd");

    let result = soft_canonicalize(&malicious_path);

    // Should succeed (path resolution is pure)
    assert!(result.is_ok());
    let resolved = result.unwrap();

    // The result should be deterministic and allow safe security checks
    assert!(resolved.is_absolute());

    // Subsequent calls should return the same result (no race condition possible)
    let result2 = soft_canonicalize(malicious_path);
    assert_eq!(result2.unwrap(), resolved);
}
