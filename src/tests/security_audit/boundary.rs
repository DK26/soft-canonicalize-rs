// Existing prefix, boundary detection, and path injection tests
use crate::soft_canonicalize;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_existing_boundary_detection_edge_cases() -> std::io::Result<()> {
    // WHITE-BOX: Test edge cases in the existing boundary detection algorithm
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Test case 1: Boundary exactly at a symlink
    #[cfg(unix)]
    {
        let real_dir = base.join("real");
        fs::create_dir(&real_dir)?;

        let symlink_dir = base.join("symlinked");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir)?;

        // Path where boundary is exactly at the symlink
        let test_path = symlink_dir.join("nonexistent.txt");
        let result = soft_canonicalize(test_path);

        // Handle platform-specific symlink behavior
        match result {
            Ok(resolved) => {
                let canonical_real = fs::canonicalize(&real_dir)?;
                let expected = canonical_real.join("nonexistent.txt");
                assert_eq!(resolved, expected);
            }
            Err(e) => {
                // On some platforms (like macOS), symlink resolution might hit limits
                let error_msg = e.to_string();
                if error_msg.contains("Too many levels") || error_msg.contains("symbolic links") {
                    println!("Platform hit symlink resolution limit (acceptable): {e}");
                } else {
                    return Err(e); // Unexpected error
                }
            }
        }
    }

    // Test case 2: Empty components in path
    let path_with_empty = base.join("").join("test.txt");
    let result = soft_canonicalize(path_with_empty)?;
    assert!(result.is_absolute());

    // Test case 3: Path ending with directory separator
    let dir_path = base.join("testdir").join("");
    let result = soft_canonicalize(dir_path)?;
    assert!(result.is_absolute());

    Ok(())
}

#[test]
fn test_existing_count_manipulation() -> std::io::Result<()> {
    // WHITE-BOX: Try to exploit the existing_count logic by creating scenarios
    // where the count might be manipulated or cause boundary detection issues
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create a deep directory structure
    let deep_path = base.join("a").join("b").join("c").join("d");
    fs::create_dir_all(deep_path)?;

    #[cfg(unix)]
    {
        // Create symlinks at different depths that might confuse existing_count
        let link1 = base.join("link1");
        std::os::unix::fs::symlink(base.join("a"), &link1)?;

        let link2 = base.join("a").join("link2");
        std::os::unix::fs::symlink(base.join("a").join("b"), &link2)?;

        // Create a broken symlink in the middle
        let broken_link = base.join("a").join("b").join("broken");
        std::os::unix::fs::symlink(base.join("nonexistent"), &broken_link)?;

        // Test paths that traverse through these mixed scenarios
        let test_cases = vec![
            link1.join("b").join("c").join("nonexistent.txt"),
            base.join("a")
                .join("link2")
                .join("c")
                .join("nonexistent.txt"),
            base.join("a")
                .join("b")
                .join("broken")
                .join("after_broken.txt"),
        ];

        for test_path in test_cases {
            let result = soft_canonicalize(test_path);
            // Should handle all these cases without panicking or returning inconsistent results
            match result {
                Ok(_) => {
                    // Good - algorithm handled the scenario
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Acceptable for broken symlinks
                }
                Err(e) => {
                    eprintln!("Unexpected error for complex existing_count scenario: {e}");
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_fast_path_bypass_attempts() -> std::io::Result<()> {
    // WHITE-BOX: Try to bypass the fast path optimization with edge cases
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create an existing absolute path with no dot components (should trigger fast path)
    let existing_file = base.join("existing.txt");
    fs::write(&existing_file, "content")?;

    // Verify fast path works
    let result = soft_canonicalize(&existing_file)?;
    let expected = fs::canonicalize(&existing_file)?;
    assert_eq!(result, expected);

    // Now try to create similar path that might confuse the fast path detection
    let tricky_path = existing_file.join("").join("..").join("existing.txt");
    let result2 = soft_canonicalize(tricky_path)?;
    // Should still resolve correctly even though it bypassed fast path
    assert_eq!(result2, expected);

    Ok(())
}

#[test]
fn test_canonicalization_bypass_attempts() -> std::io::Result<()> {
    // WHITE-BOX: Try to exploit the multiple canonicalization attempts in the algorithm
    // to bypass security checks or cause inconsistent behavior
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create scenarios where canonicalization might be bypassed
    fs::create_dir(base.join("existing"))?;

    #[cfg(unix)]
    {
        let existing_dir = base.join("existing");
        // Create symlinks that might interfere with canonicalization
        let link_to_existing = base.join("link_to_existing");
        std::os::unix::fs::symlink(&existing_dir, &link_to_existing)?;

        // Create a chain where canonicalization might be applied inconsistently
        let nested_link = existing_dir.join("nested_link");
        std::os::unix::fs::symlink(base.join("target_that_does_not_exist"), &nested_link)?;

        // Test paths that go through multiple canonicalization points
        let test_cases = vec![
            // Through direct symlink
            link_to_existing.join("nested_link").join("final_file.txt"),
            // Through path components that might trigger different canonicalization paths
            existing_dir
                .join("..")
                .join("existing")
                .join("nested_link")
                .join("final_file.txt"),
        ];

        for test_path in test_cases {
            let result = soft_canonicalize(test_path);

            match result {
                Ok(resolved) => {
                    // Should have consistent canonicalization
                    assert!(resolved.is_absolute());

                    // Verify that the resolved path makes sense
                    if let Some(parent) = resolved.parent() {
                        // The parent should either exist or be a valid non-existing path
                        assert!(parent.is_absolute());
                    }
                }
                Err(e) => {
                    // Errors are acceptable for broken symlink chains
                    assert!(
                        e.kind() == std::io::ErrorKind::NotFound
                            || e.to_string().contains("symbolic links")
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_long_path_component_handling() {
    // Test handling of very long path components
    // Some systems have limits on individual component length (not just total path length)

    use crate::soft_canonicalize;

    // Create a very long component name (typically 255 chars is the limit)
    let long_component = "a".repeat(300);
    let long_path = format!("documents/{long_component}/file.txt");

    let result = soft_canonicalize(long_path);

    // Should either succeed or fail gracefully with appropriate error
    match result {
        Ok(resolved) => {
            assert!(resolved.is_absolute());
            assert!(resolved.to_string_lossy().contains(&long_component));
        }
        Err(e) => {
            // If it fails, should be with an appropriate error kind
            assert!(
                e.kind() == std::io::ErrorKind::InvalidInput
                    || e.kind() == std::io::ErrorKind::InvalidData
                    || e.kind() == std::io::ErrorKind::NotFound,
                "Should fail with appropriate error for long component: {e:?}"
            );
        }
    }
}
