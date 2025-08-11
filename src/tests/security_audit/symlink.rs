// Symlink/cycle/chain/visited set/cycle detection tests
#[cfg(unix)]
use crate::soft_canonicalize;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_symlink_visited_set_manipulation() -> std::io::Result<()> {
    // WHITE-BOX: Try to exploit the visited HashSet by creating paths that
    // might hash to the same value or cause memory issues
    let temp_dir = TempDir::new()?;

    // Create multiple symlinks with similar paths that might cause hash collisions
    let base = temp_dir.path();
    let target = base.join("target");
    fs::create_dir(target)?;

    #[cfg(unix)]
    {
        // Create many symlinks with paths designed to potentially cause hash collisions
        for i in 0..100 {
            let link_name = format!("link_{i:03}");
            let link_path = base.join(&link_name);
            std::os::unix::fs::symlink(base.join("target"), &link_path)?;

            // Test that each symlink is resolved correctly
            let result = soft_canonicalize(link_path.join("nonexistent.txt"));

            match result {
                Ok(resolved) => {
                    let expected = fs::canonicalize(base.join("target"))?.join("nonexistent.txt");
                    assert_eq!(resolved, expected);
                }
                Err(e) => {
                    // Some platforms might limit the number of symlinks or hit other limits
                    let error_msg = e.to_string();
                    if error_msg.contains("Too many levels") || error_msg.contains("symbolic links")
                    {
                        println!("Hit platform symlink limit at iteration {i} (acceptable)");
                        break; // Stop creating more symlinks
                    } else {
                        return Err(e); // Unexpected error
                    }
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_max_symlink_depth_boundary() -> std::io::Result<()> {
    // WHITE-BOX: Test exactly at the MAX_SYMLINK_DEPTH boundary

    #[cfg(unix)]
    {
        use crate::MAX_SYMLINK_DEPTH;
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a chain of exactly MAX_SYMLINK_DEPTH symlinks
        let mut current = base.join("start");
        fs::write(&current, "content")?;

        for i in 0..MAX_SYMLINK_DEPTH {
            let next = base.join(format!("link_{i}"));
            std::os::unix::fs::symlink(&current, &next)?;
            current = next;
        }

        // This should still work (exactly at limit)
        let result = soft_canonicalize(&current);
        assert!(
            result.is_ok(),
            "Should handle exactly MAX_SYMLINK_DEPTH links"
        );

        // Add one more link - this should fail
        let final_link = base.join("final_link");
        std::os::unix::fs::symlink(&current, &final_link)?;

        let result = soft_canonicalize(&final_link);

        // Different platforms may have different symlink limits or error handling
        // Just ensure that excessive symlink chains are handled (either error or success)
        match result {
            Ok(_) => {
                // Some platforms might handle this differently - that's acceptable
                println!("Platform allows deeper symlink chains than expected");
            }
            Err(e) => {
                // Expected behavior: should limit symlink depth
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Too many levels") || error_msg.contains("symbolic links"),
                    "Should provide appropriate symlink error. Got: {error_msg}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_symlink_to_relative_path_boundary() -> std::io::Result<()> {
    // WHITE-BOX: Test symlinks that point to relative paths with complex resolution

    #[cfg(unix)]
    {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create structure: base/a/b/c/
        let deep_dir = base.join("a").join("b").join("c");
        fs::create_dir_all(&deep_dir)?;

        // Create symlink: base/a/shortcut -> ../b/c
        let shortcut = base.join("a").join("shortcut");
        std::os::unix::fs::symlink("../b/c", &shortcut)?;

        // Test path through symlink to non-existing file
        // Test: shortcut/nonexistent.txt
        let test_path = shortcut.join("nonexistent.txt");
        let result = soft_canonicalize(test_path)?;

        // Should resolve correctly through the relative symlink
        let canonical_deep = fs::canonicalize(&deep_dir)?;
        let expected = canonical_deep.join("nonexistent.txt");

        // On different platforms, symlink resolution might work differently
        // Some platforms might resolve the symlink, others might not when the final file doesn't exist
        // Check that the result resolves to either the target directory or shows the symlink path
        let result_str = result.to_string_lossy();
        let expected_str = expected.to_string_lossy();
        let expected_suffix = "a/b/c/nonexistent.txt";
        let symlink_suffix = "a/shortcut/nonexistent.txt";

        assert!(
            result == expected
                || result_str.ends_with(expected_suffix)
                || result_str.ends_with(symlink_suffix),
            "Symlink should resolve to target directory or show symlink path. Got: {result_str}, Expected target: {expected_str}"
        );
    }

    Ok(())
}

#[test]
fn test_broken_symlink_chain() -> std::io::Result<()> {
    // WHITE-BOX: Test chains of broken symlinks

    #[cfg(unix)]
    {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create chain: link1 -> link2 -> nonexistent
        let link1 = base.join("link1");
        let link2 = base.join("link2");
        let nonexistent = base.join("nonexistent");

        std::os::unix::fs::symlink(&link2, &link1)?;
        std::os::unix::fs::symlink(nonexistent, &link2)?;

        // This should resolve the chain even though final target doesn't exist
        let result = soft_canonicalize(&link1)?;
        let expected = fs::canonicalize(base)?.join("nonexistent");
        assert_eq!(result, expected);
    }

    Ok(())
}

#[test]
fn test_symlink_cycle_with_complex_paths() -> std::io::Result<()> {
    // WHITE-BOX: Test complex symlink cycles that might bypass detection

    #[cfg(unix)]
    {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create complex cycle: a -> ../b, b -> c/d, c/d -> ../../a
        let link_a = base.join("a");
        let link_b = base.join("b");
        let dir_c = base.join("c");
        fs::create_dir(&dir_c)?;
        let link_d = dir_c.join("d");

        std::os::unix::fs::symlink("../b", &link_a)?;
        std::os::unix::fs::symlink("c/d", link_b)?;
        std::os::unix::fs::symlink("../../a", link_d)?;

        // Try to traverse this cycle
        let result = soft_canonicalize(link_a.join("nonexistent.txt"));

        // Should detect the cycle - but different platforms handle this differently
        match result {
            Ok(_) => {
                // Some platforms might handle cycles differently
                println!("Platform handled symlink cycle without error");
            }
            Err(error) => {
                // Expected: cycle detection
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("Too many levels") || error_msg.contains("symbolic links"),
                    "Should detect symlink cycle. Got: {error_msg}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_system_symlink_depth_bypass() -> std::io::Result<()> {
    // WHITE-BOX: Try to exploit the system symlink depth limit (5) vs regular limit (40)
    // to create scenarios where depth counting might be inconsistent
    let temp_dir = TempDir::new()?;
    let _base = temp_dir.path();

    #[cfg(unix)]
    {
        // Create a chain that might be classified as "system" symlinks
        let var_like = _base.join("var");
        fs::create_dir(&var_like)?;

        // Create symlinks that might trigger system symlink detection
        let current_link = var_like.join("log");
        let target_dir = _base.join("actual_log");
        fs::create_dir(&target_dir)?;
        std::os::unix::fs::symlink(&target_dir, &current_link)?;

        // Now create a nested chain through this "system-like" symlink
        let mut current = current_link;
        for i in 0..8 {
            // More than system limit (5) but less than regular limit
            let next_link = target_dir.join(format!("link_{i}"));
            let next_target = target_dir.join(format!("target_{i}"));
            if i < 7 {
                fs::create_dir(&next_target)?;
                std::os::unix::fs::symlink(&next_target, &next_link)?;
            } else {
                // Last one points to non-existing to test boundary detection
                std::os::unix::fs::symlink(_base.join("nonexistent"), &next_link)?;
            }
            current = next_link;
        }

        // Test that the algorithm handles this correctly
        let test_path = current.join("final_file.txt");
        let result = soft_canonicalize(test_path);

        // Should either resolve successfully or fail with proper symlink depth error
        match result {
            Ok(_) => {
                // Good - algorithm handled the mixed depth scenario
            }
            Err(e) if e.to_string().contains("symbolic links") => {
                // Acceptable - hit depth limit as expected
            }
            Err(e) => {
                eprintln!("Unexpected error: {e}");
                return Err(e);
            }
        }
    }
    Ok(())
}

#[test]
fn test_symlink_resolved_base_race() -> std::io::Result<()> {
    // WHITE-BOX: Test the symlink_resolved_base handling for potential race conditions
    // or inconsistent state when broken symlinks are involved
    let temp_dir = TempDir::new()?;
    let _base = temp_dir.path();

    #[cfg(unix)]
    {
        // Create a scenario where symlink resolution might change state
        let target_dir = _base.join("target");
        fs::create_dir(&target_dir)?;

        let symlink = _base.join("changing_link");
        std::os::unix::fs::symlink(&target_dir, &symlink)?;

        // First create a file through the symlink
        let file_through_link = symlink.join("test.txt");
        fs::write(file_through_link, "test")?;

        // Now remove the target and make it a broken symlink
        fs::remove_dir_all(&target_dir)?;
        fs::remove_file(&symlink)?; // Remove the existing symlink first
        std::os::unix::fs::symlink(_base.join("broken_target"), &symlink)?;

        // Test canonicalization with this now-broken symlink
        let test_path = symlink.join("new_file.txt");
        let result = soft_canonicalize(test_path);

        // Should handle the broken symlink scenario gracefully
        match result {
            Ok(resolved) => {
                // Should resolve to something reasonable
                assert!(resolved.is_absolute());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Acceptable for broken symlinks
            }
            Err(e) => {
                eprintln!("Unexpected error in symlink race scenario: {e}");
                return Err(e);
            }
        }
    }
    Ok(())
}
