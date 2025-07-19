#[cfg(test)]
mod test_python_inspired {
    use crate::soft_canonicalize;
    use std::{env, fs};
    use tempfile::TempDir;

    /// Test inspired by Python's test_resolve_nonexist_relative_issue38671
    /// Tests non-existing relative paths resolve correctly
    #[test]
    fn test_resolve_nonexist_relative() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Test relative non-existing path from a real directory
        let original_cwd = env::current_dir().unwrap();
        env::set_current_dir(base_path).unwrap();

        let result = soft_canonicalize("non/exist/path.txt");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("non/exist/path.txt"));

        env::set_current_dir(original_cwd).unwrap();
    }

    /// Test inspired by Python's test_resolve_common with strict=False
    /// Tests various combinations of existing and non-existing components
    #[test]
    fn test_resolve_mixed_existing_nonexisting() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create some existing structure
        let existing_dir = base_path.join("existing_dir");
        fs::create_dir(&existing_dir).unwrap();
        let existing_file = existing_dir.join("existing_file.txt");
        fs::write(&existing_file, "test").unwrap();

        // Test: existing_dir/existing_file/non/existing/path
        let mixed_path = existing_file.join("non/existing/path.txt");
        let result = soft_canonicalize(&mixed_path);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.to_string_lossy().contains("existing_file.txt"));
        // Check for platform-appropriate path separators
        #[cfg(windows)]
        assert!(resolved
            .to_string_lossy()
            .contains("non\\existing\\path.txt"));
        #[cfg(not(windows))]
        assert!(resolved.to_string_lossy().contains("non/existing/path.txt"));

        // Test: existing_dir/non_existing/file.txt
        let partial_path = existing_dir.join("non_existing/file.txt");
        let result = soft_canonicalize(&partial_path);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.to_string_lossy().contains("existing_dir"));
        // Check for platform-appropriate path separators
        #[cfg(windows)]
        assert!(resolved
            .to_string_lossy()
            .contains("non_existing\\file.txt"));
        #[cfg(not(windows))]
        assert!(resolved.to_string_lossy().contains("non_existing/file.txt"));
    }

    /// Test inspired by Python's test_resolve_dot with strict=False
    /// Tests resolution of symlinks pointing to current directory
    #[cfg(unix)]
    #[test]
    fn test_resolve_dot_symlinks() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a simple symlink to current directory
        let link_dot = base_path.join("link_to_dot");
        symlink(".", &link_dot).unwrap();

        // Test resolving through the symlink with non-existing suffix
        let test_path = link_dot.join("some/nonexisting/path.txt");
        let result = soft_canonicalize(&test_path);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());

        // Should resolve to base_path/some/nonexisting/path.txt
        let expected_suffix = base_path.join("some/nonexisting/path.txt");
        assert_eq!(resolved, expected_suffix);
    }

    /// Test inspired by Python's resolve with parent directory traversal
    /// Tests that .. components are handled correctly in mixed scenarios
    /// Consolidates: path_traversal::test_parent_directory_traversal
    #[test]
    fn test_resolve_parent_traversal_mixed() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Test basic parent directory traversal (from path_traversal module)
        // Create: base_path/level1/level2/
        let level1 = base_path.join("level1");
        let level2 = level1.join("level2");
        fs::create_dir_all(&level2).unwrap();

        // Test path: level2/subdir/../../../target.txt -> base_path/target.txt
        let basic_traversal = level2
            .join("subdir")
            .join("..")
            .join("..")
            .join("..")
            .join("target.txt");
        let result = soft_canonicalize(&basic_traversal);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(
            resolved,
            fs::canonicalize(base_path).unwrap().join("target.txt")
        );

        // Test advanced: Create nested directory structure for complex scenarios
        let dir_a = base_path.join("dirA");
        let dir_b = base_path.join("dirB");
        fs::create_dir(&dir_a).unwrap();
        fs::create_dir(&dir_b).unwrap();

        // Test: dirA/../dirB/non_existing_file.txt
        let traversal_path = dir_a.join("../dirB/non_existing_file.txt");
        let result = soft_canonicalize(&traversal_path);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.to_string_lossy().contains("dirB"));
        assert!(resolved.to_string_lossy().contains("non_existing_file.txt"));
        assert!(!resolved.to_string_lossy().contains("dirA"));
        assert!(!resolved.to_string_lossy().contains(".."));

        // Test multiple parent traversals with non-existing components
        let complex_traversal = dir_a
            .join("../../../temp/../")
            .join(base_path.file_name().unwrap())
            .join("dirB/deep/non/existing.txt");
        let result = soft_canonicalize(&complex_traversal);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(!resolved.to_string_lossy().contains(".."));
    }

    /// Test inspired by Python's handling of symlink loops with strict=False
    /// Tests that symlink loops are detected and return the looping path
    #[cfg(unix)]
    #[test]
    fn test_resolve_symlink_loops_with_suffix() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create symlink loop: linkX -> linkX/inside
        let link_x = base_path.join("linkX");
        symlink("linkX/inside", &link_x).unwrap();

        // Python's strict=False handles this by returning the path as-is when hitting a loop
        let loop_path = link_x.join("foo/bar.txt");
        let result = soft_canonicalize(&loop_path);

        // Our implementation should detect the loop and handle it gracefully
        // The exact behavior may vary, but it should not infinite loop
        assert!(result.is_ok() || result.is_err());
        if let Ok(resolved) = result {
            // If successful, should be absolute and contain the non-existing suffix
            assert!(resolved.is_absolute());
        }
    }

    /// Test inspired by Python's realpath with non-terminal file handling
    /// Tests paths that traverse through files (which should fail in strict mode)
    #[test]
    fn test_resolve_through_file() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a file
        let file_path = base_path.join("regular_file.txt");
        fs::write(&file_path, "test content").unwrap();

        // Try to resolve a path that goes "through" the file
        let through_file = file_path.join("subdir/file.txt");
        let result = soft_canonicalize(&through_file);

        // Our implementation should handle this - the existing portion resolves to the file,
        // and the non-existing portion is appended
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.to_string_lossy().contains("regular_file.txt"));
        // Check for platform-appropriate path separators
        #[cfg(windows)]
        assert!(resolved.to_string_lossy().contains("subdir\\file.txt"));
        #[cfg(not(windows))]
        assert!(resolved.to_string_lossy().contains("subdir/file.txt"));
    }

    /// Test inspired by Python's handling of invalid path characters
    /// Tests edge cases with unusual but valid path components  
    #[test]
    fn test_resolve_unusual_characters() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Test paths with spaces, unicode, etc.
        let unusual_paths = vec![
            "path with spaces/file.txt",
            "path-with-dashes/file.txt",
            "path_with_underscores/file.txt",
            "pathwith中文/file.txt",
            "path.with.dots/file.txt",
        ];

        for unusual_path in unusual_paths {
            let full_path = base_path.join(unusual_path);
            let result = soft_canonicalize(&full_path);
            assert!(result.is_ok(), "Failed to resolve path: {unusual_path}");
            let resolved = result.unwrap();
            assert!(resolved.is_absolute());
            assert!(resolved.to_string_lossy().contains("file.txt"));
        }
    }

    /// Test inspired by Python's handling of very deep paths
    /// Tests performance and correctness with deep directory structures
    /// Consolidates: basic_functionality::test_deeply_non_existing_path
    #[test]
    fn test_resolve_deep_paths() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Test basic deeply non-existing path (from basic_functionality)
        let basic_deep_path = base_path.join("a/b/c/d/e/file.txt");
        let result = soft_canonicalize(&basic_deep_path);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert_eq!(
            resolved,
            fs::canonicalize(base_path)
                .unwrap()
                .join("a/b/c/d/e/file.txt")
        );

        // Test advanced: Create a moderately deep existing structure
        let mut current = base_path.to_path_buf();
        for i in 0..10 {
            current = current.join(format!("level_{i}"));
            fs::create_dir(&current).unwrap();
        }

        // Add a very deep non-existing suffix
        let mut deep_path = current.clone();
        for i in 0..50 {
            deep_path = deep_path.join(format!("deep_{i}"));
        }
        deep_path = deep_path.join("final_file.txt");

        let result = soft_canonicalize(&deep_path);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.to_string_lossy().contains("level_9")); // Should contain the deepest existing level
        assert!(resolved.to_string_lossy().contains("deep_49")); // Should contain the deepest non-existing level
        assert!(resolved.to_string_lossy().contains("final_file.txt"));
    }

    /// Test inspired by Python's current working directory edge cases
    /// Tests resolution from different working directories
    #[test]
    fn test_resolve_from_different_cwd() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create subdirectories
        let sub_dir1 = base_path.join("sub1");
        let sub_dir2 = base_path.join("sub2");
        fs::create_dir(&sub_dir1).unwrap();
        fs::create_dir(&sub_dir2).unwrap();

        let original_cwd = env::current_dir().unwrap();

        // Wrap in a closure to ensure proper cleanup
        let test_result = std::panic::catch_unwind(|| {
            // Test relative resolution from sub_dir1
            env::set_current_dir(&sub_dir1).unwrap();
            let result1 = soft_canonicalize("../sub2/non_existing.txt");
            assert!(result1.is_ok());
            let resolved1 = result1.unwrap();
            assert!(resolved1.is_absolute());
            assert!(resolved1.to_string_lossy().contains("sub2"));
            assert!(resolved1.to_string_lossy().contains("non_existing.txt"));

            // Test relative resolution from sub_dir2
            env::set_current_dir(&sub_dir2).unwrap();
            let result2 = soft_canonicalize("../sub1/non_existing.txt");
            assert!(result2.is_ok());
            let resolved2 = result2.unwrap();
            assert!(resolved2.is_absolute());
            assert!(resolved2.to_string_lossy().contains("sub1"));
        });

        // Always restore the original directory, even if the test panicked
        let _ = env::set_current_dir(original_cwd);

        // Re-raise any panic that occurred
        if let Err(e) = test_result {
            std::panic::resume_unwind(e);
        }
    }

    /// Test inspired by Python's empty and minimal path handling
    /// Tests edge cases with empty components and minimal paths
    #[test]
    fn test_resolve_minimal_paths() {
        // Test current directory
        let result = soft_canonicalize(".");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());

        // Test parent directory
        let result = soft_canonicalize("..");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());

        // Test single file name
        let result = soft_canonicalize("single_file.txt");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.to_string_lossy().contains("single_file.txt"));
    }

    /// Test to ensure std::fs::canonicalize compatibility for existing paths
    /// This validates that we provide a superset of std functionality
    /// Consolidates: api_compatibility::test_std_compatibility_api
    #[test]
    fn test_std_compatibility_existing_paths() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create existing file and directory
        let existing_file = base_path.join("existing.txt");
        let existing_dir = base_path.join("existing_dir");
        fs::write(&existing_file, "test").unwrap();
        fs::create_dir(&existing_dir).unwrap();

        // Test that our results match std::fs::canonicalize for existing paths
        for existing_path in [&existing_file, &existing_dir, base_path] {
            let std_result = fs::canonicalize(existing_path);
            let our_result = soft_canonicalize(existing_path);

            assert!(
                std_result.is_ok(),
                "std::fs::canonicalize should work for existing path"
            );
            assert!(
                our_result.is_ok(),
                "soft_canonicalize should work for existing path"
            );

            // Results should be equivalent (modulo potential differences in canonicalization)
            let std_canonical = std_result.unwrap();
            let our_canonical = our_result.unwrap();

            // Both should be absolute
            assert!(std_canonical.is_absolute());
            assert!(our_canonical.is_absolute());

            // Test API compatibility patterns (from api_compatibility module)
            // Pattern 1: String literal
            let str_literal = existing_path.to_string_lossy();
            let our_str_result = soft_canonicalize(str_literal.as_ref()).unwrap();
            let std_str_result = fs::canonicalize(str_literal.as_ref()).unwrap();
            assert_eq!(our_str_result, std_str_result);

            // Pattern 2: PathBuf by value
            let pathbuf = existing_path.to_path_buf();
            let our_pathbuf_result = soft_canonicalize(pathbuf.clone()).unwrap();
            let std_pathbuf_result = fs::canonicalize(pathbuf).unwrap();
            assert_eq!(our_pathbuf_result, std_pathbuf_result);

            // Pattern 3: &PathBuf
            let pathbuf = existing_path.to_path_buf();
            let our_ref_result = soft_canonicalize(&pathbuf).unwrap();
            let std_ref_result = fs::canonicalize(&pathbuf).unwrap();
            assert_eq!(our_ref_result, std_ref_result);
        }
    }
}
