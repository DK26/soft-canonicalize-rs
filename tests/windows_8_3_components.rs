//! Windows-specific tests: 8.3 short-name components interacting with symlinks
//!
//! Covers:
//! - Chain of symlinks where the final target directory has an 8.3-like name
//! - 8.3-like component appearing *before* a symlink in the path
//! - 8.3-like components on *both sides* of a symlink (around symlink)

// Import shared test helpers (must be at crate root level for integration tests)
mod test_helpers;

#[cfg(windows)]
mod windows_8_3_components_tests {
    use soft_canonicalize::soft_canonicalize;
    use std::fs;
    use std::io;
    use std::path::Path;
    use tempfile::TempDir;

    use crate::test_helpers::symlink_or_junction::create_symlink_or_junction;

    /// Helper to create a symlink with junction fallback.
    /// Returns Ok(true) if link created, Ok(false) if skipped (both symlink and junction failed).
    fn try_create_symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(
        original: P,
        link: Q,
    ) -> io::Result<bool> {
        create_symlink_or_junction(original, link)
    }

    /// Test Scenario 3: Chain of symlinks where final target contains 8.3 names
    ///
    /// This tests:
    /// - Multiple symlinks in the path (symlink_seen = true early)
    /// - Final resolution contains 8.3-like patterns
    /// - Verify proper handling through the entire chain
    #[test]
    fn test_chained_symlinks_with_8_3_target() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create target with 8.3-like name
        let final_target = base.join("LONGDI~1");
        fs::create_dir(&final_target)?;
        fs::create_dir(final_target.join("subdir"))?;

        // Create intermediate target
        let intermediate = base.join("intermediate");
        match try_create_symlink_dir(&final_target, &intermediate) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "Skipping test_chained_symlinks_with_8_3_target: no symlink/junction support"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Create first symlink pointing to intermediate
        let first_link = base.join("first_link");
        match try_create_symlink_dir(&intermediate, &first_link) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "Skipping test_chained_symlinks_with_8_3_target: no symlink/junction support"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Test path through the chain with non-existing suffix
        let test_path = first_link.join("subdir").join("file.txt");
        let result = soft_canonicalize(&test_path)?;

        println!("Test path: {}", test_path.display());
        println!("Result: {}", result.display());

        assert!(result.is_absolute());

        // Verify the existing portion matches std::fs::canonicalize
        let existing_check = first_link.join("subdir");
        if let Ok(std_canon) = fs::canonicalize(existing_check) {
            println!(
                "std::fs::canonicalize of existing portion: {}",
                std_canon.display()
            );
            #[cfg(not(feature = "dunce"))]
            {
                let expected = std_canon.join("file.txt");
                assert_eq!(
                    result, expected,
                    "Result must equal std(existing)+tail for non-existing suffix"
                );
            }
            #[cfg(feature = "dunce")]
            {
                let expected = std_canon.join("file.txt");
                let result_check = result.to_string_lossy();
                let expected_str = expected.to_string_lossy();
                assert!(!result_check.starts_with(r"\\?\"), "dunce should simplify");
                assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
                let expected_simplified = expected_str.trim_start_matches(r"\\?\");
                assert_eq!(
                    result_check, expected_simplified,
                    "Result must equal std(existing)+tail (simplified)"
                );
            }

            // Check if LONGDI~1 is expanded or preserved
            let std_str = std_canon.to_string_lossy();
            if std_str.contains("LONGDI~1") {
                println!(
                    "INFO: std::fs::canonicalize preserves 'LONGDI~1' (actual directory name)"
                );
            } else {
                println!("INFO: std::fs::canonicalize expanded or normalized 'LONGDI~1'");
            }
        }

        Ok(())
    }

    /// Test Scenario 4: 8.3-like component BEFORE a symlink
    ///
    /// This tests:
    /// - Path has 8.3-like name early in the path
    /// - Followed by a symlink component
    /// - Verify proper handling of this ordering
    #[test]
    fn test_8_3_component_before_symlink() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create directory with 8.3-like name
        let eight_three_dir = base.join("SHORTD~1");
        fs::create_dir(&eight_three_dir)?;

        // Create target for symlink
        let target_dir = base.join("target");
        fs::create_dir(&target_dir)?;
        fs::create_dir(target_dir.join("inner"))?;

        // Create symlink inside the 8.3-like directory
        let link_path = eight_three_dir.join("mylink");
        match try_create_symlink_dir(&target_dir, link_path) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "Skipping test_8_3_component_before_symlink: no symlink/junction support"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Test path: SHORTD~1/mylink/inner/file.txt
        let test_path = eight_three_dir
            .join("mylink")
            .join("inner")
            .join("file.txt");
        let result = soft_canonicalize(&test_path)?;

        println!("Test path: {}", test_path.display());
        println!("Result: {}", result.display());

        assert!(result.is_absolute());

        // Verify the existing portion is canonicalized correctly
        let existing_check = eight_three_dir.join("mylink").join("inner");
        if let Ok(std_canon) = fs::canonicalize(existing_check) {
            println!("std::fs::canonicalize result: {}", std_canon.display());
            #[cfg(not(feature = "dunce"))]
            {
                assert!(
                    result.starts_with(std_canon),
                    "Result should match std::fs::canonicalize for existing portion"
                );
            }
            #[cfg(feature = "dunce")]
            {
                let result_check = result.to_string_lossy();
                let std_str = std_canon.to_string_lossy();
                assert!(!result_check.starts_with(r"\\?\"), "dunce should simplify");
                assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
                let std_simplified = std_str.trim_start_matches(r"\\?\");
                assert!(
                    result_check.starts_with(std_simplified),
                    "Result should match std::fs::canonicalize for existing portion"
                );
            }
        }

        Ok(())
    }

    /// Test Scenario 6: Symlink in middle of path with 8.3 before and after
    ///
    /// This is a complex scenario:
    /// - Path: SHORTD~1/symlink/LONGDI~2/file.txt
    /// - Verify correct handling throughout
    #[test]
    fn test_8_3_around_symlink() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create first 8.3-like directory
        let first_83 = base.join("FIRST8~1");
        fs::create_dir(&first_83)?;

        // Create target with 8.3-like name
        let target_83 = base.join("TARGET~1");
        fs::create_dir(&target_83)?;
        fs::create_dir(target_83.join("SECOND~1"))?;

        // Create symlink in first directory pointing to target
        let link_path = first_83.join("mylink");
        match try_create_symlink_dir(&target_83, link_path) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("Skipping test_8_3_around_symlink: no symlink/junction support");
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Test path: FIRST8~1/mylink/SECOND~1/file.txt
        let test_path = first_83.join("mylink").join("SECOND~1").join("file.txt");
        let result = soft_canonicalize(&test_path)?;

        println!("Test path: {}", test_path.display());
        println!("Result: {}", result.display());

        assert!(result.is_absolute());

        // Compare existing portion with std::fs::canonicalize
        let existing_check = first_83.join("mylink").join("SECOND~1");
        if let Ok(std_canon) = fs::canonicalize(existing_check) {
            println!("std::fs::canonicalize result: {}", std_canon.display());
            #[cfg(not(feature = "dunce"))]
            {
                let expected = std_canon.join("file.txt");
                assert_eq!(
                    result, expected,
                    "Result must equal std(existing)+tail for non-existing suffix"
                );
            }
            #[cfg(feature = "dunce")]
            {
                let expected = std_canon.join("file.txt");
                let result_check = result.to_string_lossy();
                let expected_str = expected.to_string_lossy();
                assert!(!result_check.starts_with(r"\\?\"), "dunce should simplify");
                assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
                let expected_simplified = expected_str.trim_start_matches(r"\\?\");
                assert_eq!(
                    result_check, expected_simplified,
                    "Result must equal std(existing)+tail (simplified)"
                );
            }
        }

        Ok(())
    }
}

#[cfg(not(windows))]
mod non_windows {
    #[test]
    fn placeholder_test() {
        // These tests are Windows-specific
        println!("Windows-specific symlink + 8.3 component tests skipped on non-Windows platforms");
    }
}
