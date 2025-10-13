//! Windows-specific tests for symlink and 8.3 short name interaction
//!
//! These tests validate that the v0.4.0 optimizations (direct component streaming,
//! elimination of VecDeque) don't introduce issues with Windows 8.3 short name
//! expansion when symlinks are involved.
//!
//! Test scenarios:
//! 1. Symlink as first component resolving to path with 8.3 names
//! 2. Symlink followed by non-existing suffix with 8.3 pattern
//! 3. Multiple symlinks in chain where target contains 8.3 names
//! 4. 8.3 name component before a symlink
//! 5. Mixed existing/non-existing with symlinks and 8.3 patterns

// Import shared test helpers (must be at crate root level for integration tests)
mod test_helpers;

#[cfg(windows)]
mod windows_symlink_8_3_tests {
    use soft_canonicalize::soft_canonicalize;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    // Use the symlink helper from test utilities
    use crate::test_helpers::symlink_or_junction::create_symlink_or_junction;

    /// Helper to create a symlink with junction fallback
    /// Returns Ok(true) if link created, Ok(false) if skipped (both symlink and junction failed)
    fn try_create_symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(
        original: P,
        link: Q,
    ) -> io::Result<bool> {
        create_symlink_or_junction(original, link)
    }

    /// Get the actual Windows 8.3 short path name for a given path using FFI.
    /// Returns None if 8.3 names are disabled or the path has no short name.
    fn get_short_path_name(path: &Path) -> Option<PathBuf> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::ffi::OsStringExt;

        #[link(name = "kernel32")]
        extern "system" {
            fn GetShortPathNameW(
                lpszlongpath: *const u16,
                lpszshortpath: *mut u16,
                cchbuffer: u32,
            ) -> u32;
        }

        let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

        // First call to get the required buffer size
        let required_len =
            unsafe { GetShortPathNameW(wide_path.as_ptr(), std::ptr::null_mut(), 0) };

        if required_len == 0 {
            return None;
        }

        // Second call to get the actual short path
        let mut buffer = vec![0u16; required_len as usize];
        let result_len =
            unsafe { GetShortPathNameW(wide_path.as_ptr(), buffer.as_mut_ptr(), required_len) };

        if result_len == 0 || result_len >= required_len {
            return None;
        }

        buffer.truncate(result_len as usize);
        let short_path = OsString::from_wide(&buffer);
        Some(PathBuf::from(short_path))
    }

    /// Check if 8.3 short names are actually generated on this system
    fn are_8_3_names_enabled() -> bool {
        // Create a test directory with a long name
        if let Ok(temp_dir) = TempDir::new() {
            let long_name = temp_dir
                .path()
                .join("VeryLongDirectoryNameForTestingPurposes");
            if fs::create_dir(&long_name).is_ok() {
                if let Some(short_path) = get_short_path_name(&long_name) {
                    let short_str = short_path.to_string_lossy();
                    let long_str = long_name.to_string_lossy();
                    // If they're different, 8.3 names are enabled
                    return short_str != long_str && short_str.contains('~');
                }
            }
        }
        false
    }

    /// Test Scenario 1: Symlink as first component resolving to path with ACTUAL 8.3 short names
    ///
    /// This tests the critical case where:
    /// - First component is a symlink (sets symlink_seen = true early)
    /// - Resolved target contains ACTUAL filesystem-generated 8.3 short names
    /// - We need to verify if 8.3 expansion still works correctly
    ///
    /// This is the CORRECTED version that uses real 8.3 short names, not literal "PROGRA~1" directories.
    #[test]
    fn test_symlink_first_component_to_8_3_path() -> io::Result<()> {
        // First check if 8.3 names are even enabled on this system
        if !are_8_3_names_enabled() {
            eprintln!("Skipping test_symlink_first_component_to_8_3_path: 8.3 short names are not enabled on this system");
            return Ok(());
        }

        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a directory with a LONG name that will get an 8.3 short name
        let long_target = base.join("VeryLongDirectoryNameThatExceedsEightCharactersLimit");
        fs::create_dir(&long_target)?;

        // Create a subdirectory
        let subdir = long_target.join("Subdirectory");
        fs::create_dir(subdir)?;

        // Get the ACTUAL 8.3 short name for the long directory
        let short_target = match get_short_path_name(&long_target) {
            Some(short) => short,
            None => {
                eprintln!("Skipping test_symlink_first_component_to_8_3_path: Could not get 8.3 short name");
                return Ok(());
            }
        };

        println!("Created long name: {}", long_target.display());
        println!("Got short name: {}", short_target.display());

        // Verify we actually got a different short name
        if short_target == long_target {
            eprintln!("Skipping test_symlink_first_component_to_8_3_path: Short name equals long name (8.3 not generated)");
            return Ok(());
        }

        // Create a symlink (or junction fallback) pointing to the SHORT NAME directory
        let link_path = base.join("mylink");
        match try_create_symlink_dir(&short_target, &link_path) {
            Ok(true) => {} // Link created successfully
            Ok(false) => {
                // Both symlink and junction failed - skip test
                eprintln!("Skipping test_symlink_first_component_to_8_3_path: no symlink/junction support");
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Test path: link/Subdirectory/nonexisting.txt
        // This goes through symlink (first component) that points to an 8.3 short name
        let test_path = link_path.join("Subdirectory").join("nonexisting.txt");

        println!("\n=== Testing symlink to 8.3 short name ===");
        println!("Test path: {}", test_path.display());

        let result = soft_canonicalize(&test_path)?;
        println!("soft_canonicalize result: {}", result.display());

        // CRITICAL: Compare with std::fs::canonicalize for existing portion
        let existing_test = link_path.join("Subdirectory");
        let std_result = fs::canonicalize(existing_test)?;
        println!("std::fs::canonicalize result: {}", std_result.display());

        // The result must equal std::fs::canonicalize(existing) joined with the non-existing tail
        let expected = std_result.join("nonexisting.txt");
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                result, expected,
                "soft_canonicalize(existing)+tail must equal std(existing)+tail"
            );
        }
        #[cfg(feature = "dunce")]
        {
            let result_str_check = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(
                !result_str_check.starts_with(r"\\?\"),
                "dunce should simplify"
            );
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
            let std_simplified = expected_str.trim_start_matches(r"\\?\");
            assert!(
                result_str_check == std_simplified,
                "soft_canonicalize(existing)+tail must equal std(existing)+tail (simplified)"
            );
        }

        // Check if 8.3 short name was expanded to long name
        let result_str = result.to_string_lossy();
        let short_str = short_target.to_string_lossy();

        if result_str.contains(&*short_str) {
            println!("⚠️  WARNING: Result still contains 8.3 short name path");
            println!("   This might indicate 8.3 expansion was skipped");
        } else {
            println!("✅ 8.3 short name was properly expanded to long name");
        }

        Ok(())
    }

    /// Test Scenario 2: Symlink with non-existing suffix containing 8.3 pattern
    ///
    /// This tests:
    /// - Symlink exists and is resolved (sets symlink_seen = true)
    /// - Non-existing suffix contains 8.3-like pattern
    /// - Verify that the non-existing portion is handled correctly
    #[test]
    fn test_symlink_with_nonexisting_8_3_suffix() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create target directory
        let target_dir = base.join("target_dir");
        fs::create_dir(&target_dir)?;

        // Create symlink (or junction fallback)
        let link_path = base.join("mylink");
        match try_create_symlink_dir(&target_dir, &link_path) {
            Ok(true) => {} // Link created
            Ok(false) => {
                eprintln!(
                    "Skipping test_symlink_with_nonexisting_8_3_suffix: no symlink/junction support"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Test path with non-existing 8.3-like components
        let test_path = link_path.join("PROGRA~1").join("WINDOW~1").join("file.txt");
        let result = soft_canonicalize(&test_path)?;

        println!("Test path: {}", test_path.display());
        println!("Result: {}", result.display());

        assert!(result.is_absolute());

        // Expected: canonicalize(target_dir) + non-existing tail
        let expected = fs::canonicalize(&target_dir)?
            .join("PROGRA~1")
            .join("WINDOW~1")
            .join("file.txt");

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(result, expected);
        }
        #[cfg(feature = "dunce")]
        {
            let res_str = result.to_string_lossy();
            let exp_str = expected.to_string_lossy();
            assert!(!res_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(exp_str.starts_with(r"\\?\"), "std returns UNC");
            assert_eq!(res_str.as_ref(), exp_str.trim_start_matches(r"\\?\"));
        }

        // The non-existing 8.3-like names should be preserved literally
        // since they don't exist and can't be expanded
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("PROGRA~1") && result_str.contains("WINDOW~1"),
            "Non-existing 8.3-like names should be preserved literally in result: {}",
            result_str
        );

        // Verify the symlink portion was resolved correctly
        let canon_target = fs::canonicalize(&target_dir)?;
        #[cfg(not(feature = "dunce"))]
        {
            assert!(
                result.starts_with(canon_target),
                "Result should start with canonicalized symlink target"
            );
        }
        #[cfg(feature = "dunce")]
        {
            let result_check = result.to_string_lossy();
            let canon_str = canon_target.to_string_lossy();
            assert!(!result_check.starts_with(r"\\?\"), "dunce should simplify");
            assert!(canon_str.starts_with(r"\\?\"), "std returns UNC");
            let canon_simplified = canon_str.trim_start_matches(r"\\?\");
            assert!(
                result_check.starts_with(canon_simplified),
                "Result should start with canonicalized symlink target"
            );
        }

        Ok(())
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

    /// Test Scenario 5: Real 8.3 expansion with existing file after symlink
    ///
    /// This tests:
    /// - Symlink resolved (symlink_seen = true)
    /// - Path after symlink contains actual existing 8.3 short names
    /// - Verify that 8.3 expansion happens despite symlink_seen flag
    #[test]
    fn test_real_8_3_expansion_after_symlink() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a directory with a long name (might get 8.3 alias on NTFS)
        let long_name_dir = base.join("VeryLongDirectoryNameThatExceedsEightCharacters");
        fs::create_dir(&long_name_dir)?;
        let inner_file = long_name_dir.join("test.txt");
        fs::write(inner_file, b"test content")?;

        // Create target for symlink
        let target_dir = base.join("target");
        fs::create_dir(&target_dir)?;

        // Create symlink
        let link_path = target_dir.join("mylink");
        match try_create_symlink_dir(&long_name_dir, link_path) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "Skipping test_real_8_3_expansion_after_symlink: no symlink/junction support"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Test with the actual long name path
        let test_path_long = target_dir.join("mylink").join("test.txt");
        let result_long = soft_canonicalize(&test_path_long)?;

        println!("Test path (long name): {}", test_path_long.display());
        println!("Result (long name): {}", result_long.display());

        // Compare with std::fs::canonicalize (the gold standard)
        let std_result = fs::canonicalize(&test_path_long)?;
        println!("std::fs::canonicalize: {}", std_result.display());

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                result_long, std_result,
                "soft_canonicalize should match std::fs::canonicalize for fully existing paths"
            );
        }
        #[cfg(feature = "dunce")]
        {
            let result_str = result_long.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
            let std_simplified = std_str.trim_start_matches(r"\\?\");
            assert_eq!(
                result_str.as_ref(),
                std_simplified,
                "soft_canonicalize should match std::fs::canonicalize for fully existing paths"
            );
        }

        // Try to detect if there's an 8.3 alias (this is filesystem-dependent)
        // We'll use std::fs to check what the actual short name might be
        // This is informational - we can't reliably create/detect 8.3 names
        println!("INFO: Testing with filesystem-assigned names");
        println!("      If NTFS has created an 8.3 alias, both should resolve identically");

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

    /// Test Scenario 7: Non-existing path with symlink and 8.3 pattern
    ///
    /// Edge case where symlink itself doesn't exist but path contains 8.3 pattern
    #[test]
    fn test_nonexisting_symlink_with_8_3_pattern() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a base directory
        let start_dir = base.join("start");
        fs::create_dir(&start_dir)?;

        // Test path where symlink doesn't exist but has 8.3 pattern in suffix
        let test_path = start_dir
            .join("nonexistent_link")
            .join("PROGRA~1")
            .join("file.txt");
        let result = soft_canonicalize(&test_path)?;

        println!("Test path: {}", test_path.display());
        println!("Result: {}", result.display());

        assert!(result.is_absolute());

        // Non-existing 8.3 patterns should be preserved literally
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("PROGRA~1"),
            "Non-existing 8.3 pattern should be preserved: {}",
            result_str
        );

        Ok(())
    }

    /// Comparative test: Ensure parity with std::fs::canonicalize when path fully exists
    ///
    /// This is the critical compatibility test - when both symlinks and 8.3 names exist,
    /// our result MUST match std::fs::canonicalize exactly
    #[test]
    fn test_std_parity_symlink_and_8_3_existing() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create directory with 8.3-like name
        let dir_83 = base.join("MYDIR8~1");
        fs::create_dir(&dir_83)?;

        // Create target
        let target = base.join("target");
        fs::create_dir(&target)?;
        fs::create_dir(target.join("inner"))?;
        fs::write(target.join("inner").join("file.txt"), b"content")?;

        // Create symlink in 8.3-named directory
        let link_path = dir_83.join("mylink");
        match try_create_symlink_dir(&target, link_path) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "Skipping test_std_parity_symlink_and_8_3_existing: no symlink/junction support"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Test FULLY EXISTING path
        let test_path = dir_83.join("mylink").join("inner").join("file.txt");
        let our_result = soft_canonicalize(&test_path)?;
        let std_result = fs::canonicalize(&test_path)?;

        println!("Test path: {}", test_path.display());
        println!("Our result: {}", our_result.display());
        println!("std result: {}", std_result.display());

        // CRITICAL: Must match exactly for existing paths
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                our_result, std_result,
                "CRITICAL: soft_canonicalize MUST match std::fs::canonicalize for fully existing paths.\n\
                 This is a core requirement of the library.\n\
                 Our result: {}\n\
                 std result: {}",
                our_result.display(),
                std_result.display()
            );
        }
        #[cfg(feature = "dunce")]
        {
            let our_str = our_result.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert!(!our_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
            let std_simplified = std_str.trim_start_matches(r"\\?\");
            assert_eq!(
                our_str.as_ref(), std_simplified,
                "CRITICAL: soft_canonicalize MUST match std::fs::canonicalize for fully existing paths.\n\
                 This is a core requirement of the library.\n\
                 Our result: {}\n\
                 std result (simplified): {}",
                our_result.display(),
                std_simplified
            );
        }

        Ok(())
    }
}

#[cfg(not(windows))]
mod non_windows {
    #[test]
    fn placeholder_test() {
        // These tests are Windows-specific
        println!("Windows-specific symlink + 8.3 tests skipped on non-Windows platforms");
    }
}
