//! Direct test of 8.3 short name expansion without symlinks
//! This tests whether the basic 8.3 expansion works on this system

#[cfg(windows)]
mod windows_direct_8_3_test {
    use soft_canonicalize::soft_canonicalize;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// Get the actual Windows 8.3 short path name using FFI
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

        let required_len =
            unsafe { GetShortPathNameW(wide_path.as_ptr(), std::ptr::null_mut(), 0) };

        if required_len == 0 {
            return None;
        }

        let mut buffer = vec![0u16; required_len as usize];
        let result_len =
            unsafe { GetShortPathNameW(wide_path.as_ptr(), buffer.as_mut_ptr(), required_len) };

        if result_len == 0 || result_len >= required_len {
            return None;
        }

        buffer.truncate(result_len as usize);
        Some(PathBuf::from(OsString::from_wide(&buffer)))
    }

    #[cfg(feature = "anchored")]
    #[test]
    fn test_8_3_first_component_with_anchor_clamp() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let anchor = temp_dir.path().join("root").join("sub");
        fs::create_dir_all(&anchor)?;
        // Use soft_canonicalize to ensure extended-length absolute anchor on Windows
        let abs_anchor = soft_canonicalize(&anchor)?;

        // Inside the anchor, create a long-named directory that likely gets an 8.3 alias
        let long_dir = abs_anchor.join("VeryLongDirectoryNameThatExceedsEightCharacters");
        fs::create_dir(&long_dir)?;

        // Query the actual short path and extract just the last component (e.g., "VERYLO~1")
        let short_full = match get_short_path_name(&long_dir) {
            Some(s) => s,
            None => {
                eprintln!(
                    "SKIP: Could not get 8.3 short name for first component (may be disabled)"
                );
                return Ok(());
            }
        };
        if short_full == long_dir {
            eprintln!("SKIP: 8.3 generation disabled (short == long)");
            return Ok(());
        }
        let short_name = match short_full.file_name() {
            Some(s) => s.to_string_lossy().into_owned(),
            None => {
                eprintln!("SKIP: Could not extract short name component");
                return Ok(());
            }
        };

        // Build an input that starts with the short name and then tries to escape via `..\\..`
        // Expected behavior: traversal is clamped to the anchor, yielding anchor\\etc\\passwd
        let input = format!(r"{}\\..\\..\\etc\\passwd", short_name);
        let out = soft_canonicalize::anchored_canonicalize(&abs_anchor, input)?;

        // Exact expectation under Windows: absolute (extended-length) anchor joined with etc\\passwd
        let expected = abs_anchor.join(r"etc\passwd");
        assert!(out.is_absolute());
        assert_eq!(
            out, expected,
            "Result must clamp to anchor and ignore escape attempts"
        );

        Ok(())
    }

    #[test]
    fn test_actual_8_3_expansion_existing_path() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a directory with a long name
        let long_dir = base.join("VeryLongDirectoryNameThatExceedsEightCharacters");
        fs::create_dir(&long_dir)?;

        // Create a file inside
        let long_file = long_dir.join("file.txt");
        fs::write(long_file, b"test")?;

        // Try to get the 8.3 short name
        let short_dir = match get_short_path_name(&long_dir) {
            Some(s) => s,
            None => {
                eprintln!("SKIP: Could not get 8.3 short name (may be disabled on this system)");
                return Ok(());
            }
        };

        println!("\n=== Testing ACTUAL 8.3 short name expansion ===");
        println!("Long name:  {}", long_dir.display());
        println!("Short name: {}", short_dir.display());

        // Verify we got a different short name
        if short_dir == long_dir {
            eprintln!("SKIP: Short name equals long name (8.3 generation disabled)");
            return Ok(());
        }

        // Test accessing via SHORT name
        let short_file = short_dir.join("file.txt");
        println!("\nAccessing file via short name: {}", short_file.display());

        // Test our canonicalization
        let our_result = soft_canonicalize(&short_file)?;
        println!("soft_canonicalize:  {}", our_result.display());

        // Test std::fs::canonicalize (the gold standard)
        let std_result = fs::canonicalize(&short_file)?;
        println!("std::fs::canonicalize: {}", std_result.display());

        // CRITICAL TEST: They must match for existing paths
        assert_eq!(
            our_result,
            std_result,
            "\n❌ FAILURE: Results don't match!\n\
             This indicates 8.3 short name expansion is broken!\n\
             soft_canonicalize:  {}\n\
             std::fs::canonicalize: {}",
            our_result.display(),
            std_result.display()
        );

        println!("\n✅ SUCCESS: 8.3 short names are properly expanded!");
        println!("   soft_canonicalize matches std::fs::canonicalize");

        Ok(())
    }

    #[test]
    fn test_actual_8_3_with_nonexisting_suffix() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a directory with a long name
        let long_dir = base.join("AnotherVeryLongDirectoryName");
        fs::create_dir(&long_dir)?;

        // Get its 8.3 short name
        let short_dir = match get_short_path_name(&long_dir) {
            Some(s) => s,
            None => {
                eprintln!("SKIP: Could not get 8.3 short name");
                return Ok(());
            }
        };

        if short_dir == long_dir {
            eprintln!("SKIP: 8.3 generation disabled");
            return Ok(());
        }

        println!("\n=== Testing 8.3 with NON-EXISTING suffix ===");
        println!("Long dir:  {}", long_dir.display());
        println!("Short dir: {}", short_dir.display());

        // Access via short name with NON-EXISTING suffix
        let test_path = short_dir.join("nonexisting").join("file.txt");
        println!("\nTest path (via short name): {}", test_path.display());

        let our_result = soft_canonicalize(&test_path)?;
        println!("soft_canonicalize result: {}", our_result.display());

        // For the EXISTING portion (just the directory), compare with std
        let std_result = fs::canonicalize(&short_dir)?;
        println!(
            "std::fs::canonicalize (existing dir): {}",
            std_result.display()
        );

        // The result should start with the canonicalized directory
        assert!(
            our_result.starts_with(&std_result),
            "\n❌ FAILURE: Result doesn't start with canonicalized directory!\n\
             soft_canonicalize:  {}\n\
             Expected to start with: {}",
            our_result.display(),
            std_result.display()
        );

        println!("✅ SUCCESS: Existing 8.3 portion expanded, non-existing suffix appended");

        Ok(())
    }

    #[test]
    fn test_nested_8_3_paths() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create nested long-named directories
        let long_dir1 = base.join("FirstVeryLongDirectoryName");
        fs::create_dir(&long_dir1)?;

        let long_dir2 = long_dir1.join("SecondVeryLongDirectoryName");
        fs::create_dir(&long_dir2)?;

        let file_path = long_dir2.join("testfile.txt");
        fs::write(&file_path, b"content")?;

        // Get short names for both
        let short_dir1 = match get_short_path_name(&long_dir1) {
            Some(s) => s,
            None => {
                eprintln!("SKIP: Could not get 8.3 short names");
                return Ok(());
            }
        };

        if short_dir1 == long_dir1 {
            eprintln!("SKIP: 8.3 disabled");
            return Ok(());
        }

        let short_dir2_relative = match get_short_path_name(&long_dir2) {
            Some(s) => s,
            None => {
                eprintln!("SKIP: Could not get nested 8.3 short name");
                return Ok(());
            }
        };

        println!("\n=== Testing NESTED 8.3 short names ===");
        println!("Long path:  {}", file_path.display());

        // Build path using short names
        let short_dir2_name = short_dir2_relative.file_name().unwrap();
        let short_path = short_dir1.join(short_dir2_name).join("testfile.txt");
        println!("Short path: {}", short_path.display());

        // Test our canonicalization
        let our_result = soft_canonicalize(&short_path)?;
        println!("soft_canonicalize:  {}", our_result.display());

        // Test std (gold standard)
        let std_result = fs::canonicalize(&short_path)?;
        println!("std::fs::canonicalize: {}", std_result.display());

        // MUST match
        assert_eq!(
            our_result,
            std_result,
            "\n❌ FAILURE: Nested 8.3 paths don't match!\n\
             soft_canonicalize:  {}\n\
             std::fs::canonicalize: {}",
            our_result.display(),
            std_result.display()
        );

        println!("✅ SUCCESS: Nested 8.3 short names properly expanded!");

        Ok(())
    }
}

#[cfg(not(windows))]
mod non_windows {
    #[test]
    fn placeholder() {
        println!("These are Windows-specific 8.3 tests");
    }
}
