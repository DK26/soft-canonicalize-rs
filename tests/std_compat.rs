//! Tests adapted from Rust's std library canonicalize tests
//!
//! These tests ensure that soft_canonicalize behaves compatibly with std::fs::canonicalize
//! for existing paths, but handles non-existing paths gracefully.
//!
//! Feature-conditional testing:
//! - WITHOUT dunce: Verifies EXACT UNC format match with std::fs::canonicalize
//! - WITH dunce: Verifies simplified format (no \\?\ prefix when safe)

use soft_canonicalize::soft_canonicalize;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tempfile::{Builder, TempDir};

/// Helper to create a temporary directory for testing
fn tmpdir() -> TempDir {
    Builder::new()
        .prefix("soft_canonicalize_test")
        .tempdir()
        .unwrap()
}

/// Check if we have symlink permissions (mainly for Windows)
fn got_symlink_permission(tmpdir: &TempDir) -> bool {
    #[cfg(windows)]
    {
        let link = tmpdir.path().join("symlink_test");
        let target = tmpdir.path().join("target");
        File::create(&target).ok();
        std::os::windows::fs::symlink_file(&target, link).is_ok()
    }
    #[cfg(not(windows))]
    {
        let _ = tmpdir;
        true
    }
}

/// Helper to create symlinks in a cross-platform way
fn symlink_file(original: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(original, link);
    #[cfg(not(windows))]
    return std::os::unix::fs::symlink(original, link);
}

/// Helper to create directory symlinks in a cross-platform way
fn symlink_dir(original: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    return std::os::windows::fs::symlink_dir(original, link);
    #[cfg(not(windows))]
    return std::os::unix::fs::symlink(original, link);
}

/// Test that soft_canonicalize behaves like std canonicalize for existing files
#[test]
fn soft_canonicalize_works_simple() {
    let tmpdir = tmpdir();
    let tmpdir = fs::canonicalize(tmpdir.path()).unwrap();
    let file = tmpdir.join("test");
    File::create(&file).unwrap();

    let soft_result = soft_canonicalize(&file).unwrap();
    let std_result = fs::canonicalize(&file).unwrap();

    // WITHOUT dunce: EXACT format match with std::fs::canonicalize (UNC on Windows)
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            soft_result, std_result,
            "Without dunce: must match std EXACTLY"
        );
        assert_eq!(soft_canonicalize(&file).unwrap(), file);
    }

    // WITH dunce: Simplified format (no \\?\ prefix when safe on Windows)
    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let soft_str = soft_result.to_string_lossy();
            let std_str = std_result.to_string_lossy();

            // std returns \\?\C:\... but dunce simplifies to C:\...
            assert!(std_str.starts_with(r"\\?\"), "std should return UNC format");
            assert!(
                !soft_str.starts_with(r"\\?\"),
                "dunce should simplify safe paths"
            );

            // Verify semantic equivalence
            let soft_stripped = soft_str.strip_prefix(r"\\?\").unwrap_or(&soft_str);
            let std_stripped = std_str.strip_prefix(r"\\?\").unwrap_or(&std_str);
            assert_eq!(
                soft_stripped, std_stripped,
                "Paths should be semantically equal"
            );
        }
        #[cfg(not(windows))]
        {
            // On Unix, dunce doesn't change behavior
            assert_eq!(soft_result, std_result);
        }
    }
}

/// Test soft_canonicalize with non-existing files (the key difference from std)
#[test]
fn soft_canonicalize_nonexisting() {
    let tmpdir = tmpdir();
    let tmpdir_canonical_all = fs::canonicalize(tmpdir.path()).unwrap();

    // Non-existing file in existing directory
    let nonexisting = tmpdir.path().join("does_not_exist.txt");
    let result = soft_canonicalize(&nonexisting).unwrap();

    // WITHOUT dunce: UNC format
    #[cfg(not(feature = "dunce"))]
    {
        let expected = tmpdir_canonical_all.join("does_not_exist.txt");
        assert_eq!(result, expected, "Without dunce: exact UNC format");
    }

    // WITH dunce: Simplified format
    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        assert!(
            !result_str.starts_with(r"\\?\"),
            "dunce should simplify non-existing paths"
        );
        let expected = tmpdir_canonical_all.join("does_not_exist.txt");
        let expected_str = expected.to_string_lossy();
        assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        assert_eq!(
            result_str.as_ref(),
            expected_str.trim_start_matches(r"\\?\")
        );
    }

    // Non-existing directory
    let nonexisting_dir = tmpdir.path().join("missing_dir").join("file.txt");
    let result2 = soft_canonicalize(&nonexisting_dir).unwrap();

    #[cfg(not(feature = "dunce"))]
    {
        let expected2 = tmpdir_canonical_all.join("missing_dir").join("file.txt");
        assert_eq!(result2, expected2, "Without dunce: exact UNC format");
    }

    #[cfg(feature = "dunce")]
    {
        let result2_str = result2.to_string_lossy();
        assert!(!result2_str.starts_with(r"\\?\"), "dunce should simplify");
        let expected2 = tmpdir_canonical_all.join("missing_dir").join("file.txt");
        let expected2_str = expected2.to_string_lossy();
        assert!(expected2_str.starts_with(r"\\?\"), "std returns UNC");
        assert_eq!(
            result2_str.as_ref(),
            expected2_str.trim_start_matches(r"\\?\")
        );
    }

    // Std canonicalize should fail for these
    assert!(fs::canonicalize(&nonexisting).is_err());
    assert!(fs::canonicalize(&nonexisting_dir).is_err());
}

/// Test adapted from std's realpath_works
#[test]
fn soft_realpath_works() {
    let tmpdir = tmpdir();
    if !got_symlink_permission(&tmpdir) {
        return;
    }

    let tmpdir = fs::canonicalize(tmpdir.path()).unwrap();
    let file = tmpdir.join("test");
    let dir = tmpdir.join("test2");
    let link = dir.join("link");
    let linkdir = tmpdir.join("test3");

    File::create(&file).unwrap();
    fs::create_dir(&dir).unwrap();
    symlink_file(&file, &link).unwrap();
    symlink_dir(&dir, &linkdir).unwrap();

    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());

    // Test that soft_canonicalize resolves symlinks like std::fs::canonicalize

    // WITHOUT dunce: EXACT match with std
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(soft_canonicalize(&tmpdir).unwrap(), tmpdir);
        assert_eq!(
            soft_canonicalize(&file).unwrap(),
            fs::canonicalize(&file).unwrap()
        );
        assert_eq!(
            soft_canonicalize(&link).unwrap(),
            fs::canonicalize(&link).unwrap()
        );
        assert_eq!(
            soft_canonicalize(&linkdir).unwrap(),
            fs::canonicalize(&linkdir).unwrap()
        );
    }

    // WITH dunce: Verify simplified format but semantic equivalence
    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let soft_tmpdir = soft_canonicalize(&tmpdir).unwrap();
            let soft_tmpdir_str = soft_tmpdir.to_string_lossy();
            assert!(
                !soft_tmpdir_str.starts_with(r"\\?\"),
                "dunce should simplify tmpdir"
            );

            let soft_file = soft_canonicalize(&file).unwrap();
            let std_file = fs::canonicalize(&file).unwrap();
            assert!(
                !soft_file.to_string_lossy().starts_with(r"\\?\"),
                "dunce should simplify file"
            );
            assert!(
                std_file.to_string_lossy().starts_with(r"\\?\"),
                "std returns UNC"
            );

            let soft_link = soft_canonicalize(&link).unwrap();
            let std_link = fs::canonicalize(&link).unwrap();
            assert!(
                !soft_link.to_string_lossy().starts_with(r"\\?\"),
                "dunce should simplify link"
            );
            assert!(
                std_link.to_string_lossy().starts_with(r"\\?\"),
                "std returns UNC"
            );

            let soft_linkdir = soft_canonicalize(&linkdir).unwrap();
            let std_linkdir = fs::canonicalize(&linkdir).unwrap();
            assert!(
                !soft_linkdir.to_string_lossy().starts_with(r"\\?\"),
                "dunce should simplify linkdir"
            );
            assert!(
                std_linkdir.to_string_lossy().starts_with(r"\\?\"),
                "std returns UNC"
            );
        }
        #[cfg(not(windows))]
        {
            // On Unix, just verify the operations work
            let _ = soft_canonicalize(&tmpdir).unwrap();
            let _ = soft_canonicalize(&file).unwrap();
            let _ = soft_canonicalize(&link).unwrap();
            let _ = soft_canonicalize(&linkdir).unwrap();
        }
    }

    // But also test with broken symlinks (pointing to non-existing files)
    let broken_link = tmpdir.join("broken_link");
    let nonexisting_target = tmpdir.join("does_not_exist");
    symlink_file(&nonexisting_target, &broken_link).unwrap();

    // std::fs::canonicalize fails on broken symlinks
    assert!(fs::canonicalize(&broken_link).is_err());

    // But soft_canonicalize should handle it gracefully
    let result = soft_canonicalize(&broken_link).unwrap();
    let expected_target = tmpdir.join("does_not_exist");

    // WITHOUT dunce: EXACT match
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected_target);
    }

    // WITH dunce: Compare simplified paths
    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected_target.to_string_lossy();

            // dunce simplifies, tmpdir was canonicalized with UNC prefix
            assert!(
                !result_str.starts_with(r"\\?\"),
                "dunce should simplify result"
            );
            assert!(
                expected_str.starts_with(r"\\?\"),
                "expected_target has UNC from canonicalized tmpdir"
            );

            let expected_simplified = expected_str.trim_start_matches(r"\\?\");
            assert_eq!(result_str.as_ref(), expected_simplified);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected_target);
        }
    }
}

/// Test adapted from std's realpath_works_tricky  
#[test]
fn soft_realpath_works_tricky() {
    let tmpdir = tmpdir();
    if !got_symlink_permission(&tmpdir) {
        return;
    }

    let tmpdir = fs::canonicalize(tmpdir.path()).unwrap();
    let a = tmpdir.join("a");
    let b = a.join("b");
    let c = b.join("c");
    let d = a.join("d");
    let e = d.join("e");
    let f = a.join("f");

    fs::create_dir_all(&b).unwrap();
    fs::create_dir_all(&d).unwrap();
    File::create(&f).unwrap();

    // Create tricky symlinks: c -> ../d/e -> ../f
    if cfg!(not(windows)) {
        symlink_file(Path::new("../d/e"), &c).unwrap();
        symlink_file(Path::new("../f"), &e).unwrap();
    }
    if cfg!(windows) {
        symlink_file(Path::new(r"..\d\e"), &c).unwrap();
        symlink_file(Path::new(r"..\f"), &e).unwrap();
    }

    // Both should resolve to f
    let soft_c = soft_canonicalize(&c).unwrap();
    let std_c = fs::canonicalize(&c).unwrap();
    let std_f = fs::canonicalize(&f).unwrap();

    // WITHOUT dunce: EXACT match
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(soft_c, std_c);
        assert_eq!(soft_c, std_f);
    }

    // WITH dunce: Verify simplified but semantically equal
    #[cfg(feature = "dunce")]
    {
        let soft_c_str = soft_c.to_string_lossy();

        assert!(
            !soft_c_str.starts_with(r"\\?\"),
            "dunce should simplify symlink"
        );

        // Windows-specific UNC format checks
        #[cfg(windows)]
        {
            let std_c_str = std_c.to_string_lossy();
            let std_f_str = std_f.to_string_lossy();
            assert!(std_c_str.starts_with(r"\\?\"), "std returns UNC");
            assert!(std_f_str.starts_with(r"\\?\"), "std returns UNC");
        }

        // Unix: No UNC paths, verify equality
        #[cfg(not(windows))]
        {
            assert_eq!(soft_c, std_c);
            assert_eq!(soft_c, std_f);
        }
    }
}

/// Test dot and dotdot handling
#[test]
fn soft_canonicalize_dots() {
    let tmpdir = tmpdir();
    #[cfg(not(feature = "dunce"))]
    let tmpdir_canonical = fs::canonicalize(tmpdir.path()).unwrap();

    // Create nested directory structure
    let a = tmpdir.path().join("a");
    let b = a.join("b");
    fs::create_dir_all(&b).unwrap();

    let file = b.join("test.txt");
    File::create(&file).unwrap();

    // Test various dot patterns
    let cases = vec![
        // (input_path, should_equal_to)
        (a.join(".").join("b").join("test.txt"), file.clone()),
        (b.join(".").join("test.txt"), file.clone()),
        (b.join("..").join("b").join("test.txt"), file.clone()),
        (
            a.join("b").join("..").join("b").join("test.txt"),
            file.clone(),
        ),
        (
            tmpdir
                .path()
                .join("a")
                .join("./b")
                .join("../b")
                .join("test.txt"),
            file,
        ),
    ];

    for (input, expected) in cases {
        let soft_result = soft_canonicalize(&input).unwrap();
        let std_result = fs::canonicalize(&expected).unwrap();

        // WITHOUT dunce: EXACT match
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(soft_result, std_result, "Failed for input: {input:?}");
        }

        // WITH dunce: Verify simplified but semantically equal
        #[cfg(feature = "dunce")]
        {
            let soft_str = soft_result.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert!(
                !soft_str.starts_with(r"\\?\"),
                "dunce should simplify for input: {input:?}"
            );

            // Windows-specific UNC format check
            #[cfg(windows)]
            {
                assert!(
                    std_str.starts_with(r"\\?\"),
                    "std returns UNC for input: {input:?}"
                );
            }

            // Semantic equality check
            let soft_stripped = soft_str.strip_prefix(r"\\?\").unwrap_or(&soft_str);
            let std_stripped = std_str.strip_prefix(r"\\?\").unwrap_or(&std_str);
            assert_eq!(soft_stripped, std_stripped, "Failed for input: {input:?}");
        }
    }

    // Test with non-existing components
    let nonexisting_with_dots = a.join("b").join("..").join("c").join("test.txt");
    let result = soft_canonicalize(nonexisting_with_dots).unwrap();

    #[cfg(not(feature = "dunce"))]
    {
        let expected = tmpdir_canonical.join("a").join("c").join("test.txt");
        assert_eq!(result, expected);
    }

    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        assert!(
            !result_str.starts_with(r"\\?\"),
            "dunce should simplify non-existing"
        );
        let tmpdir_canonical = fs::canonicalize(tmpdir.path()).unwrap();
        let expected = tmpdir_canonical.join("a").join("c").join("test.txt");
        let expected_str = expected.to_string_lossy();
        assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        assert_eq!(
            result_str.as_ref(),
            expected_str.trim_start_matches(r"\\?\")
        );
    }
}

/// Test absolute vs relative paths
#[test]
fn soft_canonicalize_absolute_relative() {
    let tmpdir = tmpdir();
    #[cfg(not(feature = "dunce"))]
    let tmpdir_canonical = fs::canonicalize(tmpdir.path()).unwrap();

    // Create test structure
    let subdir = tmpdir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    let file = subdir.join("test.txt");
    File::create(&file).unwrap();

    // Test that relative paths get converted to absolute
    let original_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmpdir.path()).unwrap();

    let relative_result = soft_canonicalize(Path::new("subdir/test.txt")).unwrap();
    assert!(relative_result.is_absolute());

    // WITHOUT dunce: EXACT match
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(relative_result, fs::canonicalize(&file).unwrap());
    }

    // WITH dunce: Simplified format
    #[cfg(feature = "dunce")]
    {
        let soft_str = relative_result.to_string_lossy();
        let std_path = fs::canonicalize(&file).unwrap();
        assert!(!soft_str.starts_with(r"\\?\"), "dunce should simplify");

        // Windows-specific UNC format check
        #[cfg(windows)]
        {
            let std_str = std_path.to_string_lossy();
            assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
        }

        // Unix: Verify basic equality
        #[cfg(not(windows))]
        {
            assert_eq!(relative_result, std_path);
        }
    }

    // Test relative non-existing path
    let relative_nonexisting = soft_canonicalize(Path::new("subdir/nonexisting.txt")).unwrap();

    #[cfg(not(feature = "dunce"))]
    {
        let expected = tmpdir_canonical.join("subdir").join("nonexisting.txt");
        assert_eq!(relative_nonexisting, expected);
    }

    #[cfg(feature = "dunce")]
    {
        let result_str = relative_nonexisting.to_string_lossy();
        assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
        let expected = fs::canonicalize(tmpdir.path())
            .unwrap()
            .join("subdir")
            .join("nonexisting.txt");
        let expected_str = expected.to_string_lossy();
        assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        assert_eq!(
            result_str.as_ref(),
            expected_str.trim_start_matches(r"\\?\")
        );
    }

    std::env::set_current_dir(original_cwd).unwrap();
}

/// Test edge cases and error conditions
#[test]
fn soft_canonicalize_edge_cases() {
    // Test empty path - should fail exactly like std::fs::canonicalize
    assert!(soft_canonicalize(Path::new("")).is_err());
    assert!(fs::canonicalize("").is_err());

    // Both should fail with NotFound error kind
    match soft_canonicalize(Path::new("")) {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        Ok(_) => panic!("Empty path should fail"),
    }

    // Test root path
    #[cfg(unix)]
    {
        let root_result = soft_canonicalize(Path::new("/")).unwrap();
        assert_eq!(root_result, PathBuf::from("/"));
    }

    #[cfg(windows)]
    {
        let c_root = soft_canonicalize(Path::new("C:\\")).unwrap();

        // WITHOUT dunce: UNC format
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(c_root, PathBuf::from("\\\\?\\C:\\"));
        }

        // WITH dunce: Simplified format
        #[cfg(feature = "dunce")]
        {
            assert_eq!(c_root, PathBuf::from("C:\\"));
        }
    }
}

/// Test symlink cycles detection
#[test]
fn soft_canonicalize_symlink_cycles() {
    let tmpdir = tmpdir();
    if !got_symlink_permission(&tmpdir) {
        return;
    }

    let link1 = tmpdir.path().join("link1");
    let link2 = tmpdir.path().join("link2");

    // Create symlink cycle: link1 -> link2 -> link1
    symlink_file(&link2, &link1).unwrap();
    symlink_file(&link1, &link2).unwrap();

    // Both std and soft canonicalize should detect this cycle
    assert!(fs::canonicalize(&link1).is_err());
    assert!(soft_canonicalize(&link1).is_err());
}

/// Test with very long paths
#[test]
fn soft_canonicalize_long_paths() {
    let tmpdir = tmpdir();

    // Create a very deep directory structure
    let mut path = tmpdir.path().to_path_buf();
    for i in 0..50 {
        path = path.join(format!("dir_{i}"));
    }

    // Test with non-existing deep path
    let result = soft_canonicalize(&path).unwrap();
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("dir_49"));
}

/// Test Unicode path handling
#[test]
fn soft_canonicalize_unicode() {
    let tmpdir = tmpdir();

    // Test with Unicode characters in path
    let unicode_dir = tmpdir.path().join("测试目录");
    let unicode_file = unicode_dir.join("файл.txt");

    fs::create_dir(&unicode_dir).unwrap();
    File::create(&unicode_file).unwrap();

    // Test existing Unicode path
    let result = soft_canonicalize(&unicode_file).unwrap();

    // WITHOUT dunce: EXACT match
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, fs::canonicalize(&unicode_file).unwrap());
    }

    // WITH dunce: Simplified format
    #[cfg(feature = "dunce")]
    {
        let soft_str = result.to_string_lossy();
        let std_path = fs::canonicalize(&unicode_file).unwrap();
        assert!(
            !soft_str.starts_with(r"\\?\"),
            "dunce should simplify Unicode"
        );

        // Windows-specific UNC format check
        #[cfg(windows)]
        {
            let std_str = std_path.to_string_lossy();
            assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
        }

        // Unix: Verify basic equality
        #[cfg(not(windows))]
        {
            assert_eq!(result, std_path);
        }

        assert!(soft_str.contains("файл.txt"));
    }

    // Test non-existing Unicode path
    let nonexisting_unicode = unicode_dir.join("не_существует.txt");
    let result = soft_canonicalize(nonexisting_unicode).unwrap();
    assert!(result.to_string_lossy().contains("не_существует.txt"));
}

/// Test that soft_canonicalize preserves the behavior for existing paths
#[test]
fn soft_canonicalize_compatibility() {
    let tmpdir = tmpdir();

    // Create various existing paths to test compatibility
    let file = tmpdir.path().join("file.txt");
    let dir = tmpdir.path().join("directory");
    let nested_file = dir.join("nested.txt");

    File::create(&file).unwrap();
    fs::create_dir(&dir).unwrap();
    File::create(&nested_file).unwrap();

    let test_paths = vec![tmpdir.path(), &file, &dir, &nested_file];

    for path in test_paths {
        let soft_result = soft_canonicalize(path).unwrap();
        let std_result = fs::canonicalize(path).unwrap();

        // WITHOUT dunce: EXACT format match
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                soft_result, std_result,
                "Mismatch for existing path: {path:?}"
            );
        }

        // WITH dunce: Verify simplified but semantically equal
        #[cfg(feature = "dunce")]
        {
            let soft_str = soft_result.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert!(
                !soft_str.starts_with(r"\\?\"),
                "dunce should simplify for path: {path:?}"
            );

            // Windows-specific UNC format check
            #[cfg(windows)]
            {
                assert!(
                    std_str.starts_with(r"\\?\"),
                    "std returns UNC for path: {path:?}"
                );
            }

            // Semantic equality
            let soft_stripped = soft_str.strip_prefix(r"\\?\").unwrap_or(&soft_str);
            let std_stripped = std_str.strip_prefix(r"\\?\").unwrap_or(&std_str);
            assert_eq!(
                soft_stripped, std_stripped,
                "Semantic mismatch for path: {path:?}"
            );
        }
    }
}
