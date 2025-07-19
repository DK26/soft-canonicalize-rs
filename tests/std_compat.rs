//! Tests adapted from Rust's std library canonicalize tests
//!
//! These tests ensure that soft_canonicalize behaves compatibly with std::fs::canonicalize
//! for existing paths, but handles non-existing paths gracefully.

#![allow(clippy::needless_borrows_for_generic_args)]

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
        std::os::windows::fs::symlink_file(&target, &link).is_ok()
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

    // For existing files, soft_canonicalize should match std::fs::canonicalize
    let soft_result = soft_canonicalize(&file).unwrap();
    let std_result = fs::canonicalize(&file).unwrap();
    assert_eq!(soft_result, std_result);

    // Also test with the canonical tmpdir
    assert_eq!(soft_canonicalize(&file).unwrap(), file);
}

/// Test soft_canonicalize with non-existing files (the key difference from std)
#[test]
fn soft_canonicalize_nonexisting() {
    let tmpdir = tmpdir();
    let tmpdir_canonical = fs::canonicalize(tmpdir.path()).unwrap();

    // Non-existing file in existing directory
    let nonexisting = tmpdir.path().join("does_not_exist.txt");
    let result = soft_canonicalize(&nonexisting).unwrap();
    let expected = tmpdir_canonical.join("does_not_exist.txt");
    assert_eq!(result, expected);

    // Non-existing directory
    let nonexisting_dir = tmpdir.path().join("missing_dir").join("file.txt");
    let result = soft_canonicalize(&nonexisting_dir).unwrap();
    let expected = tmpdir_canonical.join("missing_dir").join("file.txt");
    assert_eq!(result, expected);

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

    // But also test with broken symlinks (pointing to non-existing files)
    let broken_link = tmpdir.join("broken_link");
    let nonexisting_target = tmpdir.join("does_not_exist");
    symlink_file(&nonexisting_target, &broken_link).unwrap();

    // std::fs::canonicalize fails on broken symlinks
    assert!(fs::canonicalize(&broken_link).is_err());

    // But soft_canonicalize should handle it gracefully
    let result = soft_canonicalize(&broken_link).unwrap();
    let expected_target = tmpdir.join("does_not_exist");
    assert_eq!(result, expected_target);
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
    assert_eq!(
        soft_canonicalize(&c).unwrap(),
        fs::canonicalize(&c).unwrap()
    );
    assert_eq!(
        soft_canonicalize(&c).unwrap(),
        fs::canonicalize(&f).unwrap()
    );
}

/// Test dot and dotdot handling
#[test]
fn soft_canonicalize_dots() {
    let tmpdir = tmpdir();
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
            file.clone(),
        ),
    ];

    for (input, expected) in cases {
        let soft_result = soft_canonicalize(&input).unwrap();
        let std_result = fs::canonicalize(&expected).unwrap();
        assert_eq!(soft_result, std_result, "Failed for input: {input:?}");
    }

    // Test with non-existing components
    let nonexisting_with_dots = a.join("b").join("..").join("c").join("test.txt");
    let result = soft_canonicalize(&nonexisting_with_dots).unwrap();
    let expected = tmpdir_canonical.join("a").join("c").join("test.txt");
    assert_eq!(result, expected);
}

/// Test absolute vs relative paths
#[test]
fn soft_canonicalize_absolute_relative() {
    let tmpdir = tmpdir();
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
    assert_eq!(relative_result, fs::canonicalize(&file).unwrap());

    // Test relative non-existing path
    let relative_nonexisting = soft_canonicalize(Path::new("subdir/nonexisting.txt")).unwrap();
    let expected = tmpdir_canonical.join("subdir").join("nonexisting.txt");
    assert_eq!(relative_nonexisting, expected);

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
        // Test Windows drive root
        let c_root = soft_canonicalize(&Path::new("C:\\")).unwrap();
        assert_eq!(c_root, PathBuf::from("C:\\"));
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
    assert_eq!(result, fs::canonicalize(&unicode_file).unwrap());

    // Test non-existing Unicode path
    let nonexisting_unicode = unicode_dir.join("не_существует.txt");
    let result = soft_canonicalize(&nonexisting_unicode).unwrap();
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
        assert_eq!(
            soft_result, std_result,
            "Mismatch for existing path: {path:?}"
        );
    }
}
