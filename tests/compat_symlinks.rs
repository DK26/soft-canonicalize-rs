//! Tests adapted from Rust's std library canonicalize tests — symlink resolution group.
//!
//! Covers: realpath_works, realpath_works_tricky, symlink_cycles.
//!
//! Feature-conditional testing:
//! - WITHOUT dunce: Verifies EXACT UNC format match with std::fs::canonicalize
//! - WITH dunce: Verifies simplified format (no \\?\ prefix when safe)

use soft_canonicalize::soft_canonicalize;
use std::fs::{self, File};
use std::path::Path;
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
    {
        match std::os::windows::fs::symlink_dir(original, link) {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(1314)
                {
                    match junction_verbatim::create(original, link) {
                        Ok(_) => Ok(()),
                        Err(je) => Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("junction fallback failed: {je}"),
                        )),
                    }
                } else {
                    Err(e)
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        std::os::unix::fs::symlink(original, link)
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

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
