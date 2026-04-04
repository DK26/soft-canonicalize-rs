//! Regression test for GitHub issue #53:
//! `soft_canonicalize` incorrectly removes symlinks via lexical `..` collapse.
//!
//! When a path like `/test/link/../a` is given, where `link` is a symlink to
//! `/test/nested/dir`, the lexical normalization collapses `link/..` into
//! nothing, producing `/test/a` instead of the correct `/test/nested/a`.
//!
//! The correct behavior is to follow the symlink before resolving `..`, which
//! means `link` → `/test/nested/dir`, then `..` → `/test/nested/`, yielding
//! the final path `/test/nested/a`.
//!
//! See: https://github.com/DK26/soft-canonicalize-rs/issues/53

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::path::Path;
use tempfile::{Builder, TempDir};

fn tmpdir() -> TempDir {
    Builder::new()
        .prefix("soft_canonicalize_issue53")
        .tempdir()
        .unwrap()
}

/// Cross-platform symlink creation (directory symlink).
fn symlink_dir(original: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(original, link)
    }
    #[cfg(not(windows))]
    {
        std::os::unix::fs::symlink(original, link)
    }
}

/// Check if we have symlink permissions (Windows requires elevated privileges).
fn got_symlink_permission(tmpdir: &TempDir) -> bool {
    #[cfg(windows)]
    {
        let link = tmpdir.path().join("perm_test_link");
        let target = tmpdir.path().join("perm_test_target");
        let _ = fs::create_dir(&target);
        match std::os::windows::fs::symlink_dir(&target, &link) {
            Ok(_) => {
                let _ = fs::remove_dir(&link);
                let _ = fs::remove_dir(&target);
                true
            }
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = tmpdir;
        true
    }
}

/// Issue #53: `soft_canonicalize` incorrectly collapses `link/..` lexically,
/// bypassing symlink resolution.
///
/// Layout:
///   {tmp}/a          — existing file (the WRONG answer on Unix; expected on Windows)
///   {tmp}/nested/dir — existing directory (symlink target)
///   {tmp}/nested/a   — does NOT exist (the CORRECT answer on Unix)
///   {tmp}/link       — symlink → {tmp}/nested/dir
///
/// Input:  `{tmp}/link/../a`
///
/// Platform semantics for `symlink/..`:
///   Unix:    follows symlink first, then `..` from target → nested/a (non-existing)
///   Windows: resolves `..` lexically through symlinks → {tmp}/a (existing decoy)
///
/// On Unix, the correct output is `{tmp}/nested/a` (follow symlink, then resolve `..`).
/// On Windows, `link\..` collapses lexically, so the path resolves to `{tmp}\a`
/// which exists — and we must match `std::fs::canonicalize` for existing paths.
#[test]
fn issue_53_symlink_dotdot_non_existing_suffix() -> std::io::Result<()> {
    let tmpdir = tmpdir();

    if !got_symlink_permission(&tmpdir) {
        println!("Skipping test: no symlink permission");
        return Ok(());
    }

    let base = tmpdir.path();

    // Create {tmp}/a — an existing file (the WRONG answer if returned)
    fs::write(base.join("a"), b"wrong")?;

    // Create {tmp}/nested/dir/ — the symlink target directory
    let nested_dir = base.join("nested").join("dir");
    fs::create_dir_all(&nested_dir)?;

    // {tmp}/nested/a does NOT exist — this is the correct non-existing suffix path

    // Create symlink: {tmp}/link → {tmp}/nested/dir
    let link = base.join("link");
    symlink_dir(&nested_dir, &link)?;

    // The path under test: {tmp}/link/../a
    let test_path = link.join("..").join("a");

    let result = soft_canonicalize(&test_path)?;

    // Platform divergence for `symlink/../a`:
    //   Unix:    follows symlink first, then resolves `..` from target → nested/a
    //   Windows: resolves `..` lexically through symlinks → {tmp}/a
    // On Windows, `{tmp}/a` (the decoy) exists, so std::fs::canonicalize succeeds
    // and returns it. We must match that behavior (golden rule: match std for existing paths).

    #[cfg(unix)]
    {
        let expected_base = fs::canonicalize(base.join("nested"))?;
        let expected = expected_base.join("a");
        assert_eq!(
            result,
            expected,
            "issue #53: soft_canonicalize should follow the symlink before resolving `..`\n\
             input:    {}\n\
             got:      {}\n\
             expected: {}",
            test_path.display(),
            result.display(),
            expected.display(),
        );
    }

    #[cfg(windows)]
    {
        // Windows resolves `link\..` lexically, so the path becomes `{tmp}\a` which exists.
        // soft_canonicalize must match std::fs::canonicalize for existing paths.
        let std_result = fs::canonicalize(&test_path)?;
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                result,
                std_result,
                "issue #53 (windows): soft_canonicalize must match std::fs::canonicalize\n\
                 input: {}\n\
                 got:   {}\n\
                 std:   {}",
                test_path.display(),
                result.display(),
                std_result.display(),
            );
        }
        #[cfg(feature = "dunce")]
        {
            let result_str = result.to_string_lossy();
            let std_str = std_result.to_string_lossy();
            assert_eq!(
                result_str.as_ref(),
                std_str.trim_start_matches(r"\\?\"),
                "issue #53 (windows, dunce): soft_canonicalize must match std (simplified)\n\
                 input: {}\n\
                 got:   {}\n\
                 std:   {}",
                test_path.display(),
                result.display(),
                std_str,
            );
        }
    }

    Ok(())
}

/// Same scenario from issue #53 but when the full path DOES exist —
/// in that case `std::fs::canonicalize` succeeds and we must match it exactly.
/// This confirms the fast-path still works for the fully-existing case.
#[test]
fn issue_53_symlink_dotdot_existing_suffix_matches_std() -> std::io::Result<()> {
    let tmpdir = tmpdir();

    if !got_symlink_permission(&tmpdir) {
        println!("Skipping test: no symlink permission");
        return Ok(());
    }

    let base = tmpdir.path();

    // Create {tmp}/a — decoy file
    fs::write(base.join("a"), b"wrong")?;

    // Create {tmp}/nested/dir/
    let nested_dir = base.join("nested").join("dir");
    fs::create_dir_all(&nested_dir)?;

    // Create {tmp}/nested/a — this time it EXISTS
    fs::write(base.join("nested").join("a"), b"correct")?;

    // Create symlink: {tmp}/link → {tmp}/nested/dir
    let link = base.join("link");
    symlink_dir(&nested_dir, &link)?;

    // The path under test: {tmp}/link/../a
    let test_path = link.join("..").join("a");

    let result = soft_canonicalize(&test_path)?;
    let std_result = fs::canonicalize(&test_path)?;

    // The existing-path fast-path should fire and match std exactly
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            result,
            std_result,
            "issue #53 (existing): soft_canonicalize must match std::fs::canonicalize\n\
             input: {}\n\
             got:   {}\n\
             std:   {}",
            test_path.display(),
            result.display(),
            std_result.display(),
        );
    }
    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        let std_str = std_result.to_string_lossy();
        assert_eq!(
            result_str.as_ref(),
            std_str.trim_start_matches(r"\\?\"),
            "issue #53 (existing, dunce): soft_canonicalize must match std (simplified)\n\
             input: {}\n\
             got:   {}\n\
             std:   {}",
            test_path.display(),
            result.display(),
            std_str,
        );
    }

    Ok(())
}
