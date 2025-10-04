#![cfg(unix)]
use crate::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn relative_symlink_keeps_clamp() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    let td = TempDir::new()?;
    let anchor = td.path().join("home").join("user");
    fs::create_dir_all(anchor.join("docs/dir1/dir2/dir3/project"))?;
    let base = soft_canonicalize(&anchor)?;

    fs::create_dir_all(base.join("project"))?;
    symlink("../docs/dir1/dir2/dir3/project", base.join("project/docs"))?;

    let out = anchored_canonicalize(&base, "project/docs/../../etc/passwd")?;
    assert_eq!(out, base.join("docs/dir1/dir2/etc/passwd"));
    Ok(())
}

#[test]
fn non_existing_anchor_with_input_absolute_symlink_is_clamped_unix() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    let td = TempDir::new()?;
    let root = td.path().join("root");
    let target = td.path().join("target");
    let outside = td.path().join("outside");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&target)?;
    fs::create_dir_all(&outside)?;

    // linked -> ../target (relative symlink under root)
    symlink("../target", root.join("linked"))?;

    // Create subdir under target so part of the anchor can exist
    fs::create_dir_all(target.join("miss"))?;
    // Absolute symlink inside target/miss: target/miss/escape -> abs(outside)
    let abs_outside = fs::canonicalize(&outside)?;
    symlink(abs_outside, target.join("miss").join("escape"))?;

    // Anchor includes symlinked segment and non-existing tail
    let anchor = root.join("linked").join("miss");
    // NEW BEHAVIOR: absolute symlink should be clamped to canonicalized anchor
    let out = anchored_canonicalize(&anchor, "escape")?;

    // Should be clamped (not escape to abs_outside)
    let canon_anchor = soft_canonicalize(&anchor)?;
    assert!(
        out.starts_with(&canon_anchor),
        "Absolute symlink should be clamped to anchor. Got: {:?}, Anchor: {:?}",
        out,
        canon_anchor
    );

    Ok(())
}

#[test]
fn absolute_symlink_is_clamped() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    let td = TempDir::new()?;
    let anchor = td.path().join("a").join("b");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let outside = td.path().join("outside/target");
    fs::create_dir_all(&outside)?;
    let abs_outside = fs::canonicalize(&outside)?;
    symlink(abs_outside, base.join("escape"))?;

    // NEW BEHAVIOR: absolute symlink should be clamped to anchor
    let out = anchored_canonicalize(&base, "escape")?;

    // Should be clamped within anchor
    assert!(
        out.starts_with(&base),
        "Absolute symlink should be clamped to anchor. Got: {:?}, Anchor: {:?}",
        out,
        base
    );

    Ok(())
}

#[test]
fn cycle_and_hop_limit_protected() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    let td = TempDir::new()?;
    let anchor = td.path().join("x");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let a = base.join("a");
    let b = base.join("b");
    symlink("b", a)?;
    symlink("a", b)?;

    let err = anchored_canonicalize(&base, "a").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    Ok(())
}
