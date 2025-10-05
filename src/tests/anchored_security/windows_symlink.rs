use crate::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn anchored_relative_symlink_keeps_clamp_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;

    let td = TempDir::new()?;
    let anchor = td.path().join("home").join("jail");
    let target_parent = td.path().join("opt").join("subdir");
    fs::create_dir_all(&anchor)?;
    fs::create_dir_all(&target_parent)?;
    let special_target = target_parent.join("special");
    fs::create_dir(&special_target)?;

    let base = soft_canonicalize(&anchor)?; // extended-length form

    let link = base.join("special");
    match symlink_dir(&special_target, link) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // Relative traversal should keep clamp under the anchor
    let out = anchored_canonicalize(&base, r"special\..\hello\world")?;
    let expected = soft_canonicalize(&target_parent)?
        .join("hello")
        .join("world");
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn anchored_absolute_symlink_is_clamped_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;

    let td = TempDir::new()?;
    let anchor = td.path().join("a").join("b");
    let outside = td.path().join("outside").join("place");
    fs::create_dir_all(&anchor)?;
    fs::create_dir_all(&outside)?;

    let base = soft_canonicalize(&anchor)?;
    let abs_outside = soft_canonicalize(&outside)?;

    let link = base.join("escape");
    match symlink_dir(abs_outside, link) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // NEW BEHAVIOR: absolute symlink should be clamped to anchor
    let out = anchored_canonicalize(&base, r"escape")?;

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
fn non_existing_anchor_with_input_absolute_symlink_is_clamped_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;

    let td = TempDir::new()?;
    let root = td.path().join("root");
    let target = td.path().join("target");
    let outside = td.path().join("outside");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&target)?;
    fs::create_dir_all(&outside)?;

    // linked -> target (relative path under root)
    match symlink_dir(&target, root.join("linked")) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // Create subdir under target so part of the anchor can exist
    fs::create_dir_all(target.join("miss"))?;
    // Absolute symlink inside target\miss: target\miss\escape -> abs(outside)
    let abs_outside = soft_canonicalize(&outside)?;
    match symlink_dir(abs_outside, target.join("miss").join("escape")) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // Anchor includes symlinked segment and may include non-existing tail
    let anchor = root.join("linked").join("miss");
    // NEW BEHAVIOR: absolute symlink should be clamped to the canonicalized anchor
    let out = anchored_canonicalize(&anchor, r"escape")?;

    // Result should be clamped (not escape to abs_outside)
    let canon_anchor = soft_canonicalize(&anchor)?;
    assert!(
        out.starts_with(&canon_anchor),
        "Absolute symlink should be clamped to anchor. Got: {:?}, Anchor: {:?}",
        out,
        canon_anchor
    );

    Ok(())
}
