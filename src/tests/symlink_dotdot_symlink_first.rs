//! Validate symlink-first semantics for paths like: jail/special/../hello/world
//! where `jail/special` is a symlink to `opt/subdir/special`.

use crate::soft_canonicalize;
use std::fs;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn symlink_first_with_non_existing_tail() -> std::io::Result<()> {
    // Layout:
    // base/home/jail/
    // base/opt/subdir/special/
    // symlink: base/home/jail/special -> base/opt/subdir/special
    let td = TempDir::new()?;
    let base = td.path();
    let jail = base.join("home").join("jail");
    let opt_sub = base.join("opt").join("subdir");
    fs::create_dir_all(&jail)?;
    fs::create_dir_all(&opt_sub)?;
    let special_target = opt_sub.join("special");
    fs::create_dir(&special_target)?;
    let link = jail.join("special");
    std::os::unix::fs::symlink(&special_target, link)?;

    let test_path = jail.join("special").join("..").join("hello").join("world");

    // soft_canonicalize should resolve the symlink first, then apply the `..` lexically
    let out = soft_canonicalize(test_path)?;

    // Expected: canonical(opt/subdir).join("hello/world")
    let expected_base = fs::canonicalize(&opt_sub)?;
    let expected = expected_base.join("hello").join("world");
    assert_eq!(
        out, expected,
        "soft_canonicalize should resolve via symlink target for non-existing tails"
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_first_with_existing_tail_matches_std() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let base = td.path();
    let jail = base.join("home").join("jail");
    let opt_sub = base.join("opt").join("subdir");
    fs::create_dir_all(&jail)?;
    fs::create_dir_all(&opt_sub)?;
    let special_target = opt_sub.join("special");
    fs::create_dir(&special_target)?;
    let link = jail.join("special");
    std::os::unix::fs::symlink(&special_target, link)?;

    // Create the final existing tail under the symlink target
    fs::create_dir_all(opt_sub.join("hello").join("world"))?;

    let test_path = jail.join("special").join("..").join("hello").join("world");

    let soft = soft_canonicalize(&test_path)?;
    let std = fs::canonicalize(&test_path)?;

    assert_eq!(
        soft, std,
        "soft_canonicalize should match std::fs::canonicalize for existing path"
    );

    // And equals the symlink-target path
    let expected = fs::canonicalize(&opt_sub)?.join("hello").join("world");
    assert_eq!(soft, expected, "result should be the symlink target path");

    Ok(())
}

// Note: On Windows, creating symlinks usually requires special privileges; keep these tests Unix-only.
#[cfg(windows)]
#[test]
fn symlink_first_with_non_existing_tail_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;

    let td = TempDir::new()?;
    let base = td.path();
    let jail = base.join("home").join("jail");
    let opt_sub = base.join("opt").join("subdir");
    fs::create_dir_all(&jail)?;
    fs::create_dir_all(&opt_sub)?;
    let special_target = opt_sub.join("special");
    fs::create_dir(&special_target)?;
    let link = jail.join("special");

    match symlink_dir(&special_target, link) {
        Ok(_) => {}
        Err(e) => {
            // Gracefully skip if environment cannot create symlinks (no privilege)
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    let test_path = jail.join("special").join("..").join("hello").join("world");
    let out = soft_canonicalize(test_path)?;

    let expected_base = fs::canonicalize(&opt_sub)?;
    let expected = expected_base.join("hello").join("world");
    assert_eq!(out, expected);
    Ok(())
}

#[cfg(windows)]
#[test]
fn symlink_first_with_existing_tail_matches_std_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;

    let td = TempDir::new()?;
    let base = td.path();
    let jail = base.join("home").join("jail");
    let opt_sub = base.join("opt").join("subdir");
    fs::create_dir_all(&jail)?;
    fs::create_dir_all(&opt_sub)?;
    let special_target = opt_sub.join("special");
    fs::create_dir(&special_target)?;
    let link = jail.join("special");

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

    fs::create_dir_all(opt_sub.join("hello").join("world"))?;
    let test_path = jail.join("special").join("..").join("hello").join("world");

    let soft = soft_canonicalize(&test_path)?;
    let stdp = fs::canonicalize(&test_path)?;
    assert_eq!(soft, stdp);

    let expected = fs::canonicalize(&opt_sub)?.join("hello").join("world");
    assert_eq!(soft, expected);
    Ok(())
}
