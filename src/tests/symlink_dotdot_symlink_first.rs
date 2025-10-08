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

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(out, expected);
    }

    #[cfg(feature = "dunce")]
    {
        // With dunce: our result is simplified, std is UNC
        let out_str = out.to_string_lossy();
        let expected_str = expected.to_string_lossy();
        #[cfg(windows)]
        {
            assert!(!out_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
            assert_eq!(out_str.as_ref(), expected_str.trim_start_matches(r"\\?\"));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(out, expected);
        }
    }

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

    // Always assert our policy: resolve the symlinked component first, then apply `..`.

    let expected = fs::canonicalize(&opt_sub)?.join("hello").join("world");

    #[cfg(not(feature = "dunce"))]
    {
        let soft = soft_canonicalize(&test_path)?;
        assert_eq!(
            soft, expected,
            "soft_canonicalize should resolve via symlink target for existing tails on Windows"
        );

        // Additionally, check std compatibility when the environment supports it.
        // Some Windows environments (certain Server builds/configs) resolve `..`
        // lexically before following the symlink, making `jail/hello/world` the
        // effective lookup which does not exist. In that case, std::fs::canonicalize
        // returns NotFound (ERROR_PATH_NOT_FOUND, code 3). Treat that as environment-specific
        // and skip only the std-compat assertion.
        match fs::canonicalize(test_path) {
            Ok(stdp) => assert_eq!(
                soft, stdp,
                "soft_canonicalize should match std when std resolves this path"
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(3) => {
                eprintln!("note: std::fs::canonicalize returned NotFound for symlink/.. path on this Windows environment; skipping std-compat sub-assertion");
            }
            Err(e) => return Err(e),
        }
    }

    #[cfg(feature = "dunce")]
    {
        let soft = soft_canonicalize(test_path)?;
        // With dunce: our result is simplified, std is UNC
        let soft_str = soft.to_string_lossy();
        let expected_str = expected.to_string_lossy();
        assert!(!soft_str.starts_with(r"\\?\"), "dunce should simplify");
        assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        assert_eq!(
            soft_str.as_ref(),
            expected_str.trim_start_matches(r"\\?\"),
            "soft_canonicalize should resolve via symlink target for existing tails on Windows"
        );
    }

    Ok(())
}
