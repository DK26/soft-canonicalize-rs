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
    fs::create_dir(special_target)?;

    // Create the destination path that will exist after clamping and traversal
    // This ensures canonicalization can expand 8.3 short names in the full path
    let clamped_base = anchor.join("opt").join("subdir");
    fs::create_dir_all(&clamped_base)?;
    let hello_world = clamped_base.join("hello").join("world");
    fs::create_dir_all(hello_world)?;

    let base = soft_canonicalize(&anchor)?; // extended-length form

    let link = base.join("special");
    // Create a RELATIVE symlink from link location to target
    // link: TempDir/home/jail/special
    // target: TempDir/opt/subdir/special
    // relative path from link to target: ../../opt/subdir/special
    let relative_target = r"..\..\opt\subdir\special";
    match symlink_dir(relative_target, link) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // Test: Relative symlink resolution with path traversal
    // The symlink is relative: special -> ../../opt/subdir/special
    // When we traverse: special/.../hello/world
    // The symlink resolves to: anchor/../../opt/subdir/special (normalized: TempDir/opt/subdir/special)
    // With virtual filesystem clamping: relative symlinks stay clamped to anchor
    // So the resolved path becomes: anchor/opt/subdir/special
    // Then .. brings us to: anchor/opt/subdir
    // Finally adding hello/world: anchor/opt/subdir/hello/world
    let out = anchored_canonicalize(&base, r"special\..\hello\world")?;
    let expected = base.join("opt").join("subdir").join("hello").join("world");
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

#[test]
fn anchored_toctou_symlink_swap_to_unc_is_clamped_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;
    use std::thread;
    use std::time::Duration;

    let td = TempDir::new()?;
    let anchor = td.path().join("root");
    let safe_target = td.path().join("safe");
    std::fs::create_dir_all(&anchor)?;
    std::fs::create_dir_all(&safe_target)?;

    let base = soft_canonicalize(&anchor)?;
    let link = base.join("esc");

    // Start with symlink pointing to a safe absolute dir
    match symlink_dir(&safe_target, &link) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // Spawn a thread to swap the symlink to a UNC absolute path while resolving
    let link_swap = link;
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));
        let _ = std::fs::remove_dir(&link_swap);
        // Point at a UNC absolute path (won't be accessed; purely lexical)
        let _ = symlink_dir(r"\\?\UNC\server\share", &link_swap);
    });

    // Resolve via anchor while the swap may occur
    let out = anchored_canonicalize(&base, r"esc\child.txt")?;
    handle.join().ok();

    // Must remain clamped under the anchor regardless of swap
    assert!(out.starts_with(&base));
    Ok(())
}

#[test]
fn anchored_toctou_symlink_swap_to_device_is_clamped_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;
    use std::thread;
    use std::time::Duration;

    let td = TempDir::new()?;
    let anchor = td.path().join("root");
    let safe_target = td.path().join("safe");
    std::fs::create_dir_all(&anchor)?;
    std::fs::create_dir_all(&safe_target)?;

    let base = soft_canonicalize(&anchor)?;
    let link_dir = base.join("dirlink");

    // Start with directory symlink pointing to a safe absolute dir
    match symlink_dir(&safe_target, &link_dir) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // Spawn a thread to swap the symlink to a Device namespace path while resolving
    let link_swap = link_dir;
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));
        let _ = std::fs::remove_dir(&link_swap);
        // Attempt to point at a DeviceNS path; this may fail depending on environment
        // Treat failure as non-fatal for the test's property (we still assert clamping)
        let _ = symlink_dir(r"\\.\PIPE", &link_swap);
    });

    // Resolve via anchor while the swap may occur
    let out = anchored_canonicalize(&base, r"dirlink\child.txt")?;
    handle.join().ok();

    // Must remain clamped under the anchor regardless of swap outcome
    assert!(out.starts_with(&base));
    Ok(())
}

#[test]
fn anchored_absolute_symlink_to_device_is_clamped_windows() -> std::io::Result<()> {
    use std::io;
    use std::os::windows::fs::symlink_dir;

    let td = TempDir::new()?;
    let anchor = td.path().join("base");
    std::fs::create_dir_all(&anchor)?;

    // Use a common existing absolute directory target (device/disk path)
    // We pick C:\Windows\System32 as a real absolute directory to avoid UNC dependencies.
    let abs_target = r"C:\\Windows\\System32";

    let base = soft_canonicalize(&anchor)?;
    let link = base.join("escape");
    match symlink_dir(abs_target, link) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                eprintln!("skipping: symlink creation not permitted on this Windows environment");
                return Ok(());
            }
            return Err(e);
        }
    }

    // Absolute symlink target must be clamped under the anchor with virtual FS semantics
    let out = anchored_canonicalize(&base, "escape")?;
    // Expected: anchor + reinterpreted absolute target path (drive + components stripped)
    let expected = base.join(r"Windows\System32");
    assert_eq!(out, expected);
    Ok(())
}
