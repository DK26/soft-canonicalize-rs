//! Windows-only: Anchored clamp with 8.3 short name and TOCTOU symlink swap
//!
//! This test exercises a race where the first component (an actual 8.3 alias
//! under the anchor) is swapped from a real directory to a dangling symlink
//! while anchored_canonicalize is resolving. We assert that:
//! - On success, traversal is clamped to the anchor and the final path equals
//!   anchor\etc\passwd (absolute, extended-length on Windows).
//! - On error, the function fails gracefully with NotFound or Other (timing-dependent).
//!
//! The test gracefully skips when 8.3 short names are not generated on the system
//! or when the process lacks symlink creation privileges (common on Windows).

#![cfg(all(windows, feature = "anchored"))]

use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Returns the actual Windows 8.3 short path for `path`, or None when not available.
fn get_short_path_name(path: &Path) -> Option<PathBuf> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetShortPathNameW(
            lpszlongpath: *const u16,
            lpszshortpath: *mut u16,
            cchbuffer: u32,
        ) -> u32;
    }

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let need = unsafe { GetShortPathNameW(wide.as_ptr(), std::ptr::null_mut(), 0) };
    if need == 0 {
        return None;
    }
    let mut buf = vec![0u16; need as usize];
    let wrote = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), need) };
    if wrote == 0 || wrote >= need {
        return None;
    }
    buf.truncate(wrote as usize);
    Some(PathBuf::from(OsString::from_wide(&buf)))
}

/// Quick probe to see if symlink creation is permitted (Windows often requires elevation).
fn have_symlink_permission(tmp: &TempDir) -> bool {
    let target = tmp.path().join("_perm_target");
    let link = tmp.path().join("_perm_link");
    let _ = fs::create_dir(&target);
    let ok = std::os::windows::fs::symlink_dir(&target, &link).is_ok();
    let _ = fs::remove_dir_all(&link);
    let _ = fs::remove_dir_all(&target);
    ok
}

/// Test anchored clamping with 8.3 component and TOCTOU symlink swap.
/// CRITICAL: This test has THREE paths to ensure we don't hide edge cases:
/// 1. Full race test (8.3 + symlink swap) when both conditions are met
/// 2. Static test (8.3 without race) when symlinks unavailable
/// 3. Lexical fallback (8.3-like pattern) when real 8.3 unavailable
#[test]
fn test_anchored_clamp_with_8_3_and_toctou() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let anchor = tmp.path().join("anchor");
    fs::create_dir(&anchor)?;

    let can_symlink = have_symlink_permission(&tmp);

    // Try to get a real 8.3 short name
    let long = anchor.join("VeryLongDirectoryNameThatExceedsEightCharacters_Alpha");
    fs::create_dir(&long)?;
    fs::create_dir(long.join("inner"))?;

    let real_8_3 = get_short_path_name(&long)
        .filter(|short| short != &long)
        .and_then(|short| short.file_name().and_then(|s| s.to_str()).map(String::from))
        .filter(|s| s.contains('~'));

    match (can_symlink, real_8_3) {
        // PATH 1: Full race test with real 8.3 + symlink swap
        (true, Some(short_name)) => {
            eprintln!("Running FULL test: 8.3 + TOCTOU race");
            test_with_race(&anchor, &long, &short_name)?;
        }
        // PATH 2: Static test with real 8.3, no race
        (false, Some(short_name)) => {
            eprintln!("Running PARTIAL test: 8.3 without symlink race (no privileges)");
            test_static_8_3_clamp(&anchor, &short_name)?;
        }
        // PATH 3: Lexical test with 8.3-like pattern
        _ => {
            eprintln!(
                "Running FALLBACK test: lexical 8.3-like pattern (no real 8.3 or no symlinks)"
            );
            test_lexical_8_3_clamp(&anchor)?;
        }
    }

    Ok(())
}

/// Full test: Real 8.3 component with TOCTOU symlink swap race
fn test_with_race(
    anchor: &std::path::Path,
    long: &std::path::Path,
    short_name: &str,
) -> io::Result<()> {
    let input = PathBuf::from(short_name)
        .join("..")
        .join("..")
        .join("etc")
        .join("passwd");

    let anchor_clone = anchor.to_path_buf();
    let long_clone = long.to_path_buf();

    let race = thread::spawn(move || {
        thread::sleep(Duration::from_millis(5));
        let renamed = anchor_clone.join("__long_orig");
        if fs::rename(&long_clone, &renamed).is_ok() {
            let _ =
                std::os::windows::fs::symlink_dir(anchor_clone.join("does_not_exist"), &long_clone);
            let _ = fs::remove_dir_all(&renamed);
        }
    });

    let result = anchored_canonicalize(anchor, input);
    let _ = race.join();

    let abs_anchor = soft_canonicalize(anchor)?;
    let expected = abs_anchor.join(r"etc\passwd");

    match result {
        Ok(out) => {
            assert_eq!(out, expected, "TOCTOU race must preserve clamp");
        }
        Err(e) => {
            assert!(
                e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::Other,
                "Race error must be benign, got: {:?}",
                e.kind()
            );
        }
    }
    Ok(())
}

/// Partial test: Real 8.3 without race (when no symlink privileges)
fn test_static_8_3_clamp(anchor: &std::path::Path, short_name: &str) -> io::Result<()> {
    let input = PathBuf::from(short_name)
        .join("..")
        .join("..")
        .join("etc")
        .join("passwd");

    let abs_anchor = soft_canonicalize(anchor)?;
    let expected = abs_anchor.join(r"etc\passwd");

    let result = anchored_canonicalize(anchor, input)?;
    assert_eq!(result, expected, "8.3 traversal must clamp without race");
    Ok(())
}

/// Fallback test: Lexical 8.3-like pattern (when no real 8.3 available)
fn test_lexical_8_3_clamp(anchor: &std::path::Path) -> io::Result<()> {
    // Use a lexical 8.3-like pattern that won't exist
    let input = PathBuf::from("SOMEDI~1")
        .join("..")
        .join("..")
        .join("etc")
        .join("passwd");

    let abs_anchor = soft_canonicalize(anchor)?;
    let expected = abs_anchor.join(r"etc\passwd");

    let result = anchored_canonicalize(anchor, input)?;
    assert_eq!(result, expected, "Lexical 8.3-like pattern must clamp");
    Ok(())
}

#[cfg(all(windows, not(feature = "anchored")))]
#[test]
fn placeholder_without_anchored_feature() {
    // This test requires the 'anchored' feature; run with --all-features.
    eprintln!("Skipping windows_8_3_toctou_anchored: 'anchored' feature not enabled");
}

#[cfg(not(windows))]
#[test]
fn placeholder_non_windows() {
    eprintln!("Skipping windows_8_3_toctou_anchored: Windows-only test");
}
