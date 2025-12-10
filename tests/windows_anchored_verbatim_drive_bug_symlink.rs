//! Regression test attempting to trigger the malformed verbatim drive path bug via symlinks.
//!
//! This test tries to create conditions where `anchored_canonicalize` might construct
//! a path with a Disk prefix but no RootDir component, which would result in a
//! drive-relative path like `C:Users\...` that becomes malformed when prefixed: `\\?\C:Users\...`

#![cfg(all(feature = "anchored", windows))]

use soft_canonicalize::anchored_canonicalize;
use std::fs;
use std::os::windows::fs as windows_fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Detects malformed verbatim drive paths like "\\?\C:Users\..." (missing backslash after colon)
fn is_malformed_verbatim_drive(p: &Path) -> bool {
    let s = p.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && (b[0] as char).is_ascii_alphabetic() && b[1] == b':' {
            // Bug condition: next char after drive colon is NOT '\\' or '/'
            return b[2] != b'\\' && b[2] != b'/';
        }
    }
    false
}

/// Helper to check if we have symlink creation privileges
fn got_symlink_permission(tmpdir: &Path) -> bool {
    let link = tmpdir.join("_symlink_test");
    let target = tmpdir.join("_target");
    let _ = fs::write(&target, b"test");

    match windows_fs::symlink_file(&target, &link) {
        Ok(_) => {
            let _ = fs::remove_file(&link);
            true
        }
        Err(e) => {
            // ERROR_PRIVILEGE_NOT_HELD = 1314
            if e.raw_os_error() == Some(1314) {
                eprintln!("Skipping: symlink creation not permitted (run as admin or enable Developer Mode)");
                false
            } else {
                true
            }
        }
    }
}

#[test]
fn anchored_with_symlink_escaping_to_different_drive_structure() -> std::io::Result<()> {
    let tmpdir = TempDir::new()?;

    // Skip if no symlink permission (this test needs symlinks)
    if !got_symlink_permission(tmpdir.path()) {
        return Ok(());
    }

    let anchor = tmpdir.path().join("jail");
    fs::create_dir_all(&anchor)?;

    // Create a symlink inside the anchor that points to an absolute path
    // This could potentially trigger the component reconstruction bug
    let link = anchor.join("escape_link");
    let target = PathBuf::from(r"C:\Windows\System32");

    // Create symlink (this might fail without admin rights)
    if let Err(e) = windows_fs::symlink_dir(target, link) {
        if e.raw_os_error() == Some(1314) {
            eprintln!("Skipping: symlink creation not permitted");
            return Ok(());
        }
        return Err(e);
    }

    // Now try to resolve through the symlink with anchored_canonicalize
    let result = anchored_canonicalize(&anchor, "escape_link/notepad.exe")?;

    eprintln!("anchor: {:?}", anchor);
    eprintln!("result: {:?}", result);

    // The result must not be malformed
    assert!(
        !is_malformed_verbatim_drive(&result),
        "BUG FOUND: anchored_canonicalize returned malformed verbatim drive path: {:?}",
        result
    );

    // The result must start with anchor (clamping semantics) - tolerate verbatim prefix differences
    let anchor_canonical = fs::canonicalize(&anchor)?;
    let result_s = result.to_string_lossy();
    let anchor_s = anchor_canonical.to_string_lossy();
    let result_norm = result_s.trim_start_matches(r"\\?\");
    let anchor_norm = anchor_s.trim_start_matches(r"\\?\");
    assert!(
        result_norm.starts_with(anchor_norm),
        "Result {} should start with anchor {} (virtual filesystem semantics)",
        result_s,
        anchor_s
    );

    Ok(())
}

#[test]
fn anchored_with_symlink_chain_component_reconstruction() -> std::io::Result<()> {
    let tmpdir = TempDir::new()?;

    if !got_symlink_permission(tmpdir.path()) {
        return Ok(());
    }

    let anchor = tmpdir.path().join("root");
    fs::create_dir_all(&anchor)?;

    // Create a more complex scenario: symlink chain
    let link1 = anchor.join("link1");
    let link2 = anchor.join("link2");
    let target = anchor.join("data");
    fs::create_dir_all(&target)?;

    // link1 -> link2 -> data
    windows_fs::symlink_dir(&link2, link1)?;
    windows_fs::symlink_dir(target, link2)?;

    let result = anchored_canonicalize(&anchor, "link1/file.txt")?;

    eprintln!("anchor: {:?}", anchor);
    eprintln!("result: {:?}", result);

    assert!(
        !is_malformed_verbatim_drive(&result),
        "BUG FOUND: Symlink chain produced malformed verbatim drive path: {:?}",
        result
    );

    Ok(())
}

#[test]
fn anchored_with_drive_relative_constructed_components_should_be_well_formed() -> std::io::Result<()>
{
    // Deliberately create a drive-relative intermediate by pushing onto a Disk prefix base
    // Then ensure anchored_canonicalize never returns a malformed verbatim path.

    let anchor = std::fs::canonicalize(std::env::temp_dir())?;

    // Build a candidate that when naively joined component-wise could resemble a drive-relative form
    // We use an absolute-like candidate to exercise the stripping of RootDir/Prefix in the loop
    let candidate = "/data/drive/relative";

    let out = anchored_canonicalize(&anchor, candidate)?;

    // Must be absolute and well-formed; if buggy code created a drive-relative base before
    // adding the extended-length prefix, we'd see \\\\?\\C:Users\\... here.
    let s = out.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        if rest.len() >= 2 && rest.chars().nth(1) == Some(':') {
            assert!(
                rest.chars().nth(2) == Some('\\') || rest.chars().nth(2) == Some('/'),
                "BUG: Verbatim drive path missing backslash after colon: {:?}",
                out
            );
        }
    }

    // Also ensure it stays under anchor (normalize verbatim differences)
    let out_s = out.to_string_lossy();
    let anchor_s = anchor.to_string_lossy();
    let out_norm = out_s.trim_start_matches(r"\\?\");
    let anchor_norm = anchor_s.trim_start_matches(r"\\?\");
    assert!(
        out_norm.starts_with(anchor_norm),
        "Output {} must start with anchor {}",
        out_s,
        anchor_s
    );

    Ok(())
}

#[test]
fn manually_construct_drive_relative_path_and_test() -> std::io::Result<()> {
    // This test manually constructs what we suspect might be the bug condition:
    // A PathBuf with Disk prefix but no RootDir component

    use std::path::{Component, Prefix};

    // Try to manually construct a drive-relative path
    // Keep function body minimal; we rely on anchored_canonicalize behavior, not manual construction

    // We can't easily construct this directly via public APIs,
    // but we can demonstrate the problem with ensure_windows_extended_prefix

    // Instead, let's test what happens if we push components incorrectly
    let anchor = std::fs::canonicalize(std::env::temp_dir())?;

    // Test various edge cases
    let candidates = vec![
        "/",
        "/a",
        "/data",
        "/data/",
        "/data/dir",
        "//data",
        "///data",
    ];

    for candidate in candidates {
        let result = anchored_canonicalize(&anchor, candidate)?;

        eprintln!("Testing: {:?} -> {:?}", candidate, result);

        // Check that result is not malformed
        assert!(
            !is_malformed_verbatim_drive(&result),
            "Candidate {:?} produced malformed verbatim drive path: {:?}",
            candidate,
            result
        );

        // Verify component structure
        let components: Vec<_> = result.components().collect();
        eprintln!("  Components: {:?}", components);

        // If we have a Disk prefix, the next component MUST be RootDir
        if let Some(Component::Prefix(p)) = components.first() {
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                assert!(
                    matches!(components.get(1), Some(Component::RootDir)),
                    "BUG FOUND: Disk prefix not followed by RootDir in {:?}. Components: {:?}",
                    result,
                    components
                );
            }
        }
    }

    Ok(())
}
