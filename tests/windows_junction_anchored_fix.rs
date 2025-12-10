//! Regression test for junction following in anchored_canonicalize.
//!
//! Bug: When a junction inside the anchor points to a directory also within the anchor,
//! the path resolution was incorrectly handling the prefix mismatch between the anchor
//! (\\?\C:\...) and the junction target (C:\...), causing path duplication or CWD insertion.
//!
//! Fix: Use component-aware comparison that treats VerbatimDisk(C) and Disk(C) as equivalent
//! when checking if the junction target is within the anchor.
//!
//! This test suite ensures the bug can never return by testing:
//! - Basic junction following within anchor
//! - File access through junctions
//! - Junction escape clamping
//! - Chained junctions
//! - Non-existing suffixes through junctions
//! - Multiple junctions in path
//! - CWD non-contamination (core bug symptom)
//! - Symlinks (when privileges available)

#![cfg(all(windows, feature = "anchored"))]

use soft_canonicalize::anchored_canonicalize;
use std::fs;
use std::path::Path;

/// Helper macro for dunce-aware path comparison.
/// When dunce feature is enabled, our library returns simplified paths (no `\\?\` prefix)
/// while std::fs::canonicalize always returns UNC format on Windows.
macro_rules! assert_std_compat {
    ($result:expr, $expected_std:expr, $msg:expr) => {
        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!($result, $expected_std, "{}", $msg);
        }
        #[cfg(feature = "dunce")]
        {
            let result_str = $result.to_string_lossy();
            let std_str = $expected_std.to_string_lossy();
            // std returns \\?\C:\... but dunce simplifies to C:\...
            let std_stripped = std_str.trim_start_matches(r"\\?\");
            assert_eq!(
                result_str.as_ref(),
                std_stripped,
                "{}\nResult: {}\nExpected (stripped): {}",
                $msg,
                result_str,
                std_stripped
            );
        }
    };
}

fn create_junction(junction: &Path, target: &Path) -> std::io::Result<()> {
    let output = std::process::Command::new("cmd")
        .args([
            "/c",
            "mklink",
            "/J",
            &junction.to_string_lossy(),
            &target.to_string_lossy(),
        ])
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "mklink /J failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ))
    }
}

fn create_symlink_dir(link: &Path, target: &Path) -> std::io::Result<bool> {
    let output = std::process::Command::new("cmd")
        .args([
            "/c",
            "mklink",
            "/D",
            &link.to_string_lossy(),
            &target.to_string_lossy(),
        ])
        .output()?;

    if output.status.success() {
        Ok(true)
    } else {
        // Check for privilege error (1314 = ERROR_PRIVILEGE_NOT_HELD)
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("privilege") || stderr.contains("1314") {
            Ok(false) // No symlink privileges
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mklink /D failed: {}", stderr),
            ))
        }
    }
}

/// Test that junction following produces correct paths when the junction target
/// is within the same anchor directory.
#[test]
fn test_junction_within_anchor_produces_correct_path() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    // Create structure: anchor/data/dir and anchor/links/junc -> anchor/data/dir
    fs::create_dir_all(anchor.join("data").join("dir"))?;
    fs::create_dir_all(anchor.join("links"))?;

    let junction = anchor.join("links").join("junc");
    let target = anchor.join("data").join("dir");

    // Create junction pointing to target
    create_junction(&junction, &target)?;

    // Test anchored_canonicalize following the junction
    let result = anchored_canonicalize(anchor, "links/junc")?;

    // Expected: the canonicalized path to data/dir
    let expected = std::fs::canonicalize(&target)?;

    // Verify the result matches expected (accounting for dunce feature)
    assert_std_compat!(
        result,
        expected,
        "Junction following should resolve to the target directory."
    );

    // Also verify the path doesn't contain any unexpected components
    // (no CWD insertion, no path duplication)
    let result_str = result.to_string_lossy();

    // Get anchor string in the same format as result (dunce-aware)
    #[cfg(not(feature = "dunce"))]
    let anchor_str = std::fs::canonicalize(anchor)?.to_string_lossy().to_string();
    #[cfg(feature = "dunce")]
    let anchor_str = std::fs::canonicalize(anchor)?
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();

    // The result should start with the anchor
    assert!(
        result_str.starts_with(&anchor_str),
        "Result should start with anchor.\n\
         Result: {}\n\
         Anchor: {}",
        result_str,
        anchor_str
    );

    // The result should NOT contain duplicated path segments
    // Count occurrences of "data" - should be exactly 1
    let data_count = result_str.matches("data").count();
    assert_eq!(
        data_count, 1,
        "Path should not have duplicated segments. Found {} occurrences of 'data' in: {}",
        data_count, result_str
    );

    Ok(())
}

/// Test that junction following works when accessing files through the junction.
#[test]
fn test_junction_to_file_through_junction() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    // Create structure with a file: anchor/data/file.txt
    fs::create_dir_all(anchor.join("data"))?;
    fs::write(anchor.join("data").join("file.txt"), "test content")?;
    fs::create_dir_all(anchor.join("links"))?;

    let junction = anchor.join("links").join("junc");
    let target = anchor.join("data");

    // Create junction pointing to data directory
    create_junction(&junction, &target)?;

    // Access file through junction
    let result = anchored_canonicalize(anchor, "links/junc/file.txt")?;

    // Expected: the canonicalized path to data/file.txt
    let expected = std::fs::canonicalize(anchor.join("data").join("file.txt"))?;

    assert_std_compat!(
        result,
        expected,
        "File access through junction should resolve correctly."
    );

    Ok(())
}

/// Test that junction pointing outside anchor is properly clamped.
#[test]
fn test_junction_outside_anchor_is_clamped() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path().join("jail");
    let outside = tmp.path().join("outside");

    // Create structure
    fs::create_dir_all(&anchor)?;
    fs::create_dir_all(&outside)?;

    let junction = anchor.join("escape_link");

    // Create junction pointing OUTSIDE the anchor
    create_junction(&junction, &outside)?;

    // Access through junction - should be clamped to anchor
    let result = anchored_canonicalize(&anchor, "escape_link")?;

    // The result should stay within the anchor (clamped)
    let anchor_canonical = std::fs::canonicalize(&anchor)?;

    // Get anchor string in the same format as result (dunce-aware)
    #[cfg(not(feature = "dunce"))]
    let anchor_str = anchor_canonical.to_string_lossy().to_string();
    #[cfg(feature = "dunce")]
    let anchor_str = anchor_canonical
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();

    let result_str = result.to_string_lossy();

    assert!(
        result_str.starts_with(&anchor_str),
        "Junction to outside should be clamped to anchor.\n\
         Result: {}\n\
         Anchor: {}",
        result_str,
        anchor_str
    );

    Ok(())
}

/// CRITICAL: Test that CWD is NEVER inserted into the result path.
/// This is the core symptom of the original bug.
#[test]
fn test_junction_never_includes_cwd() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    // Get the current working directory
    let cwd = std::env::current_dir()?;
    let cwd_str = cwd.to_string_lossy();

    // Create structure
    fs::create_dir_all(anchor.join("data").join("subdir"))?;
    fs::create_dir_all(anchor.join("links"))?;

    let junction = anchor.join("links").join("junc");
    let target = anchor.join("data");

    create_junction(&junction, &target)?;

    // Test various path patterns through the junction
    let test_paths = [
        "links/junc",
        "links/junc/subdir",
        "links/../links/junc",
        "links/junc/.",
    ];

    for path in &test_paths {
        let result = anchored_canonicalize(anchor, path)?;
        let result_str = result.to_string_lossy();

        // The result should NEVER contain any part of the CWD
        // (unless the temp dir happens to be under CWD, which we check for)
        let anchor_canonical = std::fs::canonicalize(anchor)?;
        if !anchor_canonical.starts_with(&cwd) {
            // Only check if anchor is not under CWD
            assert!(
                !result_str.contains(&*cwd_str),
                "Result should not contain CWD!\n\
                 Path: {}\n\
                 Result: {}\n\
                 CWD: {}",
                path,
                result_str,
                cwd_str
            );
        }

        // More specific: the path after the drive prefix should start with expected content
        // It should NOT have CWD components between the drive and the anchor
        // Handle both with and without dunce feature
        #[cfg(not(feature = "dunce"))]
        let prefix_pattern = r"\\?\C:\";
        #[cfg(feature = "dunce")]
        let prefix_pattern = "C:\\";

        if let Some(after_prefix) = result_str.strip_prefix(prefix_pattern) {
            let anchor_str = anchor_canonical.to_string_lossy();
            let anchor_after_prefix = anchor_str
                .strip_prefix(r"\\?\C:\")
                .or_else(|| anchor_str.strip_prefix("C:\\"))
                .unwrap_or(&anchor_str)
                .to_string();

            assert!(
                after_prefix.starts_with(&anchor_after_prefix)
                    || anchor_after_prefix
                        .starts_with(after_prefix.split('\\').next().unwrap_or("")),
                "Path after drive prefix should relate to anchor, not CWD.\n\
                 Path: {}\n\
                 Result after prefix: {}\n\
                 Anchor after prefix: {}",
                path,
                after_prefix,
                anchor_after_prefix
            );
        }
    }

    Ok(())
}

/// Test chained junctions: junction → directory containing another junction → target
#[test]
fn test_chained_junctions() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    // Create structure with chained junctions:
    // anchor/data/final/ (actual target)
    // anchor/level1/junc1 → anchor/data (junction to data)
    // anchor/level2/junc2 → anchor/level1 (junction to level1, which contains junc1)
    // Path: level2/junc2/junc1/final → goes through junc2, then junc1, reaches data/final

    fs::create_dir_all(anchor.join("data").join("final"))?;
    fs::create_dir_all(anchor.join("level1"))?;
    fs::create_dir_all(anchor.join("level2"))?;

    // junc1 → data
    let junc1 = anchor.join("level1").join("junc1");
    create_junction(&junc1, &anchor.join("data"))?;

    // junc2 → level1 (so junc2/junc1 = level1/junc1 = data)
    let junc2 = anchor.join("level2").join("junc2");
    create_junction(&junc2, &anchor.join("level1"))?;

    // Access through both junctions: level2/junc2/junc1/final
    let result = anchored_canonicalize(anchor, "level2/junc2/junc1/final")?;

    // Should resolve to data/final
    let expected = std::fs::canonicalize(anchor.join("data").join("final"))?;

    assert_std_compat!(
        result,
        expected,
        "Chained junction should resolve correctly."
    );

    Ok(())
}

/// Test junction with non-existing suffix
#[test]
fn test_junction_with_nonexisting_suffix() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    fs::create_dir_all(anchor.join("data"))?;
    fs::create_dir_all(anchor.join("links"))?;

    let junction = anchor.join("links").join("junc");
    create_junction(&junction, &anchor.join("data"))?;

    // Access non-existing path through junction
    let result = anchored_canonicalize(anchor, "links/junc/nonexistent/file.txt")?;

    // Should be: anchor/data/nonexistent/file.txt (with proper prefix)
    let expected_base = std::fs::canonicalize(anchor.join("data"))?;
    let expected = expected_base.join("nonexistent").join("file.txt");

    assert_std_compat!(
        result,
        expected,
        "Junction with non-existing suffix should resolve correctly."
    );

    // Verify no path duplication
    let result_str = result.to_string_lossy();
    assert_eq!(
        result_str.matches("data").count(),
        1,
        "Should have exactly one 'data' component"
    );

    Ok(())
}

/// Test multiple junctions in a single path
#[test]
fn test_multiple_junctions_in_path() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    // Create: anchor/a/b/c and anchor/x/y/z
    // junc1 points to a, inside a we have junc2 pointing to x
    fs::create_dir_all(anchor.join("a").join("b").join("c"))?;
    fs::create_dir_all(anchor.join("x").join("y").join("z"))?;

    let junc1 = anchor.join("junc1");
    create_junction(&junc1, &anchor.join("a"))?;

    let junc2 = anchor.join("a").join("junc2");
    create_junction(&junc2, &anchor.join("x"))?;

    // Path: junc1/junc2/y/z (goes through two junctions)
    let result = anchored_canonicalize(anchor, "junc1/junc2/y/z")?;

    let expected = std::fs::canonicalize(anchor.join("x").join("y").join("z"))?;

    assert_std_compat!(
        result,
        expected,
        "Multiple junctions in path should resolve correctly."
    );

    Ok(())
}

/// Test junction at anchor root level
#[test]
fn test_junction_at_anchor_root() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    fs::create_dir_all(anchor.join("target_dir").join("subdir"))?;

    // Junction directly in anchor root
    let junction = anchor.join("root_junc");
    create_junction(&junction, &anchor.join("target_dir"))?;

    let result = anchored_canonicalize(anchor, "root_junc/subdir")?;

    let expected = std::fs::canonicalize(anchor.join("target_dir").join("subdir"))?;

    assert_std_compat!(
        result,
        expected,
        "Junction at anchor root should resolve correctly."
    );

    Ok(())
}

/// Test symlink (if privileges available) - same bug could affect symlinks
#[test]
fn test_symlink_within_anchor_if_privileged() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    fs::create_dir_all(anchor.join("data").join("dir"))?;
    fs::create_dir_all(anchor.join("links"))?;

    let symlink = anchor.join("links").join("sym");
    let target = anchor.join("data").join("dir");

    // Try to create symlink - skip test if no privileges
    if !create_symlink_dir(&symlink, &target)? {
        println!("Skipping symlink test: no symlink privileges");
        return Ok(());
    }

    let result = anchored_canonicalize(anchor, "links/sym")?;
    let expected = std::fs::canonicalize(&target)?;

    assert_std_compat!(
        result,
        expected,
        "Symlink following should resolve correctly."
    );

    Ok(())
}

/// Verify path never has duplicated anchor components (regression symptom)
#[test]
fn test_no_path_duplication_regression() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let anchor = tmp.path();

    // Use a distinctive directory name to detect duplication
    let unique_name = "UNIQUE_DIR_12345";
    fs::create_dir_all(anchor.join(unique_name).join("target"))?;
    fs::create_dir_all(anchor.join("links"))?;

    let junction = anchor.join("links").join("junc");
    create_junction(&junction, &anchor.join(unique_name).join("target"))?;

    let result = anchored_canonicalize(anchor, "links/junc")?;
    let result_str = result.to_string_lossy();

    // The unique name should appear exactly ONCE
    let count = result_str.matches(unique_name).count();
    assert_eq!(
        count, 1,
        "Path should contain '{}' exactly once, found {} times in: {}",
        unique_name, count, result_str
    );

    // Also check that common temp dir patterns don't duplicate
    // e.g., "AppData" or "Local" or "Temp" shouldn't appear twice
    for pattern in &["AppData", "Local", "Temp"] {
        let pat_count = result_str.matches(pattern).count();
        assert!(
            pat_count <= 1,
            "Path should not have duplicated '{}' (found {} times): {}",
            pattern,
            pat_count,
            result_str
        );
    }

    Ok(())
}
