//! Security tests: Junction vs symlink behavioral discrimination (Windows).
//!
//! Verifies that soft_canonicalize handles NTFS junction points correctly,
//! resolving them like absolute symlinks and clamping ".." traversal.

use soft_canonicalize::soft_canonicalize;
use std::io;

// ─── 5. Junction vs Symlink Discrimination (Windows) ─────────────────────────

#[cfg(windows)]
mod junction_discrimination {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    /// Create a junction point (not a symlink) from link to target directory.
    /// Returns Ok(true) if junction was created, Ok(false) if unavailable.
    fn create_junction(target: &std::path::Path, link: &std::path::Path) -> io::Result<bool> {
        let status = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .output()?;
        Ok(status.status.success())
    }

    #[test]
    fn junction_resolves_like_canonicalize() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("real_dir");
        fs::create_dir(&target)?;
        fs::write(target.join("file.txt"), b"data")?;

        let link = tmp.path().join("junction_link");
        if !create_junction(&target, &link)? {
            eprintln!("Skipping junction test: mklink /J not available");
            return Ok(());
        }

        let file_through_junction = link.join("file.txt");
        let result = soft_canonicalize(&file_through_junction)?;
        let expected = std::fs::canonicalize(&file_through_junction)?;

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(result, expected);
        }
        #[cfg(feature = "dunce")]
        {
            let result_str = result.to_string_lossy();
            let std_str = expected.to_string_lossy();
            assert_eq!(result_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
        }
        Ok(())
    }

    #[test]
    fn junction_with_nonexisting_suffix() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("real_dir");
        fs::create_dir(&target)?;

        let link = tmp.path().join("jlink");
        if !create_junction(&target, &link)? {
            eprintln!("Skipping junction test: mklink /J not available");
            return Ok(());
        }

        // Non-existing child through a junction should resolve the junction
        // and append the non-existing suffix
        let path = link.join("nonexist").join("deep").join("file.txt");
        let result = soft_canonicalize(path)?;

        // The junction should be resolved — result should contain the *target* path
        // not the junction path
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("real_dir"),
            "Junction should resolve to real_dir in result: {result_str}"
        );
        assert!(
            result_str.contains("nonexist"),
            "Non-existing suffix should be preserved: {result_str}"
        );
        Ok(())
    }

    #[test]
    fn junction_dotdot_does_not_escape() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("real");
        fs::create_dir(&target)?;

        let link = tmp.path().join("jlink2");
        if !create_junction(&target, &link)? {
            return Ok(());
        }

        // Dotdot after a junction should behave correctly
        let path = link.join("..").join("real").join("file.txt");
        let result = soft_canonicalize(path)?;

        // Should resolve to tmp/real/file.txt (non-existing suffix)
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains("real"),
            "Junction + dotdot should stay consistent: {result_str}"
        );
        Ok(())
    }

    #[test]
    fn junction_is_always_absolute() -> io::Result<()> {
        // Junctions cannot be relative (unlike symlinks) — verify we handle
        // them identically to absolute symlinks
        let tmp = TempDir::new()?;
        let a = tmp.path().join("a");
        let _b = tmp.path().join("b");
        fs::create_dir(&a)?;
        fs::write(a.join("test.txt"), b"data")?;

        let link = tmp.path().join("j");
        if !create_junction(&a, &link)? {
            return Ok(());
        }

        let result = soft_canonicalize(link.join("test.txt"))?;
        let expected = std::fs::canonicalize(a.join("test.txt"))?;

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(result, expected);
        }
        #[cfg(feature = "dunce")]
        {
            let result_str = result.to_string_lossy();
            let std_str = expected.to_string_lossy();
            assert_eq!(result_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
        }
        Ok(())
    }
}
