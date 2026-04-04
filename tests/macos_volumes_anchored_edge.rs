#![cfg(target_os = "macos")]
//! macOS-Specific Security Tests — Part 4: Volumes, Anchored Canonicalize, and Edge Cases
//!
//! Covers:
//! 8. Mounted volume paths (`/Volumes/…`)
//! 9. Anchored canonicalize: macOS-specific behaviors
//! 10. macOS-specific edge cases (dot-underscore files, .DS_Store, spaces, long names, etc.)

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io;
use std::path::Path;
use tempfile::TempDir;

// ─── 8. Volumes Mount Points ────────────────────────────────────────────────

mod volumes {
    use super::*;

    #[test]
    fn volumes_directory_exists() -> io::Result<()> {
        // /Volumes always exists on macOS
        let path = Path::new("/Volumes");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn volumes_with_nonexisting_mount() -> io::Result<()> {
        // Non-existing volume mount point
        let path = Path::new("/Volumes/NonExistentDisk_SoftCanon/file.txt");
        let result = soft_canonicalize(path)?;
        let canonical_volumes = std::fs::canonicalize("/Volumes")?;
        assert_eq!(
            result,
            canonical_volumes
                .join("NonExistentDisk_SoftCanon")
                .join("file.txt")
        );
        Ok(())
    }

    #[test]
    fn macintosh_hd_volume() -> io::Result<()> {
        // The main volume is often accessible at /Volumes/Macintosh HD
        let path = Path::new("/Volumes/Macintosh HD");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dotdot_from_volumes_mount() -> io::Result<()> {
        // Traversing up from a mount point
        let path = Path::new("/Volumes/../etc/hosts");
        if Path::new("/etc/hosts").exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize("/etc/hosts")?;
            assert_eq!(result, expected);
        }
        Ok(())
    }
}

// ─── 9. Anchored Canonicalize: macOS-specific ───────────────────────────────

#[cfg(feature = "anchored")]
mod anchored_macos {
    use soft_canonicalize::anchored_canonicalize;
    use std::fs;
    use std::io;
    use tempfile::TempDir;

    #[test]
    fn anchored_resolves_through_private() -> io::Result<()> {
        // Anchor under /tmp (which resolves to /private/tmp)
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir(&anchor)?;

        let result = anchored_canonicalize(&anchor, "child/file.txt")?;
        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;

        assert!(
            result.starts_with(&canonical_anchor),
            "Anchored result should be within canonicalized anchor: {result:?}"
        );
        // Verify /private prefix
        assert!(
            result.to_string_lossy().starts_with("/private"),
            "macOS anchored result should go through /private: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn anchored_nfd_input() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir(&anchor)?;

        // NFD input should be preserved as non-existing suffix
        let nfd_input = "cafe\u{0301}/file.txt";
        let result = anchored_canonicalize(&anchor, nfd_input)?;
        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;

        assert!(
            result.starts_with(&canonical_anchor),
            "NFD input must stay within anchor: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn anchored_case_mismatch_in_anchor() -> io::Result<()> {
        // Anchor with wrong case — should still resolve correctly on macOS
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("MyAnchor");
        fs::create_dir(&anchor)?;

        let wrong_case_anchor = tmp.path().join("myanchor");
        let result = anchored_canonicalize(&wrong_case_anchor, "file.txt")?;

        // On case-insensitive macOS, this should resolve
        let canonical_anchor = std::fs::canonicalize(&anchor)?;
        assert!(
            result.starts_with(&canonical_anchor),
            "Case-insensitive anchor must resolve: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn anchored_symlink_escape_through_private_clamped() -> io::Result<()> {
        // Symlink inside anchor that points to /etc (→ /private/etc)
        // Should be clamped to the anchor
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir(&anchor)?;

        let link = anchor.join("escape");
        std::os::unix::fs::symlink("/etc", &link)?;

        let result = anchored_canonicalize(&anchor, "escape/hosts")?;
        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;

        assert!(
            result.starts_with(&canonical_anchor),
            "Symlink to /etc must be clamped to anchor: {result:?}"
        );
        // The escape should be reinterpreted within the anchor, NOT follow to /private/etc
        Ok(())
    }
}

// ─── 10. macOS-Specific Edge Cases ──────────────────────────────────────────

mod macos_edge_cases {
    use super::*;

    #[test]
    fn dot_underscore_file() -> io::Result<()> {
        // macOS creates ._filename files for extended attributes on non-HFS volumes
        let tmp = TempDir::new()?;
        let file = tmp.path().join("._test.txt");
        fs::write(&file, b"xattr")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn ds_store_file() -> io::Result<()> {
        // .DS_Store is a common macOS file in directories
        let tmp = TempDir::new()?;
        let file = tmp.path().join(".DS_Store");
        fs::write(&file, b"store")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn hidden_directory_with_dot_prefix() -> io::Result<()> {
        // macOS has many dot-prefixed hidden directories
        let tmp = TempDir::new()?;
        let dir = tmp.path().join(".hidden_dir");
        fs::create_dir(&dir)?;
        let file = dir.join("file.txt");
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn space_in_path_component() -> io::Result<()> {
        // macOS commonly has spaces in paths (e.g., "Macintosh HD", "Application Support")
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("Application Support");
        fs::create_dir(&dir)?;
        let file = dir.join("My Config.plist");
        fs::write(&file, b"xml")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn very_long_utf8_filename() -> io::Result<()> {
        // APFS supports filenames up to 255 UTF-8 bytes
        let tmp = TempDir::new()?;

        // Use multi-byte characters to approach the limit
        // Each é in NFC is 2 bytes, so 127 of them = 254 bytes + ".t" = boundary
        let long_name = "\u{00E9}".repeat(120) + ".t";
        let file = tmp.path().join(&long_name);

        if let Ok(()) = fs::write(&file, b"data") {
            let result = soft_canonicalize(&file)?;
            let expected = std::fs::canonicalize(&file)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn usr_bin_through_firmlink() -> io::Result<()> {
        // /usr/bin exists on all macOS systems
        let path = Path::new("/usr/bin");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn usr_local_through_nonexisting() -> io::Result<()> {
        // /usr/local/bin might or might not exist, test with non-existing suffix
        let path = Path::new("/usr/local/bin/softcanon_test_nonexistent_binary");
        let result = soft_canonicalize(path)?;

        // The existing prefix (/usr/local/bin or /usr/local or /usr) should be canonicalized
        let result_str = result.to_string_lossy();
        assert!(
            result_str.starts_with("/usr"),
            "Should preserve /usr prefix: {result_str}"
        );
        assert!(
            result_str.contains("softcanon_test_nonexistent_binary"),
            "Should preserve non-existing suffix"
        );
        Ok(())
    }

    #[test]
    fn symlink_to_system_binary() -> io::Result<()> {
        // Create a symlink to a system binary (e.g., /bin/sh)
        let tmp = TempDir::new()?;
        let link = tmp.path().join("my_sh");
        if Path::new("/bin/sh").exists() {
            std::os::unix::fs::symlink("/bin/sh", &link)?;
            let result = soft_canonicalize(&link)?;
            let expected = std::fs::canonicalize(&link)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn multiple_symlinks_through_system_paths() -> io::Result<()> {
        // Chain: link1 → /tmp/dir → (resolves to /private/tmp/dir) → link_inside → target
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("target_dir");
        fs::create_dir(&dir)?;
        let target_file = dir.join("goal.txt");
        fs::write(&target_file, b"goal")?;

        // Create an inner symlink to the file
        let inner_link = dir.join("inner_link");
        std::os::unix::fs::symlink(&target_file, &inner_link)?;

        // Create an outer symlink to inner_link
        let outer_link = tmp.path().join("outer_link");
        std::os::unix::fs::symlink(&inner_link, &outer_link)?;

        let result = soft_canonicalize(&outer_link)?;
        let expected = std::fs::canonicalize(&outer_link)?;
        assert_eq!(result, expected);
        Ok(())
    }
}
