#![cfg(target_os = "macos")]
//! macOS-Specific Security Tests — Part 2: /private Symlink Family and System Symlink Depth Budget
//!
//! Covers:
//! 3. `/private` symlink family (`/tmp`, `/var`, `/etc` → `/private/…`)
//! 4. System symlink depth-budget heuristic (`is_likely_system_symlink`)

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io;
use std::path::Path;
use tempfile::TempDir;

// ─── 3. /private Symlink Family ─────────────────────────────────────────────

mod private_symlinks {
    use super::*;

    #[test]
    fn tmp_resolves_to_private_tmp() -> io::Result<()> {
        // /tmp is a symlink to /private/tmp on macOS
        if Path::new("/tmp").exists() {
            let result = soft_canonicalize("/tmp")?;
            let expected = std::fs::canonicalize("/tmp")?;
            assert_eq!(result, expected);

            // Verify it goes through /private
            assert!(
                result.starts_with("/private"),
                "/tmp should resolve to /private/tmp: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn etc_resolves_to_private_etc() -> io::Result<()> {
        // /etc is a symlink to /private/etc on macOS
        if Path::new("/etc").exists() {
            let result = soft_canonicalize("/etc")?;
            let expected = std::fs::canonicalize("/etc")?;
            assert_eq!(result, expected);

            assert!(
                result.starts_with("/private"),
                "/etc should resolve to /private/etc: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn var_resolves_to_private_var() -> io::Result<()> {
        if Path::new("/var").exists() {
            let result = soft_canonicalize("/var")?;
            let expected = std::fs::canonicalize("/var")?;
            assert_eq!(result, expected);

            assert!(
                result.starts_with("/private"),
                "/var should resolve to /private/var: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn tmp_with_nonexisting_suffix() -> io::Result<()> {
        let leaf = "softcanon_macos_test_abcdef.txt";
        let path = format!("/tmp/{leaf}");

        let result = soft_canonicalize(&path)?;
        let expected = std::fs::canonicalize("/tmp")?.join(leaf);
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn etc_with_existing_file() -> io::Result<()> {
        // /etc/hosts exists on all macOS systems
        let path = Path::new("/etc/hosts");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn private_directly_matches_symlink() -> io::Result<()> {
        // Accessing /private/tmp directly vs /tmp should give same result
        if Path::new("/private/tmp").exists() && Path::new("/tmp").exists() {
            let via_symlink = soft_canonicalize("/tmp")?;
            let via_direct = soft_canonicalize("/private/tmp")?;
            assert_eq!(via_symlink, via_direct);
        }
        Ok(())
    }

    #[test]
    fn dotdot_from_private_tmp_to_private() -> io::Result<()> {
        // /tmp/../etc should resolve through /private
        let path = "/tmp/../etc/hosts";
        if Path::new("/etc/hosts").exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize("/etc/hosts")?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn var_folders_temp_dir() -> io::Result<()> {
        // macOS temp directories are often under /var/folders/…
        // Verify TempDir paths canonicalize correctly through the /var → /private/var symlink
        let tmp = TempDir::new()?;
        let file = tmp.path().join("test.txt");
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);

        // On macOS, TempDir is usually under /private/var/folders or /private/tmp
        let result_str = result.to_string_lossy();
        assert!(
            result_str.starts_with("/private"),
            "TempDir should resolve through /private: {result_str}"
        );
        Ok(())
    }

    #[test]
    fn symlink_chain_through_private() -> io::Result<()> {
        // Create a symlink chain: link1 → /tmp/subdir → (which is really /private/tmp/subdir)
        let tmp = TempDir::new()?;
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir)?;
        fs::write(real_dir.join("target.txt"), b"data")?;

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link)?;

        let result = soft_canonicalize(link.join("target.txt"))?;
        let expected = std::fs::canonicalize(real_dir.join("target.txt"))?;
        assert_eq!(result, expected);
        Ok(())
    }
}

// ─── 4. System Symlink Depth Budget Heuristic ────────────────────────────────

mod system_symlink_budget {
    use super::*;

    #[test]
    fn var_does_not_exhaust_depth_budget() -> io::Result<()> {
        // /var → /private/var consumes 1 symlink level.
        // Our heuristic reduces budget for /var paths to 5, which is still enough.
        // Create a chain through /var that exercises the heuristic.
        let tmp = TempDir::new()?;

        // Create a moderate symlink chain inside the temp dir (which is under /var)
        let dir = tmp.path().join("chain");
        fs::create_dir(&dir)?;
        fs::write(dir.join("target.txt"), b"data")?;

        // 3-level chain: l1 → l2 → l3 → chain
        let l3 = tmp.path().join("l3");
        std::os::unix::fs::symlink(&dir, &l3)?;
        let l2 = tmp.path().join("l2");
        std::os::unix::fs::symlink(&l3, &l2)?;
        let l1 = tmp.path().join("l1");
        std::os::unix::fs::symlink(&l2, &l1)?;

        // This should resolve despite the reduced budget
        let result = soft_canonicalize(l1.join("target.txt"))?;
        let expected = std::fs::canonicalize(l1.join("target.txt"))?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn etc_does_not_exhaust_depth_budget() -> io::Result<()> {
        // /etc → /private/etc is a system symlink.
        // Verify an existing file under /etc resolves correctly.
        let path = Path::new("/etc/hosts");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn tmp_tempdir_chain_within_budget() -> io::Result<()> {
        // TempDir on macOS is typically under /tmp or /var/tmp, both system symlinks.
        // Create the max budget chain (budget = 5, minus 1 for /var symlink = 4 remaining)
        let tmp = TempDir::new()?;
        let target = tmp.path().join("leaf");
        fs::create_dir(&target)?;

        let mut current = target.clone();
        for i in 0..4 {
            let link = tmp.path().join(format!("hop{i}"));
            std::os::unix::fs::symlink(&current, &link)?;
            current = link;
        }

        let result = soft_canonicalize(&current)?;
        let expected = std::fs::canonicalize(&current)?;
        assert_eq!(result, expected);
        Ok(())
    }
}
