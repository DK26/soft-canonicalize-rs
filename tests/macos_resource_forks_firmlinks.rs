#![cfg(target_os = "macos")]
//! macOS-Specific Security Tests — Part 3: Resource Forks, Firmlinks, and /dev/fd Paths
//!
//! Covers:
//! 5. Resource forks / named forks (`..namedfork/rsrc`)
//! 6. Firmlinks (`/Users` ↔ `/System/Volumes/Data/Users`)
//! 7. `/dev/fd/N` file descriptor paths (macOS equivalent of `/proc/self/fd`)

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io;
use std::path::Path;
use tempfile::TempDir;

// ─── 5. Resource Forks / Named Forks ─────────────────────────────────────────

mod resource_forks {
    use super::*;

    #[test]
    fn namedfork_rsrc_path() -> io::Result<()> {
        // macOS supports resource forks via `file/..namedfork/rsrc`
        // This is a special path component that accesses the resource fork
        let tmp = TempDir::new()?;
        let file = tmp.path().join("test.txt");
        fs::write(&file, b"data")?;

        let rsrc_path = file.join("..namedfork").join("rsrc");
        let result = soft_canonicalize(&rsrc_path);
        // The resource fork may or may not exist, but the function must not panic
        // and should either resolve it or return a clean error
        if let Ok(p) = result {
            // If it resolves, verify it's sensible
            let p_str = p.to_string_lossy();
            assert!(
                p_str.contains("test.txt"),
                "Resource fork path should reference the base file: {p_str}"
            );
        }
        Ok(())
    }

    #[test]
    fn namedfork_as_traversal_attempt() -> io::Result<()> {
        // Verify `..namedfork` is not confused with `..` (parent) traversal
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("subdir");
        fs::create_dir(&dir)?;
        let file = dir.join("test.txt");
        fs::write(&file, b"data")?;

        // `..namedfork` is NOT `..` — it should not traverse up
        let path = dir.join("..namedfork");
        let result = soft_canonicalize(&path);
        if let Ok(p) = result {
            // Must not resolve to tmp.path() (parent) — ..namedfork is not ..
            assert!(
                p.starts_with(std::fs::canonicalize(&dir).unwrap_or(dir.clone())),
                "..namedfork must not act as parent traversal: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn namedfork_with_nonexisting_suffix() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let file = tmp.path().join("base.txt");
        fs::write(&file, b"data")?;

        // Non-existing path through a named fork
        let path = file.join("..namedfork").join("rsrc").join("evil.txt");
        let result = soft_canonicalize(&path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }
}

// ─── 6. Firmlinks ───────────────────────────────────────────────────────────

mod firmlinks {
    use super::*;

    #[test]
    fn users_firmlink_consistency() -> io::Result<()> {
        // On macOS Catalina+, /Users is a firmlink to /System/Volumes/Data/Users
        // Both paths should resolve to the same canonical path
        let users = Path::new("/Users");
        let data_users = Path::new("/System/Volumes/Data/Users");

        if users.exists() && data_users.exists() {
            let result_users = soft_canonicalize(users)?;
            let result_data = soft_canonicalize(data_users)?;
            let expected_users = std::fs::canonicalize(users)?;
            let expected_data = std::fs::canonicalize(data_users)?;

            // Match std behavior — whether they resolve to the same path depends
            // on how macOS handles firmlinks in realpath()
            assert_eq!(result_users, expected_users);
            assert_eq!(result_data, expected_data);
        }
        Ok(())
    }

    #[test]
    fn applications_firmlink() -> io::Result<()> {
        let apps = Path::new("/Applications");
        if apps.exists() {
            let result = soft_canonicalize(apps)?;
            let expected = std::fs::canonicalize(apps)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn library_firmlink() -> io::Result<()> {
        let lib = Path::new("/Library");
        if lib.exists() {
            let result = soft_canonicalize(lib)?;
            let expected = std::fs::canonicalize(lib)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn system_library_deep_path() -> io::Result<()> {
        // /System/Library exists on all macOS
        let path = Path::new("/System/Library");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn firmlink_with_nonexisting_suffix() -> io::Result<()> {
        let users = Path::new("/Users");
        if users.exists() {
            let path = users
                .join("nonexistent_user_softcanon_test")
                .join("file.txt");
            let result = soft_canonicalize(&path)?;
            let canonical_users = std::fs::canonicalize(users)?;
            assert_eq!(
                result,
                canonical_users
                    .join("nonexistent_user_softcanon_test")
                    .join("file.txt")
            );
        }
        Ok(())
    }
}

// ─── 7. /dev/fd/N Paths ────────────────────────────────────────────────────

mod dev_fd {
    use super::*;

    #[test]
    fn dev_fd_stdin() -> io::Result<()> {
        // /dev/fd/0 is stdin on macOS (equivalent to /proc/self/fd/0 on Linux)
        let path = Path::new("/dev/fd/0");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dev_fd_with_nonexisting_suffix() -> io::Result<()> {
        // /dev/fd is a directory on macOS — trying to traverse past a fd number
        let path = Path::new("/dev/fd/999999/evil/passwd");
        let result = soft_canonicalize(path);
        // Must not panic — likely errors since fd 999999 doesn't exist
        if let Ok(p) = result {
            // Should not resolve to something outside /dev
            assert!(
                p.starts_with("/dev"),
                "/dev/fd traversal must stay in /dev: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn dev_fd_dotdot_escape_attempt() -> io::Result<()> {
        // Try to use /dev/fd/../../../etc/passwd
        let path = Path::new("/dev/fd/../../../etc/passwd");
        if Path::new("/etc/passwd").exists() {
            let result = soft_canonicalize(path)?;
            // This should resolve /dev/fd/.. to /dev, then ../../etc/passwd to /etc/passwd
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dev_null_consistency() -> io::Result<()> {
        let result = soft_canonicalize("/dev/null")?;
        let expected = std::fs::canonicalize("/dev/null")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn dev_stderr_fd() -> io::Result<()> {
        // /dev/fd/2 = stderr
        let path = Path::new("/dev/fd/2");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }
}
