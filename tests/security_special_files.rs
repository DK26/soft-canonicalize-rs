//! Security tests: FIFO / socket / device-node confusion (Unix).
//!
//! Verifies that soft_canonicalize handles special file types correctly:
//! FIFOs, Unix domain sockets, and character/block devices.

#[cfg(unix)]
use soft_canonicalize::soft_canonicalize;
#[cfg(unix)]
use std::io;

// ─── 3. FIFO / Socket / Device-Node Confusion (Unix) ────────────────────────

#[cfg(unix)]
mod special_file_types {
    use super::*;

    use tempfile::TempDir;

    #[test]
    fn fifo_as_path_component() -> io::Result<()> {
        use std::process::Command;

        let tmp = TempDir::new()?;
        let fifo = tmp.path().join("my_fifo");

        // Create a FIFO (named pipe)
        let status = Command::new("mkfifo").arg(&fifo).status();
        match status {
            Ok(s) if s.success() => {
                // The FIFO exists — canonicalize should resolve it like any other entry
                let result = soft_canonicalize(&fifo)?;
                let expected = std::fs::canonicalize(&fifo)?;
                assert_eq!(result, expected);
            }
            _ => {
                // mkfifo not available — skip
                eprintln!("Skipping FIFO test: mkfifo not available");
            }
        }
        Ok(())
    }

    #[test]
    fn unix_socket_as_path_component() -> io::Result<()> {
        use std::os::unix::net::UnixListener;

        let tmp = TempDir::new()?;
        let sock_path = tmp.path().join("test.sock");

        let _listener = UnixListener::bind(&sock_path)?;

        // Socket exists — canonicalize should resolve it
        let result = soft_canonicalize(&sock_path)?;
        let expected = std::fs::canonicalize(&sock_path)?;
        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn fifo_with_nonexisting_suffix() -> io::Result<()> {
        use std::process::Command;

        let tmp = TempDir::new()?;
        let fifo = tmp.path().join("pipe_dir");

        // A FIFO is not a directory — a path like pipe/child should fail
        let status = Command::new("mkfifo").arg(&fifo).status();
        match status {
            Ok(s) if s.success() => {
                let path_through = tmp.path().join("pipe_dir").join("child.txt");
                let result = soft_canonicalize(path_through);
                // The FIFO is not a directory, so traversing into it should fail
                // or treat "child.txt" as a non-existing suffix
                if let Ok(p) = result {
                    // If it succeeds, the result should include the non-existing suffix
                    assert!(
                        p.to_string_lossy().contains("child.txt"),
                        "Result should preserve non-existing suffix: {p:?}"
                    );
                }
            }
            _ => {
                eprintln!("Skipping FIFO suffix test: mkfifo not available");
            }
        }
        Ok(())
    }

    #[test]
    fn symlink_to_fifo() -> io::Result<()> {
        use std::process::Command;

        let tmp = TempDir::new()?;
        let fifo = tmp.path().join("actual_fifo");
        let link = tmp.path().join("link_to_fifo");

        let status = Command::new("mkfifo").arg(&fifo).status();
        match status {
            Ok(s) if s.success() => {
                std::os::unix::fs::symlink(&fifo, &link)?;

                let result = soft_canonicalize(&link)?;
                let expected = std::fs::canonicalize(&link)?;
                assert_eq!(result, expected);
            }
            _ => {
                eprintln!("Skipping symlink-to-FIFO test: mkfifo not available");
            }
        }
        Ok(())
    }

    #[test]
    fn dev_null_canonicalize() -> io::Result<()> {
        // /dev/null exists on all Unix systems
        let result = soft_canonicalize("/dev/null")?;
        let expected = std::fs::canonicalize("/dev/null")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn dev_zero_canonicalize() -> io::Result<()> {
        let path = std::path::Path::new("/dev/zero");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dev_urandom_canonicalize() -> io::Result<()> {
        let path = std::path::Path::new("/dev/urandom");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dev_device_with_nonexisting_suffix() -> io::Result<()> {
        // /dev/null/child — /dev/null is not a directory, so this should
        // treat "child" as a non-existing suffix or error out
        let path = std::path::Path::new("/dev/null/child.txt");
        let result = soft_canonicalize(path);
        if let Ok(p) = result {
            assert!(
                p.to_string_lossy().contains("child.txt"),
                "Result should preserve non-existing suffix: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn symlink_to_dev_null() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let link = tmp.path().join("null_link");
        std::os::unix::fs::symlink("/dev/null", &link)?;

        let result = soft_canonicalize(&link)?;
        let expected = std::fs::canonicalize(&link)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn block_device_traversal_attempt() -> io::Result<()> {
        // Try to use a block device as a directory (should not traverse into it)
        // /dev/sda probably exists on most Linux systems but we don't need it to
        // for this test to be valid
        let paths = ["/dev/sda/etc/passwd", "/dev/loop0/etc/passwd"];
        for path_str in &paths {
            let path = std::path::Path::new(path_str);
            let result = soft_canonicalize(path);
            if let Ok(p) = result {
                // Should NOT resolve to /etc/passwd
                assert!(
                    !p.ends_with("etc/passwd") || p.to_string_lossy().contains("dev"),
                    "Block device should not allow traversal to /etc/passwd: {p:?}"
                );
            }
        }
        Ok(())
    }
}
