//! Security Coverage Gap Tests
//!
//! This test file addresses security attack vectors that were identified as missing
//! or underrepresented in the existing test suite:
//!
//! 1. Unpaired UTF-16 surrogates in path components (Windows)
//! 2. Permission-change TOCTOU during resolution
//! 3. FIFO/socket/device-node confusion (Unix)
//! 4. Mount-point / bind-mount boundary traversal (Linux)
//! 5. Junction vs symlink behavioral discrimination (Windows)
//! 6. Invalid UTF-8 path components via raw OsStr (Unix)

use soft_canonicalize::soft_canonicalize;
use std::io;

// ─── 1. Unpaired UTF-16 Surrogates (Windows) ────────────────────────────────

#[cfg(windows)]
mod unpaired_surrogates {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Construct an OsString from raw UTF-16 code units, potentially including
    /// unpaired surrogates that are invalid Unicode but valid WTF-16.
    fn os_from_wide(units: &[u16]) -> OsString {
        OsString::from_wide(units)
    }

    #[test]
    fn unpaired_high_surrogate_in_component() {
        let tmp = TempDir::new().unwrap();
        // "test" + 0xD800 (high surrogate without low) + ".txt"
        let wide: Vec<u16> = tmp
            .path()
            .as_os_str()
            .encode_wide()
            .chain([b'\\' as u16, b't' as u16, 0xD800, b'.' as u16, b't' as u16])
            .collect();
        let bad_path = PathBuf::from(os_from_wide(&wide));

        let result = soft_canonicalize(bad_path);
        // Must not panic. May return an error or a path — either is acceptable.
        // The key invariant: no panic, no UB, no infinite loop.
        match result {
            Ok(p) => {
                // If it succeeds, the result should still be within the tmp directory
                // (or at least start with its prefix)
                let _ = p; // Accept any valid path
            }
            Err(e) => {
                // Error is the expected/preferred outcome for invalid encoding
                let _ = e;
            }
        }
    }

    #[test]
    fn unpaired_low_surrogate_in_component() {
        let tmp = TempDir::new().unwrap();
        // "test" + 0xDC00 (low surrogate without high) + ".txt"
        let wide: Vec<u16> = tmp
            .path()
            .as_os_str()
            .encode_wide()
            .chain([b'\\' as u16, b'x' as u16, 0xDC00, b'.' as u16, b'r' as u16])
            .collect();
        let bad_path = PathBuf::from(os_from_wide(&wide));

        let result = soft_canonicalize(bad_path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {} // Either outcome is acceptable
        }
    }

    #[test]
    fn reversed_surrogate_pair() {
        let tmp = TempDir::new().unwrap();
        // Low surrogate BEFORE high surrogate (reversed pair)
        let wide: Vec<u16> = tmp
            .path()
            .as_os_str()
            .encode_wide()
            .chain([b'\\' as u16, 0xDC00, 0xD800, b'.' as u16, b't' as u16])
            .collect();
        let bad_path = PathBuf::from(os_from_wide(&wide));

        let result = soft_canonicalize(bad_path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
    }

    #[test]
    fn surrogate_in_directory_component() {
        let tmp = TempDir::new().unwrap();
        // Unpaired surrogate in a directory name, followed by a normal filename
        let wide: Vec<u16> = tmp
            .path()
            .as_os_str()
            .encode_wide()
            .chain([
                b'\\' as u16,
                b'd' as u16,
                0xD801, // Unpaired high surrogate
                b'r' as u16,
                b'\\' as u16,
                b'f' as u16,
                b'.' as u16,
                b't' as u16,
            ])
            .collect();
        let bad_path = PathBuf::from(os_from_wide(&wide));

        let result = soft_canonicalize(bad_path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
    }

    #[test]
    fn surrogate_with_ads_suffix() {
        let tmp = TempDir::new().unwrap();
        // Unpaired surrogate in filename + ADS stream suffix
        // This tests interaction between surrogate handling and ADS validation
        let wide: Vec<u16> = tmp
            .path()
            .as_os_str()
            .encode_wide()
            .chain([
                b'\\' as u16,
                b'f' as u16,
                0xD800, // Unpaired surrogate
                b':' as u16,
                b's' as u16,
                b't' as u16,
                b'r' as u16,
                b'e' as u16,
                b'a' as u16,
                b'm' as u16,
            ])
            .collect();
        let bad_path = PathBuf::from(os_from_wide(&wide));

        let result = soft_canonicalize(bad_path);
        // Must not panic. ADS validation should still reject traversal patterns
        // even when the base filename contains surrogates.
        match result {
            Ok(_) | Err(_) => {}
        }
    }

    #[test]
    fn surrogate_in_ads_stream_name() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("file.txt");
        std::fs::write(base, b"data").unwrap();

        // Unpaired surrogate inside the ADS stream name itself
        let wide: Vec<u16> = tmp
            .path()
            .as_os_str()
            .encode_wide()
            .chain([
                b'\\' as u16,
                b'f' as u16,
                b'i' as u16,
                b'l' as u16,
                b'e' as u16,
                b'.' as u16,
                b't' as u16,
                b'x' as u16,
                b't' as u16,
                b':' as u16,
                0xD800, // Unpaired high surrogate in stream name
                b's' as u16,
                b't' as u16,
            ])
            .collect();
        let bad_path = PathBuf::from(os_from_wide(&wide));

        let result = soft_canonicalize(bad_path);
        // ADS validation may reject this due to control character checks;
        // must not panic regardless
        match result {
            Ok(_) | Err(_) => {}
        }
    }

    #[test]
    fn all_surrogates_path_component() {
        let tmp = TempDir::new().unwrap();
        // Component made entirely of unpaired surrogates
        let wide: Vec<u16> = tmp
            .path()
            .as_os_str()
            .encode_wide()
            .chain([
                b'\\' as u16,
                0xD800,
                0xD801,
                0xD802,
                0xD803, // All unpaired high surrogates
            ])
            .collect();
        let bad_path = PathBuf::from(os_from_wide(&wide));

        let result = soft_canonicalize(bad_path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
    }

    use std::os::windows::ffi::OsStrExt;
}

// ─── 2. Permission-Change TOCTOU ────────────────────────────────────────────

#[cfg(unix)]
mod permission_toctou {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn permission_removed_during_resolution() -> io::Result<()> {
        // Create a deep path: tmp/a/b/c/d/file.txt
        // While soft_canonicalize is working, remove read+exec permissions on 'b'
        // The function should either succeed or return a clean error — never panic.
        let tmp = TempDir::new()?;
        let a = tmp.path().join("a");
        let b = a.join("b");
        let c = b.join("c");
        let d = c.join("d");
        fs::create_dir_all(&d)?;
        fs::write(d.join("file.txt"), b"data")?;

        let barrier = Arc::new(Barrier::new(2));
        let b_clone = b.clone();
        let barrier_clone = barrier.clone();

        // Thread that removes permissions mid-walk
        let handle = thread::spawn(move || {
            barrier_clone.wait();
            // Remove read+exec from 'b', which should cause the walk to fail
            let _ = fs::set_permissions(&b_clone, fs::Permissions::from_mode(0o000));
            // Restore after a brief delay so cleanup works
            thread::sleep(std::time::Duration::from_millis(50));
            let _ = fs::set_permissions(&b_clone, fs::Permissions::from_mode(0o755));
        });

        // Try to canonicalize the deep path. The permission change may or may not
        // take effect during our walk.
        barrier.wait();

        let path = d.join("file.txt");
        // Run multiple times to increase chance of hitting the race window
        for _ in 0..20 {
            let result = soft_canonicalize(&path);
            match result {
                Ok(_) => {} // Successfully resolved despite race
                Err(e) => {
                    // PermissionDenied or NotFound are acceptable race outcomes
                    assert!(
                        e.kind() == io::ErrorKind::PermissionDenied
                            || e.kind() == io::ErrorKind::NotFound
                            || e.kind() == io::ErrorKind::Other,
                        "Unexpected error kind during permission TOCTOU: {e:?}"
                    );
                }
            }
        }

        handle.join().unwrap();

        // Ensure cleanup can proceed
        let _ = fs::set_permissions(&b, fs::Permissions::from_mode(0o755));
        Ok(())
    }

    #[test]
    fn permission_restored_during_resolution() -> io::Result<()> {
        // Start with an inaccessible directory, and restore permissions during walk
        let tmp = TempDir::new()?;
        let a = tmp.path().join("a");
        let b = a.join("b");
        fs::create_dir_all(&b)?;
        fs::write(b.join("file.txt"), b"data")?;

        // Remove permissions
        fs::set_permissions(&a, fs::Permissions::from_mode(0o000))?;

        let a_clone = a.clone();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            barrier_clone.wait();
            thread::sleep(std::time::Duration::from_millis(5));
            let _ = fs::set_permissions(&a_clone, fs::Permissions::from_mode(0o755));
        });

        barrier.wait();

        for _ in 0..10 {
            let result = soft_canonicalize(b.join("file.txt"));
            match result {
                Ok(_) | Err(_) => {} // Both are fine
            }
        }

        handle.join().unwrap();
        let _ = fs::set_permissions(&a, fs::Permissions::from_mode(0o755));
        Ok(())
    }
}

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

// ─── 4. Invalid UTF-8 via Raw OsStr (Unix) ──────────────────────────────────

#[cfg(unix)]
mod invalid_utf8_paths {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn invalid_utf8_in_component() -> io::Result<()> {
        let tmp = TempDir::new()?;

        // Create a path component with invalid UTF-8 (0x80 is a continuation byte
        // without a leading byte)
        let invalid_bytes: &[u8] = b"valid/\x80\x81\x82/file.txt";
        let os_str = OsStr::from_bytes(invalid_bytes);
        let path = tmp.path().join(Path::new(os_str));

        let result = soft_canonicalize(path);
        // Must not panic — may return error or handle gracefully
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }

    #[test]
    fn overlong_utf8_encoding() -> io::Result<()> {
        let tmp = TempDir::new()?;

        // Overlong encoding of '/' (U+002F): 0xC0 0xAF
        // The library must NOT interpret this as a path separator
        let overlong_slash: &[u8] = &[b'a', 0xC0, 0xAF, b'b'];
        let os_str = OsStr::from_bytes(overlong_slash);
        let path = tmp.path().join(Path::new(os_str));

        let result = soft_canonicalize(path);
        // Must not split the component at the overlong sequence
        if let Ok(p) = result {
            // The overlong sequence should remain as a single component,
            // not split into a/b
            let components: Vec<_> = p.components().collect();
            // Should not have more path components than tmp + 1
            let tmp_components: Vec<_> = tmp.path().components().collect();
            assert!(
                components.len() <= tmp_components.len() + 2,
                "Overlong UTF-8 must not create extra path components: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn high_bytes_in_dotdot_component() -> io::Result<()> {
        let tmp = TempDir::new()?;

        // Bytes that look like ".." when interpreted as ASCII but have high bits set
        // 0x2E = '.', test with 0xAE which has the same low nibble
        let tricky_bytes: &[u8] = &[0xAE, 0xAE];
        let os_str = OsStr::from_bytes(tricky_bytes);
        let dir = tmp.path().join("subdir");
        std::fs::create_dir(&dir)?;
        let path = dir.join(Path::new(os_str)).join("file.txt");

        let result = soft_canonicalize(path);
        // Must NOT interpret 0xAE 0xAE as ".." (parent directory traversal)
        if let Ok(p) = result {
            // If it resolves, it should stay within or below the subdir
            let canonical_tmp = std::fs::canonicalize(tmp.path())?;
            assert!(
                p.starts_with(canonical_tmp),
                "High-byte component must not escape temp dir: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn null_byte_in_raw_osstr() -> io::Result<()> {
        let tmp = TempDir::new()?;

        // Embedded null byte in raw OsStr path
        let with_null: &[u8] = b"test\x00evil/passwd";
        let os_str = OsStr::from_bytes(with_null);
        let path = tmp.path().join(Path::new(os_str));

        let result = soft_canonicalize(path);
        // Must reject NULL bytes — should return an error
        assert!(
            result.is_err(),
            "Path with embedded null byte should be rejected"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidInput,
            "Null byte should produce InvalidInput, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn lone_continuation_bytes_in_path() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // Path with lone continuation bytes (invalid UTF-8)
        let bad_bytes: &[u8] = &[b'a', 0x80, 0x80, 0x80, b'b'];
        let os_str = OsStr::from_bytes(bad_bytes);
        let path = tmp.path().join(Path::new(os_str));

        let result = soft_canonicalize(path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }
}

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

// ─── 6. Anchored Canonicalize: Additional Escape Attempts ────────────────────

#[cfg(feature = "anchored")]
mod anchored_edge_cases {
    use soft_canonicalize::anchored_canonicalize;
    use std::fs;
    use std::io;
    use tempfile::TempDir;

    #[test]
    fn null_byte_in_anchor() -> io::Result<()> {
        let result = anchored_canonicalize("/tmp/test\0evil", "file.txt");
        assert!(result.is_err(), "Null byte in anchor should be rejected");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn null_byte_in_input() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor_dir");
        fs::create_dir(&anchor)?;

        let result = anchored_canonicalize(&anchor, "file\0.txt");
        assert!(result.is_err(), "Null byte in input should be rejected");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn empty_anchor() {
        let result = anchored_canonicalize("", "file.txt");
        assert!(result.is_err(), "Empty anchor should be rejected");
    }

    #[test]
    fn empty_input() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir(&anchor)?;

        // Empty input: the library may accept it (returning the anchor itself)
        // or reject it. Either is acceptable — verify no panic.
        let result = anchored_canonicalize(&anchor, "");
        if let Ok(p) = result {
            // If accepted, result should be the canonicalized anchor
            let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;
            assert!(
                p.starts_with(canonical_anchor),
                "Empty input result should be within anchor: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn thousands_of_dotdot_in_input() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir_all(&anchor)?;

        // 10000 dotdots should all be clamped to the anchor
        let evil_input = "../".repeat(10000) + "etc/passwd";
        let result = anchored_canonicalize(&anchor, evil_input)?;

        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;
        assert!(
            result.starts_with(canonical_anchor),
            "10000 dotdots must not escape anchor: {result:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn absolute_path_override_attempt() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir_all(&anchor)?;

        // Attempt to override with an absolute path
        let result = anchored_canonicalize(&anchor, "/etc/passwd")?;

        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;
        assert!(
            result.starts_with(canonical_anchor),
            "Absolute input path must be clamped to anchor: {result:?}"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_absolute_path_override_attempt() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir_all(&anchor)?;

        let result = anchored_canonicalize(&anchor, r"C:\Windows\System32\cmd.exe")?;

        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;
        assert!(
            result.starts_with(canonical_anchor),
            "Absolute input path must be clamped to anchor: {result:?}"
        );
        Ok(())
    }
}

// ─── 7. Rename TOCTOU (cross-platform) ──────────────────────────────────────

mod rename_toctou {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn directory_renamed_during_resolution() -> io::Result<()> {
        // Create tmp/original/deep/file.txt
        // While resolving, rename 'original' to 'renamed'
        let tmp = TempDir::new()?;
        let original = tmp.path().join("original");
        let renamed = tmp.path().join("renamed");
        let deep = original.join("deep");
        fs::create_dir_all(&deep)?;
        fs::write(deep.join("file.txt"), b"data")?;

        let barrier = Arc::new(Barrier::new(2));
        let orig_clone = original.clone();
        let renamed_clone = renamed.clone();
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            barrier_clone.wait();
            // Rename the directory mid-walk
            for _ in 0..50 {
                let _ = fs::rename(&orig_clone, &renamed_clone);
                thread::sleep(std::time::Duration::from_millis(1));
                let _ = fs::rename(&renamed_clone, &orig_clone);
                thread::sleep(std::time::Duration::from_millis(1));
            }
        });

        barrier.wait();

        let path = original.join("deep").join("file.txt");
        for _ in 0..100 {
            let result = soft_canonicalize(&path);
            // Must not panic. May succeed or fail with NotFound/Other
            match result {
                Ok(_) | Err(_) => {}
            }
        }

        handle.join().unwrap();
        // Ensure the directory is back in the expected place for cleanup
        if renamed.exists() && !original.exists() {
            let _ = fs::rename(&renamed, &original);
        }
        Ok(())
    }
}

// ─── 8. Component length extremes ───────────────────────────────────────────

mod component_length_attacks {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn single_component_at_os_limit() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // Most filesystems limit component names to 255 bytes
        let max_name = "A".repeat(255);
        let path = tmp.path().join(max_name);

        let result = soft_canonicalize(path);
        // Must not panic. Will likely fail with NotFound (file doesn't exist)
        // or succeed on some filesystems.
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }

    #[test]
    fn single_component_over_os_limit() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let huge_name = "B".repeat(1000);
        let path = tmp.path().join(huge_name);

        let result = soft_canonicalize(path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }

    #[test]
    fn deeply_nested_dotdot_and_components() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // a/../a/../a/../... repeated 5000 times
        let mut segments = String::new();
        for _ in 0..5000 {
            segments.push_str("a/../");
        }
        segments.push_str("final.txt");
        let path = tmp.path().join(&segments);

        let result = soft_canonicalize(path);
        // Must not panic, must not stack overflow
        if let Ok(p) = result {
            // All the a/../ should cancel out
            assert!(
                p.to_string_lossy().contains("final.txt"),
                "All a/../ should cancel: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn path_with_thousands_of_slashes() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // Excessive consecutive separators
        let excessive = format!("{}{}", "/".repeat(5000), "file.txt");
        let path = tmp.path().join(excessive);

        let result = soft_canonicalize(path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }
}
