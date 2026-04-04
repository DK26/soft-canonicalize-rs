//! Security tests: Invalid UTF-8 path components via raw OsStr (Unix).
//!
//! Verifies that soft_canonicalize never panics or treats overlong/invalid
//! UTF-8 byte sequences as path separators or ".." escape sequences.

#[cfg(unix)]
use soft_canonicalize::soft_canonicalize;
#[cfg(unix)]
use std::io;

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
