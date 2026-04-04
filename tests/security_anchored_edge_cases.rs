//! Security tests: Anchored canonicalize — additional escape attempts.
//!
//! Verifies that anchored_canonicalize rejects null bytes, handles empty
//! inputs, and clamps arbitrarily large numbers of ".." components.

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
