//! Cross-platform ADS Security Tests
//!
//! Tests that paths containing colons (the ADS separator on Windows) are handled
//! correctly on both platforms. On Windows, colons trigger ADS validation. On Unix,
//! colons are legal filename characters and should be treated literally.

use soft_canonicalize::soft_canonicalize;
use std::io;

// ─── Unix: colons in filenames are legal literal characters ───────────────────

#[cfg(unix)]
mod unix_colon_as_literal {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn colon_in_filename_is_literal() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let file = tmp.path().join("file:stream");
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let canonical_tmp = std::fs::canonicalize(tmp.path())?;
        assert_eq!(result, canonical_tmp.join("file:stream"));
        Ok(())
    }

    #[test]
    fn multiple_colons_in_filename_literal() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let file = tmp.path().join("a:b:c:d");
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let canonical_tmp = std::fs::canonicalize(tmp.path())?;
        assert_eq!(result, canonical_tmp.join("a:b:c:d"));
        Ok(())
    }

    #[test]
    fn colon_in_directory_name_literal() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("dir:name");
        fs::create_dir(&dir)?;
        let file = dir.join("file.txt");
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let canonical_tmp = std::fs::canonicalize(tmp.path())?;
        assert_eq!(result, canonical_tmp.join("dir:name").join("file.txt"));
        Ok(())
    }

    #[test]
    fn colon_filename_with_nonexisting_suffix() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("dir:colon");
        fs::create_dir(&dir)?;

        // Non-existing child under a colon-containing directory
        let path = dir.join("nonexisting.txt");
        let result = soft_canonicalize(path)?;
        let canonical_tmp = std::fs::canonicalize(tmp.path())?;
        assert_eq!(
            result,
            canonical_tmp.join("dir:colon").join("nonexisting.txt")
        );
        Ok(())
    }

    #[test]
    fn colon_does_not_trigger_ads_rejection_on_unix() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // Patterns that would be rejected as ADS traversal on Windows must succeed on Unix
        let dir = tmp.path().join("base");
        fs::create_dir(&dir)?;

        let patterns = [
            "file:stream:$DATA",
            "file:..\\evil",
            "file: :$DATA",
            "file:CON",
        ];
        for pattern in &patterns {
            let file = dir.join(pattern);
            // On Unix these are just literal filenames; the function should NOT reject them
            // as InvalidInput. They may fail with NotFound if the file doesn't exist,
            // but they must NOT fail with InvalidInput.
            match soft_canonicalize(&file) {
                Ok(_) => {} // Fine — might exist or be treated as non-existing suffix
                Err(e) => {
                    assert_ne!(
                        e.kind(),
                        io::ErrorKind::InvalidInput,
                        "Pattern '{pattern}' must not be rejected as InvalidInput on Unix"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn symlink_to_colon_filename() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("real:file");
        fs::write(&target, b"data")?;

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link)?;

        let result = soft_canonicalize(&link)?;
        let canonical_tmp = std::fs::canonicalize(tmp.path())?;
        assert_eq!(result, canonical_tmp.join("real:file"));
        Ok(())
    }
}

// ─── Windows: ADS validation must fire for colon-containing components ───────

#[cfg(windows)]
mod windows_ads_cross_platform_invariants {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn ads_traversal_rejected_on_windows() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let base = tmp.path().join("file.txt");
        fs::write(&base, b"data")?;

        // These patterns must be rejected as InvalidInput on Windows
        let attacks = [
            r"file.txt:..\..\evil",
            r"file.txt:stream\..\evil",
            r"file.txt:../../../etc/passwd",
        ];
        for pattern in &attacks {
            let path = tmp.path().join(pattern);
            match soft_canonicalize(&path) {
                Ok(v) => {
                    panic!("Expected InvalidInput for ADS traversal '{pattern}', got Ok({v:?})")
                }
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::InvalidInput,
                    "Expected InvalidInput for ADS traversal '{pattern}', got {e:?}"
                ),
            }
        }
        Ok(())
    }

    #[test]
    fn valid_ads_accepted_on_windows() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let base = tmp.path().join("file.txt");
        fs::write(&base, b"data")?;

        // Valid ADS patterns should canonicalize without InvalidInput error
        let valid = ["file.txt:stream", "file.txt:mystream:$DATA"];
        for pattern in &valid {
            let path = tmp.path().join(pattern);
            match soft_canonicalize(&path) {
                Ok(_) => {} // Good — accepted
                Err(e) => {
                    assert_ne!(
                        e.kind(),
                        io::ErrorKind::InvalidInput,
                        "Valid ADS pattern '{pattern}' should not be rejected as InvalidInput"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn device_name_in_ads_stream_rejected() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let base = tmp.path().join("file.txt");
        fs::write(&base, b"data")?;

        let attacks = [
            "file.txt:CON",
            "file.txt:NUL",
            "file.txt:COM1",
            "file.txt:LPT1",
            "file.txt:PRN",
            "file.txt:AUX",
        ];
        for pattern in &attacks {
            let path = tmp.path().join(pattern);
            match soft_canonicalize(&path) {
                Ok(v) => {
                    panic!("Expected InvalidInput for device-name ADS '{pattern}', got Ok({v:?})")
                }
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::InvalidInput,
                    "Expected InvalidInput for device-name ADS '{pattern}', got {e:?}"
                ),
            }
        }
        Ok(())
    }

    #[test]
    fn unicode_manipulation_in_ads_rejected() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let base = tmp.path().join("file.txt");
        fs::write(&base, b"data")?;

        // Zero-width space, BOM, RTL override in stream names
        let attacks = [
            "file.txt:\u{200B}stream", // Zero-width space
            "file.txt:\u{FEFF}stream", // BOM
            "file.txt:\u{202E}stream", // RTL override
            "file.txt:\u{200D}stream", // Zero-width joiner
            "file.txt:\u{200C}stream", // Zero-width non-joiner
        ];
        for pattern in &attacks {
            let path = tmp.path().join(pattern);
            match soft_canonicalize(&path) {
                Ok(v) => panic!("Expected InvalidInput for Unicode-attack ADS, got Ok({v:?})"),
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::InvalidInput,
                    "Expected InvalidInput for Unicode-attack ADS, got {e:?}"
                ),
            }
        }
        Ok(())
    }

    #[test]
    fn non_final_colon_component_rejected() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("parent");
        fs::create_dir(dir)?;

        // ADS-containing component must be final — mid-path colons are rejected
        let path = tmp.path().join(r"parent:stream\child.txt");
        match soft_canonicalize(path) {
            Ok(v) => panic!("Expected InvalidInput for non-final ADS component, got Ok({v:?})"),
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidInput,
                "Expected InvalidInput for non-final ADS component, got {e:?}"
            ),
        }
        Ok(())
    }
}
