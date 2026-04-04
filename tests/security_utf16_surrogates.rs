//! Security tests: Unpaired UTF-16 surrogates in path components (Windows).
//!
//! Verifies that soft_canonicalize never panics, causes UB, or loops when
//! fed WTF-16 encoded paths that contain unpaired high or low surrogates.

// ─── 1. Unpaired UTF-16 Surrogates (Windows) ────────────────────────────────

#[cfg(windows)]
mod unpaired_surrogates {
    use soft_canonicalize::soft_canonicalize;
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
