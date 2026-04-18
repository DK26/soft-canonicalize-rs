//! Regression test: a path containing an embedded NUL byte must be rejected
//! by *our* `reject_nul_bytes` check (not by stdlib's canonicalize), so callers
//! can reliably identify the failure via `soft_canon_detail()`.
//!
//! Before the fix, `reject_nul_bytes` ran in Stage 3.1 — after both
//! `fs_canonicalize` fast-paths. Stdlib rejected the NUL first with a generic
//! `InvalidInput`, our detail was never attached, and callers had no stable
//! way to distinguish "NUL byte" from other `InvalidInput` causes.
//!
//! After the fix, the NUL check runs in Stage 0 (before any FS contact), so
//! our detail string is always observable.

use soft_canonicalize::{soft_canonicalize, IoErrorPathExt};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

fn path_with_embedded_nul() -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        // `/tmp/foo\0bar` — absolute to skip cwd join; contains an embedded NUL.
        PathBuf::from(OsString::from_vec(b"/tmp/foo\0bar".to_vec()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        // `C:\foo\0bar` as UTF-16 code units with an embedded NUL unit.
        let units: Vec<u16> = "C:\\foo"
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .chain("bar".encode_utf16())
            .collect();
        PathBuf::from(OsString::from_wide(&units))
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("foo\0bar")
    }
}

#[test]
fn embedded_nul_rejected_with_our_detail() {
    let path = path_with_embedded_nul();
    let err = soft_canonicalize(path).expect_err("embedded NUL must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        err.soft_canon_detail(),
        Some("path contains null byte"),
        "expected our path-aware detail, got: {:?}",
        err.soft_canon_detail()
    );
}

#[test]
fn embedded_nul_error_carries_offending_path() {
    let path = path_with_embedded_nul();
    let err = soft_canonicalize(&path).expect_err("embedded NUL must be rejected");
    assert_eq!(
        err.offending_path(),
        Some(path.as_path()),
        "error must carry the offending path for diagnostics"
    );
}

#[cfg(feature = "anchored")]
#[test]
fn anchored_embedded_nul_in_input_rejected_with_our_detail() {
    use soft_canonicalize::anchored_canonicalize;
    let anchor = std::env::temp_dir();
    let input = {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(OsString::from_vec(b"foo\0bar".to_vec()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let units: Vec<u16> = "foo"
                .encode_utf16()
                .chain(std::iter::once(0u16))
                .chain("bar".encode_utf16())
                .collect();
            PathBuf::from(OsString::from_wide(&units))
        }
        #[cfg(not(any(unix, windows)))]
        {
            PathBuf::from("foo\0bar")
        }
    };
    let err =
        anchored_canonicalize(anchor, input).expect_err("embedded NUL in input must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(err.soft_canon_detail(), Some("path contains null byte"));
}
