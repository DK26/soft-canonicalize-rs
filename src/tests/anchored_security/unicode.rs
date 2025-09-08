use crate::{anchored_canonicalize, soft_canonicalize};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn null_byte_injection_rejected() {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let td = TempDir::new().unwrap();
        let anchor = td.path().join("root");
        std::fs::create_dir_all(&anchor).unwrap();
        let base = soft_canonicalize(&anchor).unwrap();

        let null_tail = OsStr::from_bytes(b"a\0b");
        let err = anchored_canonicalize(base, Path::new(null_tail)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        let td = TempDir::new().unwrap();
        let anchor = td.path().join("root");
        std::fs::create_dir_all(&anchor).unwrap();
        let base = soft_canonicalize(&anchor).unwrap();

        let null_tail: OsString = OsString::from_wide(&[97, 0, 98]);
        let err = anchored_canonicalize(base, Path::new(&null_tail)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[test]
fn zero_width_and_control_preserved() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("r");
    std::fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let cases = [
        "file\u{200B}.txt",
        "file\u{0001}.txt",
        "résumé.txt",
        "🦀.txt",
    ];
    for c in cases {
        let out = anchored_canonicalize(&base, c)?;
        assert!(out.is_absolute());
        assert!(out.to_string_lossy().contains(".txt"));
    }
    Ok(())
}
