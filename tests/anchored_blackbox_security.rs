#![cfg(feature = "anchored")]
use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn blackbox_clamp_and_preservation() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("wwwroot");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let inputs = [
        "/etc/passwd",
        "../../../../etc/passwd",
        "documents/%2e%2e/%2e%2e/etc/passwd",
        "path.with.dots/file.txt",
    ];

    for inp in inputs {
        let out = anchored_canonicalize(&base, inp)?;
        assert!(out.is_absolute());
        assert!(out.starts_with(&base));
        let s = out.to_string_lossy();
        // Blackbox: ensure we do not decode percent-encodings when present
        if inp.contains("%2e") {
            assert!(s.contains("%2e"));
        }
        if inp.ends_with("file.txt") {
            assert!(s.contains("file.txt"));
        }
    }
    Ok(())
}

#[test]
fn deep_dotdot_chain_is_clamped() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("root");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let tail = "../".repeat(2048) + "etc/passwd";
    let out = anchored_canonicalize(&base, tail)?;
    assert!(out.starts_with(&base));
    assert!(out.ends_with("etc/passwd") || out.ends_with("etc\\passwd"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_backslash_is_literal_not_separator() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("u");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let inp = r"a\..\b\c.txt"; // backslashes are regular chars on Unix
    let out = anchored_canonicalize(&base, inp)?;
    assert!(out.starts_with(&base));
    // Ensure the backslashes are preserved in the final string
    assert!(out.to_string_lossy().contains("\\..\\b\\c.txt"));
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_device_and_verbatim_inputs_are_sandboxed() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("a").join("b");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    // Attempt device/verbatim inputs; they should be stripped and clamped under the anchor
    let inputs = [
        r"\\.\C:\Windows\System32",
        r"\\?\C:\Windows\System32",
        r"\\?\UNC\server\share\folder",
    ];
    for inp in inputs {
        let out = anchored_canonicalize(&base, inp)?;
        assert!(out.starts_with(&base));
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_ads_percent_encoded_colon_is_not_decoded() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("x");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    // %3A should not be decoded into ':'
    let inp = r"file%3A.txt:stream"; // Final colon is real ADS separator; the %3A must remain text
    let out = anchored_canonicalize(base, inp)?;
    let s = out.to_string_lossy();
    assert!(s.contains("file%3A.txt"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn blackbox_absolute_symlink_escape_allowed() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;

    let td = TempDir::new()?;
    let anchor = td.path().join("root");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let outside = td.path().join("outside/dir");
    fs::create_dir_all(&outside)?;
    let abs_outside = fs::canonicalize(&outside)?;

    symlink(&abs_outside, base.join("escape"))?;
    let out = anchored_canonicalize(&base, "escape")?;
    assert_eq!(out, abs_outside);
    Ok(())
}
