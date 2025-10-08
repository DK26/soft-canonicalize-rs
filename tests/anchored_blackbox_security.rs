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

        // Compute exact expected under virtual FS semantics
        let expected = match inp {
            // Absolute path: clamp to anchor
            "/etc/passwd" => {
                #[cfg(windows)]
                {
                    base.join(r"etc\passwd")
                }
                #[cfg(not(windows))]
                {
                    base.join("etc/passwd")
                }
            }
            // Deep dotdot: clamp to anchor
            s if s.starts_with("../") || s.contains("/../") => {
                #[cfg(windows)]
                {
                    base.join(r"etc\passwd")
                }
                #[cfg(not(windows))]
                {
                    base.join("etc/passwd")
                }
            }
            // Percent-encoded traversal: treated literally
            s if s.contains("%2e") => base.join(s),
            // Regular relative path
            s => base.join(s),
        };

        assert_eq!(out, expected);

        // Blackbox: ensure we do not decode percent-encodings when present
        let s = out.to_string_lossy();
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
    #[cfg(windows)]
    let expected = base.join(r"etc\passwd");
    #[cfg(not(windows))]
    let expected = base.join("etc/passwd");
    assert_eq!(out, expected);
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
    let expected = base.join(inp);
    assert_eq!(out, expected);
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
fn blackbox_absolute_symlink_is_clamped() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;

    let td = TempDir::new()?;
    let anchor = td.path().join("root");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let outside = td.path().join("outside/dir");
    fs::create_dir_all(&outside)?;
    let abs_outside = fs::canonicalize(&outside)?;

    // Create symlink pointing to absolute path outside anchor
    symlink(&abs_outside, base.join("escape"))?;

    // With new clamping behavior, absolute symlinks are reinterpreted relative to anchor
    let out = anchored_canonicalize(&base, "escape")?;

    // The symlink target /tmp/.tmpXXXX/outside/dir becomes anchor/tmp/.tmpXXXX/outside/dir
    // (root prefix stripped, then joined to anchor)
    assert!(
        out.starts_with(&base),
        "Result should be under anchor: {:?} should start with {:?}",
        out,
        base
    );
    assert_eq!(out, base.join(abs_outside.strip_prefix("/").unwrap()));
    Ok(())
}
