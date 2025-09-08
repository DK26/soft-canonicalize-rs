use crate::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn clamp_prevents_escape_on_lexical_dotdot() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("root");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let inputs = [
        "../../../../etc/passwd",
        "../..",
        "..",
        "./.././../relative/path",
    ];
    for inp in inputs {
        let out = anchored_canonicalize(&base, inp)?;
        assert!(
            out.starts_with(&base),
            "{inp} should be clamped under anchor"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_existing_anchor_clamp_unix() -> std::io::Result<()> {
    // Create an absolute but non-existing anchor path
    let td = TempDir::new()?;
    let anchor_missing = td.path().join("non_existing").join("anchor").join("deep");

    // Soft-canonicalize the anchor first (works even if parts don't exist)
    let base = soft_canonicalize(anchor_missing)?;

    // Attempt to escape via deep traversal; clamp should hold at the base
    let out = anchored_canonicalize(&base, "../../../../etc/passwd")?;
    assert!(out.starts_with(&base));
    assert!(out.ends_with("etc/passwd"));
    Ok(())
}

#[cfg(windows)]
#[test]
fn non_existing_anchor_clamp_windows() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor_missing = td.path().join("non_existing").join("anchor").join("deep");

    let base = soft_canonicalize(anchor_missing)?;

    let out = anchored_canonicalize(&base, r"..\..\..\etc\passwd")?;
    // Should be extended-length absolute and clamped to the non-existing anchor base
    let s = out.to_string_lossy();
    assert!(s.starts_with(r"\\?\"));
    assert!(out.starts_with(&base));
    assert!(out.ends_with("etc\\passwd") || out.ends_with("etc/passwd"));
    Ok(())
}
