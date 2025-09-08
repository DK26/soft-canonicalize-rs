use crate::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn ads_layout_validation_applies_to_input() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("x");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    // Colon in non-final component is invalid
    let err = anchored_canonicalize(&base, r"bad:part\tail").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Valid ADS only as final component should be accepted lexically
    let ok = anchored_canonicalize(&base, r"file.txt:stream");
    assert!(ok.is_ok());
    Ok(())
}

#[test]
fn extended_length_prefix_on_absolute_results() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("a").join("b");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;
    let out = anchored_canonicalize(base, r"c\d\e.txt")?;
    let s = out.to_string_lossy();
    assert!(s.starts_with(r"\\?\") || s.starts_with(r"\\?\UNC\"));
    Ok(())
}

#[test]
fn non_existing_anchor_supported_windows() -> std::io::Result<()> {
    // Anchor path does not exist; function should still succeed (soft behavior)
    let td = TempDir::new()?;
    let anchor = td.path().join("does_not_exist").join("still_missing");

    let out = anchored_canonicalize(anchor, r"subdir\file.txt")?;
    let s = out.to_string_lossy();
    assert!(s.starts_with(r"\\?\"));
    assert!(out.ends_with("subdir\\file.txt"));
    Ok(())
}
