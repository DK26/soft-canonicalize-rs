use crate::{anchored_canonicalize, soft_canonicalize};
use std::path::PathBuf;

#[test]
fn unc_anchor_clamp_floor_respected() -> std::io::Result<()> {
    // This is a structural test: we don't create real shares, but we
    // simulate a UNC-looking anchor (already canonicalized) and ensure
    // clamp semantics apply to the suffix lexically.
    // On actual systems, soft_canonicalize would convert a real UNC to extended-length UNC.

    // Construct a fake UNC extended-length base like \\?\UNC\server\share
    let base = PathBuf::from(r"\\?\UNC\server\share");
    let canon_base = soft_canonicalize(&base).unwrap_or(base.clone());
    let out = anchored_canonicalize(&base, r"..\..\etc\passwd")?;
    assert!(out.starts_with(canon_base));
    Ok(())
}
