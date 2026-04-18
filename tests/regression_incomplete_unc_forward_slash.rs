//! Regression test: `//server` (forward-slash incomplete UNC) must be rejected
//! with our path-aware `InvalidInput` error, identical to the backslash form.
//!
//! Before the fix, `is_incomplete_unc` only matched paths starting with `\\`.
//! A forward-slash form like `//server` slipped past the guard and relied on
//! stdlib's generic error. We want defense-in-depth that does not depend on
//! stdlib's treatment of forward-slash UNCs.

#![cfg(windows)]

use soft_canonicalize::{soft_canonicalize, IoErrorPathExt};
use std::io;

#[test]
fn forward_slash_incomplete_unc_rejected_with_our_detail() {
    let err =
        soft_canonicalize("//server").expect_err("forward-slash incomplete UNC must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        err.soft_canon_detail(),
        Some("invalid UNC path: missing share"),
        "expected our path-aware detail, got: {:?}",
        err.soft_canon_detail()
    );
}

#[test]
fn forward_slash_incomplete_unc_matches_backslash_form() {
    let backslash_err =
        soft_canonicalize(r"\\server").expect_err("backslash incomplete UNC must be rejected");
    let forward_err =
        soft_canonicalize("//server").expect_err("forward-slash incomplete UNC must be rejected");
    assert_eq!(backslash_err.kind(), forward_err.kind());
    assert_eq!(
        backslash_err.soft_canon_detail(),
        forward_err.soft_canon_detail(),
        "forward-slash and backslash forms must produce identical details"
    );
}

#[cfg(feature = "anchored")]
#[test]
fn anchored_forward_slash_incomplete_unc_rejected() {
    use soft_canonicalize::anchored_canonicalize;
    let err = anchored_canonicalize("//server", "foo")
        .expect_err("forward-slash incomplete UNC anchor must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        err.soft_canon_detail(),
        Some("invalid UNC path: missing share"),
    );
}
