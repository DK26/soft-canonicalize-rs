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

#[test]
fn mixed_separator_incomplete_unc_rejected() {
    // `is_incomplete_unc` accepts all four two-separator prefix combinations:
    // `\\`, `//`, `\/`, `/\`. The backslash and forward-slash pure forms are
    // covered above; these two pin the mixed-separator variants so a future
    // refactor of the prefix-match cannot silently drop them.
    for form in [r"\/server", r"/\server"] {
        let err =
            soft_canonicalize(form).expect_err("mixed-separator incomplete UNC must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "form={form:?}");
        assert_eq!(
            err.soft_canon_detail(),
            Some("invalid UNC path: missing share"),
            "form={form:?}",
        );
    }
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

/// Contract documentation: `anchored_canonicalize` strips root/prefix markers
/// from the INPUT per spec (virtual-filesystem semantics treat all absolute
/// inputs as rooted under the anchor). `is_incomplete_unc` is only applied to
/// the ANCHOR — a malformed anchor has no meaningful virtual root — so an
/// incomplete UNC like `\\server` supplied as INPUT is NOT rejected.
///
/// Observed contract: Rust's `Path` parser treats `\\server` (and the
/// slash-variant siblings `//server`, `\/server`, `/\server`) as
/// `[RootDir, Normal("server")]` — the two leading separators are stripped
/// as root, and `server` is pushed as a Normal component. The result is
/// therefore `<anchor>/server`, not just `<anchor>`.
///
/// This test pins that behavior so a future reader does not mistake the
/// absence of rejection for a bug, and so a future refactor of the input
/// stripping cannot silently drift to a different outcome.
#[cfg(feature = "anchored")]
#[test]
fn anchored_incomplete_unc_as_input_is_stripped_not_rejected() {
    use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
    use tempfile::TempDir;

    let td = TempDir::new().expect("tempdir");
    let anchor = td.path().join("a");
    std::fs::create_dir(&anchor).expect("create anchor");
    let base = soft_canonicalize(&anchor).expect("canonicalize anchor");
    let expected = base.join("server");

    for input in [r"\\server", r"//server", r"\/server", r"/\server"] {
        let out = anchored_canonicalize(&base, input)
            .unwrap_or_else(|e| panic!("input {input:?} must NOT error: {e}"));
        assert_eq!(
            out, expected,
            "incomplete-UNC input {input:?} must strip leading separators \
             and land at <anchor>/server"
        );
    }
}
