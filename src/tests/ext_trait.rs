//! Tests for the [`SoftCanonicalizeExt`] extension trait.
//!
//! The trait is a thin re-spelling of the free [`crate::soft_canonicalize`]
//! function, paralleling the inherent [`std::path::Path::canonicalize`] method.
//! These tests pin three invariants:
//!
//! 1. Method-call form (`path.soft_canonicalize()`) yields exactly the same
//!    result as the free-function form for the same input.
//! 2. The trait dispatches through `Path` for both `&Path` receivers and
//!    `PathBuf` receivers (the latter via `Deref` coercion), so callers do
//!    not need a separate `PathBuf` impl in scope.
//! 3. Error semantics (NUL rejection, empty-path rejection) flow through the
//!    trait unchanged — sealing the trait must not introduce a wrapper that
//!    swallows or reshapes errors.

use crate::soft_canonicalize;
use crate::SoftCanonicalizeExt;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

#[test]
fn trait_on_path_matches_free_function_existing() -> std::io::Result<()> {
    let dir = tempdir()?;
    let p: &Path = dir.path();

    let via_trait = p.soft_canonicalize()?;
    let via_free = soft_canonicalize(p)?;
    assert_eq!(via_trait, via_free);
    Ok(())
}

#[test]
fn trait_on_pathbuf_matches_free_function_existing() -> std::io::Result<()> {
    let dir = tempdir()?;
    let p: PathBuf = dir.path().to_path_buf();

    let via_trait = p.soft_canonicalize()?;
    let via_free = soft_canonicalize(&p)?;
    assert_eq!(via_trait, via_free);
    Ok(())
}

#[test]
fn trait_on_pathbuf_matches_free_function_nonexistent_suffix() -> std::io::Result<()> {
    let dir = tempdir()?;
    let p: PathBuf = dir.path().join("does").join("not").join("exist.txt");

    let via_trait = p.soft_canonicalize()?;
    let via_free = soft_canonicalize(&p)?;
    assert_eq!(via_trait, via_free);
    Ok(())
}

#[test]
fn trait_on_path_propagates_empty_path_error() {
    let p = Path::new("");
    let err = p
        .soft_canonicalize()
        .expect_err("empty path must error like the free function");
    let free_err = soft_canonicalize(p).expect_err("free function must agree");
    assert_eq!(err.kind(), free_err.kind());
}

#[cfg(unix)]
#[test]
fn trait_propagates_nul_byte_error_unix() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let p = Path::new(OsStr::from_bytes(b"/tmp/has\0nul"));
    let err = p
        .soft_canonicalize()
        .expect_err("NUL must be rejected through the trait");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// Compile-time guard that the trait is sealed: this test contains an impl of
/// the public trait on a foreign type, but the impl is gated on a
/// nonexistent feature so it never compiles. If a contributor accidentally
/// removes the seal, a sibling negative-compile test (e.g. trybuild) should
/// catch it; here we just document the intent.
#[cfg(any())]
mod _seal_intent {
    struct LocalNewtype;
    impl crate::SoftCanonicalizeExt for LocalNewtype {
        fn soft_canonicalize(&self) -> std::io::Result<std::path::PathBuf> {
            unreachable!()
        }
    }
}
