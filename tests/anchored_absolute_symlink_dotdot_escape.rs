//! Security regression: `anchored_canonicalize` must not leak `..` components
//! into its output when an absolute symlink target contains `..` segments.
//!
//! # Bug
//!
//! In `src/symlink.rs::resolve_anchored_symlink_chain`, the branch that handles
//! absolute symlink targets outside the anchor strips only the leading root
//! separator from the RAW (un-normalized) target and joins the remainder to
//! the anchor. Unlike the relative-symlink branch (which runs
//! `simple_normalize_path` and clamps via common-ancestor), the absolute branch
//! never normalizes `..` in the target. If the symlink points at an absolute
//! path whose components include `..` (legal as symlink text, collapsed at
//! root by the kernel), the resulting `anchor.join(..)` path contains literal
//! `..` that escape the anchor when resolved by the OS.
//!
//! # Contract violation
//!
//! `anchored_canonicalize` documents virtual-filesystem / chroot-like semantics:
//!   > All absolute symlink targets are clamped to the anchor.
//!   > Safe: always stays within workspace_root, even if symlink points outside.
//!
//! A returned path that contains `..` is NOT clamped — any caller that uses it
//! (File::open, fs::read, fs::canonicalize, etc.) has the `..` resolved by the
//! OS and escapes the anchor.
//!
//! # Reproduction (Unix)
//!
//! Create a symlink inside the anchor whose raw absolute target begins with
//! `..` after the leading slash, e.g. `/../sibling/file`. `anchored_canonicalize`
//! returns `<anchor>/../sibling/file`, which reads the sibling file when opened.

#![cfg(all(unix, feature = "anchored"))]

use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Component;
use tempfile::TempDir;

#[test]
fn absolute_symlink_target_with_leading_dotdot_must_not_escape_anchor() {
    let tmp = TempDir::new().unwrap();

    // Layout:
    //   <tmp>/sandbox           (anchor)
    //   <tmp>/sandbox/link      (symlink we create)
    //   <tmp>/outside_secret    (sibling of the anchor — "attacker loot")
    let anchor = tmp.path().join("sandbox");
    fs::create_dir(&anchor).unwrap();

    let secret_path = tmp.path().join("outside_secret");
    fs::write(secret_path, b"CONFIDENTIAL").unwrap();

    // Raw absolute symlink target "/../outside_secret":
    //   - is_absolute() == true (leading "/")
    //   - kernel resolves to "/outside_secret" when accessed directly
    //   - but soft-canonicalize only strips the leading "/" and rejoins to anchor,
    //     producing "<anchor>/../outside_secret" — which the kernel will resolve
    //     to "<tmp>/outside_secret" and READ THE SECRET.
    let link = anchor.join("link");
    symlink("/../outside_secret", link).unwrap();

    let clamped = anchored_canonicalize(&anchor, "link")
        .expect("anchored_canonicalize should succeed on a valid symlink");

    // --- Contract 1 (primary): exact clamped path ---
    // The raw target "/../outside_secret" has its leading slash stripped to
    // "../outside_secret", then the ".." is popped with an empty stack (clamp
    // to anchor floor), leaving just "outside_secret" to be joined onto the
    // canonicalized anchor. Asserting the full expected PathBuf pins the
    // clamp contract directly, without relying on the OS resolving the result.
    let expected = soft_canonicalize(&anchor).unwrap().join("outside_secret");
    assert_eq!(
        clamped, expected,
        "anchored_canonicalize must clamp absolute '..'-bearing symlink target \
         to anchor floor; got {clamped:?}, expected {expected:?}"
    );

    // --- Contract 2 (invariant): output must not contain ".." components ---
    // Subsumed by Contract 1 for this exact input, but keeps a fast local
    // invariant check that any future change to the expected-path shape
    // cannot silently re-introduce literal ".." into the output.
    let leaked_dotdot = clamped
        .components()
        .any(|c| matches!(c, Component::ParentDir));
    assert!(
        !leaked_dotdot,
        "anchored_canonicalize leaked '..' into output; anchor escape is possible \
         when the caller consumes this path: {clamped:?}"
    );
}

#[test]
fn absolute_symlink_target_with_interior_dotdot_must_not_escape_anchor() {
    // Variant: ".." appears after some path components, not just at the start.
    // Same class of bug — the absolute-symlink branch never normalizes the target.
    let tmp = TempDir::new().unwrap();

    let anchor = tmp.path().join("sandbox");
    fs::create_dir(&anchor).unwrap();

    let secret_path = tmp.path().join("outside_secret2");
    fs::write(secret_path, b"TOPSECRET").unwrap();

    // Target "/foo/../../outside_secret2":
    //   - strip_root_prefix → "foo/../../outside_secret2"
    //   - anchor.join(...) → "<anchor>/foo/../../outside_secret2"
    //   - OS resolves: <anchor>/foo doesn't exist, but kernel will still apply
    //     ".." relative to <anchor>, reaching <anchor>/.. == <tmp>, then
    //     <tmp>/../outside_secret2 = <tmp_parent>/outside_secret2 — NOT what we want
    //     for escape UNLESS <anchor>/foo exists. Create it so the ".." collapses
    //     cleanly and lands inside <tmp>.
    fs::create_dir(anchor.join("foo")).unwrap();

    let link = anchor.join("link");
    symlink("/foo/../../outside_secret2", link).unwrap();

    let clamped =
        anchored_canonicalize(&anchor, "link").expect("anchored_canonicalize should succeed");

    // --- Contract 1 (primary): exact clamped path ---
    // Strip root → "foo/../../outside_secret2". Normalize with clamp:
    //   push "foo"            stack: [foo]
    //   ".."  pop             stack: []
    //   ".."  clamp (empty)   stack: []
    //   push "outside_secret2" stack: [outside_secret2]
    // Final: <canonical_anchor>/outside_secret2.
    let expected = soft_canonicalize(&anchor).unwrap().join("outside_secret2");
    assert_eq!(
        clamped, expected,
        "anchored_canonicalize must clamp interior-'..'-bearing symlink target \
         to anchor floor; got {clamped:?}, expected {expected:?}"
    );

    // --- Contract 2 (invariant): output must not contain ".." components ---
    let leaked_dotdot = clamped
        .components()
        .any(|c| matches!(c, Component::ParentDir));
    assert!(
        !leaked_dotdot,
        "anchored_canonicalize leaked '..' into output (interior ..): {clamped:?}"
    );
}
