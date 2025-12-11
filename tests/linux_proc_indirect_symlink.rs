//! Tests for indirect symlinks to `/proc/PID/root` magic paths.
//!
//! This test suite validates the bug where symlinks pointing to `/proc/PID/root`
//! bypass the protection because the input path doesn't lexically start with `/proc/`.
//!
//! **These tests are expected to FAIL** until `proc-canonicalize` is upgraded
//! to v0.0.3+ which fixes the indirect symlink bypass.
//!
//! Related issue: `proc-canonicalize` indirect symlink bypass
//! Fixed in: `proc-canonicalize` v0.0.3
//!
//! Run with: `cargo test --test linux_proc_indirect_symlink -- --nocapture`

#![cfg(target_os = "linux")]

use soft_canonicalize::soft_canonicalize;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// Test that an indirect symlink to `/proc/self/root` preserves the namespace boundary.
///
/// **Bug:** Currently returns `/` because `std::fs::canonicalize` resolves the magic symlink.
/// **Expected:** Should return `/proc/self/root` to preserve the namespace boundary.
#[test]
fn test_indirect_symlink_to_proc_self_root() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("link_to_proc");

    // Create symlink: link_to_proc -> /proc/self/root
    if let Err(e) = symlink("/proc/self/root", &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    let result = soft_canonicalize(&link_path).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", link_path);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Result must NOT be "/" for container boundary enforcement
    assert_ne!(
        result,
        PathBuf::from("/"),
        "SECURITY BUG: Indirect symlink to /proc/self/root resolved to '/' - \
         container isolation is bypassed! The result should preserve /proc/self/root prefix."
    );

    // The result should preserve /proc/self/root prefix
    assert!(
        result.starts_with("/proc/self/root"),
        "Expected /proc/self/root prefix, got: {:?}",
        result
    );
}

/// Test indirect symlink to `/proc/PID/root` with numeric PID.
#[test]
fn test_indirect_symlink_to_proc_pid_root() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("container_root");

    let pid = std::process::id();
    let proc_pid_root = format!("/proc/{}/root", pid);

    // Create symlink: container_root -> /proc/{pid}/root
    if let Err(e) = symlink(&proc_pid_root, &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    let result = soft_canonicalize(&link_path).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", link_path);
    println!("Target: {}", proc_pid_root);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Must not resolve to "/"
    assert_ne!(
        result,
        PathBuf::from("/"),
        "SECURITY BUG: Indirect symlink to {} resolved to '/' - \
         namespace boundary lost!",
        proc_pid_root
    );

    // Should preserve the /proc/PID/root prefix
    assert!(
        result.starts_with(&proc_pid_root),
        "Expected {} prefix, got: {:?}",
        proc_pid_root,
        result
    );
}

/// Test indirect symlink with suffix path (e.g., accessing /etc/passwd through the link).
///
/// This simulates the attack scenario where a security tool validates paths
/// through a container boundary symlink.
#[test]
fn test_indirect_symlink_with_suffix_path() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("container");

    // Create symlink: container -> /proc/self/root
    if let Err(e) = symlink("/proc/self/root", &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    // Canonicalize a path THROUGH the symlink
    let through_link = link_path.join("etc/passwd");

    // /etc/passwd should exist on most Linux systems
    if !Path::new("/etc/passwd").exists() {
        println!("Skipping: /etc/passwd doesn't exist");
        return;
    }

    let result = soft_canonicalize(&through_link).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", through_link);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Must preserve namespace prefix, not collapse to /etc/passwd
    assert_ne!(
        result,
        PathBuf::from("/etc/passwd"),
        "SECURITY BUG: Path through indirect symlink lost namespace prefix! \
         Expected /proc/self/root/etc/passwd, got /etc/passwd"
    );

    // Should preserve /proc/self/root prefix
    assert!(
        result.starts_with("/proc/self/root"),
        "Expected /proc/self/root prefix, got: {:?}",
        result
    );
}

/// Test chained symlinks leading to `/proc/self/root`.
///
/// link1 -> link2 -> /proc/self/root
#[test]
fn test_chained_symlinks_to_proc_root() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");

    let link2 = temp.path().join("link2");
    let link1 = temp.path().join("link1");

    // Create chain: link1 -> link2 -> /proc/self/root
    if let Err(e) = symlink("/proc/self/root", &link2) {
        println!("Skipping test: failed to create link2: {}", e);
        return;
    }
    if let Err(e) = symlink(&link2, &link1) {
        println!("Skipping test: failed to create link1: {}", e);
        return;
    }

    let result = soft_canonicalize(&link1).expect("soft_canonicalize should succeed");

    println!("Chain:  {:?} -> {:?} -> /proc/self/root", link1, link2);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Chained symlinks must also preserve namespace
    assert_ne!(
        result,
        PathBuf::from("/"),
        "SECURITY BUG: Chained symlinks to /proc/self/root resolved to '/'"
    );

    assert!(
        result.starts_with("/proc/self/root"),
        "Chained symlinks should preserve /proc prefix, got: {:?}",
        result
    );
}

/// Test the security attack scenario from the bug report.
///
/// An attacker creates a symlink pointing to /proc/.../root, and a security
/// tool using soft_canonicalize for container isolation gets bypassed.
#[test]
fn test_security_attack_scenario() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let container_root = temp.path().join("container_root");

    // Attacker creates: container_root -> /proc/self/root
    if let Err(e) = symlink("/proc/self/root", &container_root) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    // Security tool tries to validate container access
    let boundary = soft_canonicalize(&container_root).expect("canonicalize boundary");

    println!("Container root symlink: {:?}", container_root);
    println!("Boundary resolved to:   {:?}", boundary);

    // SECURITY ASSERTION: Container boundary must NOT be "/"
    assert_ne!(
        boundary,
        PathBuf::from("/"),
        "CRITICAL SECURITY BUG: Container boundary resolved to '/'! \
         Every path passes starts_with('/') check, allowing access to ANY file on the host."
    );

    // The boundary should be /proc/self/root
    assert!(
        boundary.starts_with("/proc/self/root"),
        "Container boundary should be /proc/self/root, got: {:?}",
        boundary
    );
}

/// Test symlink to `/proc/self/cwd` (another magic symlink).
///
/// Note: /proc/self/cwd resolves to the current working directory, not "/",
/// so this test documents the behavior rather than asserting a security bug.
#[test]
fn test_indirect_symlink_to_proc_self_cwd() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("cwd_link");

    // Create symlink: cwd_link -> /proc/self/cwd
    if let Err(e) = symlink("/proc/self/cwd", &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    let result = soft_canonicalize(&link_path).expect("soft_canonicalize should succeed");
    let std_result = std::fs::canonicalize(&link_path).expect("std canonicalize should succeed");

    println!("Input:      {:?}", link_path);
    println!("Our result: {:?}", result);
    println!("Std result: {:?}", std_result);

    // /proc/self/cwd resolves to the current working directory
    // Both std and soft_canonicalize should give the same result for cwd
    // (unlike /proc/self/root which is special)
}

/// Test symlink loop detection doesn't hang when following to proc paths.
#[test]
fn test_symlink_loop_with_proc_in_chain() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");

    let link_a = temp.path().join("link_a");
    let link_b = temp.path().join("link_b");

    // Create a loop: link_a -> link_b -> link_a
    if let Err(e) = symlink(&link_b, &link_a) {
        println!("Skipping test: failed to create link_a: {}", e);
        return;
    }
    if let Err(e) = symlink(&link_a, &link_b) {
        println!("Skipping test: failed to create link_b: {}", e);
        return;
    }

    // This should fail with a symlink loop error, not hang
    let result = soft_canonicalize(&link_a);

    println!("Symlink loop: {:?} <-> {:?}", link_a, link_b);
    println!("Result: {:?}", result);

    // Should be an error (too many symlink levels)
    assert!(result.is_err(), "Symlink loop should return an error");
}

/// Test that direct `/proc/self/root` paths still work correctly.
/// (Regression test for existing functionality)
#[test]
fn test_direct_proc_self_root_still_works() {
    let proc_self_root = PathBuf::from("/proc/self/root");

    if !proc_self_root.exists() {
        println!("Skipping: /proc/self/root doesn't exist");
        return;
    }

    let result = soft_canonicalize(&proc_self_root).expect("should succeed");

    println!("Input:  {:?}", proc_self_root);
    println!("Result: {:?}", result);

    // Direct paths should already be handled correctly
    assert_eq!(
        result,
        PathBuf::from("/proc/self/root"),
        "Direct /proc/self/root should be preserved"
    );
}

/// Test thread-self magic symlink (indirect).
#[test]
fn test_indirect_symlink_to_proc_thread_self_root() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("thread_link");

    // /proc/thread-self/root is another magic symlink
    let thread_self_root = "/proc/thread-self/root";

    // Check if thread-self exists (may not on older kernels)
    if !std::path::Path::new("/proc/thread-self").exists() {
        println!("Skipping: /proc/thread-self doesn't exist on this kernel");
        return;
    }

    if let Err(e) = symlink(thread_self_root, &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    let result = soft_canonicalize(&link_path).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", link_path);
    println!("Target: {}", thread_self_root);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Must not resolve to "/"
    assert_ne!(
        result,
        PathBuf::from("/"),
        "SECURITY BUG: Indirect symlink to {} resolved to '/'",
        thread_self_root
    );

    assert!(
        result.starts_with(thread_self_root),
        "Expected {} prefix, got: {:?}",
        thread_self_root,
        result
    );
}

/// Anchored canonicalize test for indirect symlinks.
#[test]
#[cfg(feature = "anchored")]
fn test_anchored_indirect_symlink_to_proc_root() {
    use soft_canonicalize::anchored_canonicalize;

    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let container_link = temp.path().join("container");

    // Create symlink: container -> /proc/self/root
    if let Err(e) = symlink("/proc/self/root", &container_link) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    // /etc/passwd should exist
    if !Path::new("/etc/passwd").exists() {
        println!("Skipping: /etc/passwd doesn't exist");
        return;
    }

    // Try to use the indirect symlink as an anchor
    let result = anchored_canonicalize(&container_link, "etc/passwd");

    println!("Anchor (indirect symlink): {:?}", container_link);
    println!("Relative path:             etc/passwd");

    match result {
        Ok(path) => {
            println!("Result: {:?}", path);

            // SECURITY ASSERTION: If anchor resolved correctly, result should NOT be /etc/passwd
            assert_ne!(
                path,
                PathBuf::from("/etc/passwd"),
                "SECURITY BUG: Anchor resolved to '/', result is /etc/passwd instead of \
                 /proc/self/root/etc/passwd"
            );
        }
        Err(e) => {
            println!("Error: {} (may be expected if anchor resolution fails)", e);
        }
    }
}
