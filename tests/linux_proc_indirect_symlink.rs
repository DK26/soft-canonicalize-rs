//! Tests for indirect symlinks to `/proc/PID/root` magic paths.
//!
//! This test suite validates security fixes for symlinks pointing to `/proc/PID/root`.
//! These attacks bypass protection because the input path doesn't lexically start with `/proc/`.
//!
//! **Attack vectors covered:**
//! - Absolute indirect symlinks: `link -> /proc/self/root`
//! - Relative symlinks resolving to proc: `link -> ../../../proc/self/root`
//! - Chained symlinks: `link1 -> link2 -> /proc/self/root`
//! - Task-level namespaces: `link -> /proc/PID/task/TID/root`
//! - Non-existing suffixes: `link/non_existing_file`
//!
//! Fixed in: `proc-canonicalize` v0.0.3 (initial), v0.0.4 (comprehensive)
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

/// Test indirect symlink to `/proc/self/root` with non-existing suffix.
///
/// This ensures that even when the path doesn't exist (triggering manual traversal),
/// the namespace boundary is preserved.
#[test]
fn test_indirect_symlink_to_proc_self_root_non_existing() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("link_to_proc_ne");

    // Create symlink: link_to_proc_ne -> /proc/self/root
    if let Err(e) = symlink("/proc/self/root", &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    // Test with non-existing suffix
    let input = link_path.join("non_existing_file");
    let result = soft_canonicalize(&input).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Result must NOT start with "/" (unless it's /proc...)
    // It should start with /proc/self/root
    assert!(
        result.starts_with("/proc/self/root"),
        "Expected /proc/self/root prefix, got: {:?}",
        result
    );
}

/// Test if `..` can escape `/proc/self/root` when manually traversing.
///
/// Scenario: `link` -> `/proc/self/root`, Input: `link/../non_existing`
/// Expected: Should NOT resolve to `/proc/self` (which would be an escape).
#[test]
fn test_dotdot_escape_from_proc_root() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("link_to_root");

    // Create symlink: link_to_root -> /proc/self/root
    if let Err(e) = symlink("/proc/self/root", &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    // Input: link_to_root/../non_existing_file
    // If link_to_root resolves to /proc/self/root, ".." should NOT pop it to /proc/self
    let input = link_path.join("..").join("non_existing_file");

    let result = soft_canonicalize(&input).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    // Check if we escaped to /proc/self
    // Valid result is /proc/self/root/non_existing_file (if .. was clamped)
    // or /proc/self/root/../non_existing_file (if .. was preserved lexically)
    // Invalid result is /proc/self/non_existing_file

    let escaped = result == PathBuf::from("/proc/self/non_existing_file");

    if escaped {
        panic!(
            "SECURITY FAIL: Escaped /proc/self/root via '..' to {:?}",
            result
        );
    }

    // We expect it to stay within root
    assert!(
        result.starts_with("/proc/self/root"),
        "Should stay within /proc/self/root, got: {:?}",
        result
    );
}

/// Test relative symlink that resolves to `/proc/self/root`.
///
/// Attack vector: `link -> ../../../proc/self/root`
/// This was fixed in proc-canonicalize 0.0.4.
#[test]
fn test_relative_symlink_resolving_to_proc_self_root() {
    // Create symlink directly in /tmp so we have a known depth
    // /tmp/xxx/rel_link -> ../../proc/self/root
    // From /tmp/xxx, ../../proc/self/root goes to / then proc/self/root
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("rel_link");

    // temp.path() is like /tmp/.tmpXXX (depth 2 from root)
    // So we need: .. (to /tmp) -> .. (to /) -> proc/self/root
    let relative_to_proc = "../../proc/self/root";

    if let Err(e) = symlink(relative_to_proc, &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    // Verify the symlink target
    match std::fs::read_link(&link_path) {
        Ok(target) => println!("Symlink target: {:?}", target),
        Err(e) => {
            println!("Skipping test: cannot read symlink: {}", e);
            return;
        }
    }

    let result = soft_canonicalize(&link_path).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", link_path);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Must not resolve to "/"
    assert_ne!(
        result,
        PathBuf::from("/"),
        "SECURITY BUG: Relative symlink to /proc/self/root resolved to '/'"
    );

    // Should preserve /proc/.../root prefix (may be /proc/self/root or /proc/PID/root)
    let result_str = result.to_string_lossy();
    let is_proc_root = result_str.starts_with("/proc/self/root")
        || result_str.starts_with("/proc/thread-self/root")
        || (result_str.starts_with("/proc/")
            && result_str.contains("/root")
            && result_str
                .strip_prefix("/proc/")
                .and_then(|s| s.split('/').next())
                .map(|pid| pid.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false));

    assert!(
        is_proc_root,
        "Expected /proc/.../root prefix, got: {:?}",
        result
    );
}

/// Test task-level namespace symlink: `/proc/PID/task/TID/root`
#[test]
fn test_indirect_symlink_to_proc_pid_task_tid_root() {
    let temp = tempfile::tempdir().expect("Failed to create temp dir");
    let link_path = temp.path().join("task_root_link");

    let pid = std::process::id();
    // Use the main thread ID (same as PID on Linux for single-threaded)
    let proc_task_root = format!("/proc/{}/task/{}/root", pid, pid);

    // Check if task-level path exists
    if !std::path::Path::new(&proc_task_root).exists() {
        println!("Skipping: {} doesn't exist", proc_task_root);
        return;
    }

    if let Err(e) = symlink(&proc_task_root, &link_path) {
        println!("Skipping test: failed to create symlink: {}", e);
        return;
    }

    let result = soft_canonicalize(&link_path).expect("soft_canonicalize should succeed");

    println!("Input:  {:?}", link_path);
    println!("Target: {}", proc_task_root);
    println!("Result: {:?}", result);

    // SECURITY ASSERTION: Must not resolve to "/"
    assert_ne!(
        result,
        PathBuf::from("/"),
        "SECURITY BUG: Indirect symlink to {} resolved to '/'",
        proc_task_root
    );

    // Should preserve the /proc/PID/task/TID/root prefix
    assert!(
        result.starts_with(&proc_task_root),
        "Expected {} prefix, got: {:?}",
        proc_task_root,
        result
    );
}
