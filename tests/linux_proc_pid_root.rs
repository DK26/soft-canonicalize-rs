//! Tests verifying that `/proc/PID/root` namespace boundaries are preserved.
//!
//! With the integration of `proc-canonicalize`, `soft_canonicalize` now correctly
//! preserves Linux `/proc/PID/root` and `/proc/PID/cwd` magic symlink prefixes
//! instead of resolving them to `/`.
//!
//! This is critical for container tooling that uses these paths as security boundaries.
//!
//! Run with: `cargo test --test linux_proc_pid_root -- --nocapture`

#![cfg(target_os = "linux")]

#[cfg(feature = "anchored")]
use soft_canonicalize::anchored_canonicalize;
use soft_canonicalize::soft_canonicalize;
use std::path::PathBuf;
use std::process;

/// Test that `/proc/self/root` is preserved (not resolved to `/`).
///
/// This verifies the fix for the namespace boundary issue where magic symlinks
/// would incorrectly resolve to `/`, breaking container security boundaries.
#[test]
fn test_proc_self_root_canonicalization_preserves_prefix() {
    // /proc/self/root is a magic symlink that:
    // - readlink() returns "/"
    // - But traversing THROUGH it stays in the process's mount namespace
    let proc_self_root = PathBuf::from("/proc/self/root");

    // Verify the path exists (it always does for running processes)
    assert!(
        proc_self_root.exists(),
        "/proc/self/root should exist on Linux"
    );

    // Canonicalize using our crate
    let canonicalized =
        soft_canonicalize(&proc_self_root).expect("soft_canonicalize should succeed");

    println!("Input:        {:?}", proc_self_root);
    println!("Canonicalized: {:?}", canonicalized);

    // FIXED: The namespace prefix is now preserved!
    assert_eq!(
        canonicalized,
        PathBuf::from("/proc/self/root"),
        "soft_canonicalize should preserve /proc/self/root prefix"
    );
}

/// Test with the actual PID format `/proc/PID/root`
#[test]
fn test_proc_pid_root_canonicalization_preserves_prefix() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

    assert!(proc_pid_root.exists(), "/proc/{}/root should exist", pid);

    let canonicalized =
        soft_canonicalize(&proc_pid_root).expect("soft_canonicalize should succeed");

    println!("Input:        {:?}", proc_pid_root);
    println!("Canonicalized: {:?}", canonicalized);

    // FIXED: The namespace prefix is now preserved!
    assert_eq!(
        canonicalized, proc_pid_root,
        "soft_canonicalize should preserve /proc/PID/root prefix"
    );
}

/// Test that anchored_canonicalize now correctly preserves namespace boundaries.
///
/// With the fix, using `/proc/PID/root` as an anchor properly enforces
/// container boundary security.
#[test]
#[cfg(feature = "anchored")]
fn test_anchored_canonicalize_proc_root_boundary_preserved() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

    // User wants to clamp paths to the "container" (in this case, our own process)
    // They expect "../../../etc/passwd" to be clamped to /proc/PID/root/etc/passwd

    // Try to access a path that SHOULD be clamped to the container
    let escape_attempt = "../../../etc/passwd";

    let result = anchored_canonicalize(&proc_pid_root, escape_attempt);

    println!("Anchor:       {:?}", proc_pid_root);
    println!("Candidate:    {:?}", escape_attempt);

    match &result {
        Ok(path) => {
            println!("Result:       {:?}", path);

            // FIXED: The result should preserve the /proc/PID/root prefix
            let preserves_namespace = path.starts_with(&proc_pid_root);
            println!("Preserves namespace prefix: {}", preserves_namespace);

            // The namespace prefix is now correctly preserved!
            assert!(
                preserves_namespace,
                "anchored_canonicalize should preserve /proc/PID/root prefix"
            );

            // The path should be clamped within the namespace boundary
            assert!(
                path.starts_with(&proc_pid_root),
                "Result should stay within namespace boundary"
            );
        }
        Err(e) => {
            println!("Error:        {:?}", e);
            // If /etc/passwd doesn't exist or isn't accessible, that's fine for this test
        }
    }
}

/// Test showing the difference between std::fs::canonicalize and soft_canonicalize.
///
/// std::fs::canonicalize still resolves /proc/self/root to "/", but our crate
/// now correctly preserves the namespace prefix.
#[test]
fn test_soft_canonicalize_differs_from_std_for_proc_root() {
    let proc_self_root = PathBuf::from("/proc/self/root");

    let std_result =
        std::fs::canonicalize(&proc_self_root).expect("std::fs::canonicalize should succeed");
    let our_result = soft_canonicalize(&proc_self_root).expect("soft_canonicalize should succeed");

    println!("std::fs::canonicalize: {:?}", std_result);
    println!("soft_canonicalize:     {:?}", our_result);

    // std::fs::canonicalize resolves to "/" (the bug we're fixing)
    assert_eq!(std_result, PathBuf::from("/"));

    // Our crate now preserves the namespace prefix!
    assert_eq!(our_result, PathBuf::from("/proc/self/root"));

    // They should now be DIFFERENT (we've fixed the behavior)
    assert_ne!(
        std_result, our_result,
        "soft_canonicalize should differ from std::fs::canonicalize for /proc magic symlinks"
    );
}

/// Test demonstrating that traversing THROUGH /proc/self/root works correctly
/// (the kernel namespace crossing is preserved when accessing files)
#[test]
fn test_file_access_through_proc_root_works() {
    let proc_self_root = PathBuf::from("/proc/self/root");

    // Access /etc/os-release through /proc/self/root
    let through_proc = proc_self_root.join("etc/os-release");
    let direct = PathBuf::from("/etc/os-release");

    // Both should access the same file (since we're in our own namespace)
    if through_proc.exists() && direct.exists() {
        let through_content = std::fs::read_to_string(&through_proc).ok();
        let direct_content = std::fs::read_to_string(&direct).ok();

        println!("Through /proc/self/root: {:?}", through_proc);
        println!("Direct access:           {:?}", direct);
        println!(
            "Contents match:          {}",
            through_content == direct_content
        );

        // For our own process, both paths access the same file
        assert_eq!(
            through_content, direct_content,
            "Traversing through /proc/self/root accesses the same namespace"
        );
    } else {
        println!("Skipping file comparison - /etc/os-release not available");
    }
}

/// Test that subpaths under /proc/PID/root preserve the prefix
#[test]
fn test_canonicalize_subpath_under_proc_root() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));
    let subpath = proc_pid_root.join("etc/passwd");

    if subpath.exists() {
        let canonicalized = soft_canonicalize(&subpath).expect("should succeed");

        println!("Input:        {:?}", subpath);
        println!("Canonicalized: {:?}", canonicalized);

        // FIXED: The /proc/PID/root prefix is now preserved!
        let has_proc_prefix = canonicalized
            .to_string_lossy()
            .contains(&format!("/proc/{}/root", pid));

        println!("Has /proc/PID/root prefix: {}", has_proc_prefix);

        // The prefix is now correctly preserved!
        assert!(
            has_proc_prefix,
            "/proc/PID/root prefix should be preserved during canonicalization"
        );

        // The path should start with the namespace root
        assert!(
            canonicalized.starts_with(&proc_pid_root),
            "Path should stay within namespace boundary"
        );
    } else {
        println!("Skipping - /etc/passwd not accessible through /proc/PID/root");
    }
}

/// Summary test that prints the fixed behavior
#[test]
fn test_summary_namespace_canonicalization_fixed() {
    println!("\n");
    println!("{}", "=".repeat(70));
    println!("NAMESPACE CANONICALIZATION FIX VERIFICATION");
    println!("{}", "=".repeat(70));
    println!();
    println!("The Original Problem:");
    println!("  /proc/PID/root is a 'magic symlink' that:");
    println!("  - readlink() returns '/'");
    println!("  - But traversing THROUGH it crosses into the process's namespace");
    println!();
    println!("Old (Broken) Behavior:");
    println!("  soft_canonicalize('/proc/PID/root')             '/'");
    println!("  soft_canonicalize('/proc/PID/root/etc/passwd')  '/etc/passwd'");
    println!();
    println!("New (Fixed) Behavior:");
    println!("  soft_canonicalize('/proc/PID/root')             '/proc/PID/root'");
    println!("  soft_canonicalize('/proc/PID/root/etc/passwd')  '/proc/PID/root/etc/passwd'");
    println!();
    println!("Security Benefit:");
    println!("  Using /proc/PID/root as a PathBoundary anchor now works correctly!");
    println!("  Container tooling can safely use soft_canonicalize for namespace paths.");
    println!();
    println!("{}", "=".repeat(70));
    println!();

    // Verify the fix is working
    let proc_self_root = PathBuf::from("/proc/self/root");
    let result = soft_canonicalize(&proc_self_root).expect("should succeed");
    assert_eq!(result, proc_self_root, "Fix verification failed!");
    println!(" Fix verified: /proc/self/root is preserved correctly");
}
