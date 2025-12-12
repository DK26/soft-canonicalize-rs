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

// ============================================================================
// Subdirectory Anchor Tests (Anchoring INSIDE /proc/PID/root)
// ============================================================================

/// Test anchoring to a subdirectory inside /proc/PID/root.
///
/// This verifies that anchored_canonicalize works correctly when the anchor
/// is not the namespace root itself, but a directory within it.
///
/// Example use case: A container tool that wants to restrict access to
/// /proc/PID/root/var/www (the web root inside the container).
#[test]
#[cfg(feature = "anchored")]
fn test_anchored_subdirectory_inside_proc_root() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

    // Create an anchor to a subdirectory inside the namespace
    // Using /tmp since it's likely to exist
    let subdir_anchor = proc_pid_root.join("tmp");

    if !subdir_anchor.exists() {
        println!("Skipping: {} doesn't exist", subdir_anchor.display());
        return;
    }

    // Simple path resolution within the subdirectory
    let result = anchored_canonicalize(&subdir_anchor, "subdir/file.txt");

    println!("Anchor:    {:?}", subdir_anchor);
    println!("Candidate: subdir/file.txt");
    println!("Result:    {:?}", result);

    match result {
        Ok(path) => {
            // Result should preserve /proc/PID/root prefix
            assert!(
                path.starts_with(&proc_pid_root),
                "Result should preserve /proc/PID/root prefix: {:?}",
                path
            );

            // Result should be within the subdirectory anchor
            // The anchor is soft-canonicalized, so check component-wise
            let path_str = path.to_string_lossy();
            assert!(
                path_str.contains("/tmp/") || path_str.ends_with("/tmp"),
                "Result should be within /tmp anchor: {:?}",
                path
            );

            // Should contain the requested file
            assert!(
                path_str.contains("file.txt"),
                "Result should contain requested filename: {:?}",
                path
            );
        }
        Err(e) => {
            println!("Error (may be acceptable): {}", e);
        }
    }
}

/// Test escape attempt from subdirectory anchor inside /proc/PID/root.
///
/// Verifies that `..` traversal from a subdirectory anchor is clamped,
/// AND that the /proc/PID/root prefix is preserved.
#[test]
#[cfg(feature = "anchored")]
fn test_anchored_subdirectory_escape_attempt_clamped() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));
    let subdir_anchor = proc_pid_root.join("tmp");

    if !subdir_anchor.exists() {
        println!("Skipping: {} doesn't exist", subdir_anchor.display());
        return;
    }

    // Try to escape the subdirectory anchor using ..
    // This should be clamped to the anchor, not escape to /proc/PID/root or beyond
    let escape_attempt = "../../../etc/passwd";
    let result = anchored_canonicalize(&subdir_anchor, escape_attempt);

    println!("Anchor:         {:?}", subdir_anchor);
    println!("Escape attempt: {:?}", escape_attempt);
    println!("Result:         {:?}", result);

    match result {
        Ok(path) => {
            // CRITICAL: Must preserve /proc/PID/root prefix
            assert!(
                path.starts_with(&proc_pid_root),
                "SECURITY: Result must preserve /proc/PID/root prefix, got: {:?}",
                path
            );

            // Should be clamped to the subdirectory anchor (/tmp)
            let canonical_anchor =
                soft_canonicalize(&subdir_anchor).expect("anchor should canonicalize");
            assert!(
                path.starts_with(&canonical_anchor),
                "Escape should be clamped to anchor {:?}, got: {:?}",
                canonical_anchor,
                path
            );

            // The escaped path should resolve to anchor/etc/passwd
            let path_str = path.to_string_lossy();
            assert!(
                path_str.contains("etc/passwd") || path_str.ends_with("etc/passwd"),
                "Clamped path should contain etc/passwd: {:?}",
                path
            );

            println!("✓ Escape attempt correctly clamped to subdirectory anchor");
        }
        Err(e) => {
            // Error is also acceptable (blocked traversal)
            println!("Blocked with error (acceptable): {}", e);
        }
    }
}

/// Test deeply nested subdirectory anchor inside /proc/PID/root.
///
/// Verifies behavior with anchors like /proc/PID/root/var/lib/app/data
#[test]
#[cfg(feature = "anchored")]
fn test_anchored_deep_subdirectory_inside_proc_root() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

    // Use a deeper path - /usr/share is commonly present
    let deep_anchor = proc_pid_root.join("usr").join("share");

    if !deep_anchor.exists() {
        println!("Skipping: {} doesn't exist", deep_anchor.display());
        return;
    }

    // Try to escape back to proc_pid_root level
    let escape_to_proc_root = "../../etc/passwd";
    let result = anchored_canonicalize(&deep_anchor, escape_to_proc_root);

    println!("Deep anchor:    {:?}", deep_anchor);
    println!("Escape attempt: {:?}", escape_to_proc_root);
    println!("Result:         {:?}", result);

    match result {
        Ok(path) => {
            // Must preserve /proc/PID/root prefix
            assert!(
                path.starts_with(&proc_pid_root),
                "SECURITY: Must preserve /proc/PID/root prefix: {:?}",
                path
            );

            // Should be clamped to the deep anchor
            let canonical_anchor =
                soft_canonicalize(&deep_anchor).expect("anchor should canonicalize");
            assert!(
                path.starts_with(&canonical_anchor),
                "Should be clamped to deep anchor {:?}, got: {:?}",
                canonical_anchor,
                path
            );

            println!("✓ Deep subdirectory anchor correctly enforced");
        }
        Err(e) => {
            println!("Blocked with error (acceptable): {}", e);
        }
    }
}

/// Test that /proc prefix is preserved even with non-existing subdirectory anchor.
///
/// Verifies soft-canonicalize behavior when anchor contains non-existing components.
#[test]
#[cfg(feature = "anchored")]
fn test_anchored_nonexisting_subdirectory_inside_proc_root() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

    if !proc_pid_root.exists() {
        println!("Skipping: /proc/{}/root doesn't exist", pid);
        return;
    }

    // Anchor to a non-existing subdirectory inside the namespace
    let nonexisting_anchor = proc_pid_root
        .join("var")
        .join("fictional_app_12345")
        .join("data");

    let result = anchored_canonicalize(&nonexisting_anchor, "config/settings.json");

    println!("Non-existing anchor: {:?}", nonexisting_anchor);
    println!("Candidate:           config/settings.json");
    println!("Result:              {:?}", result);

    match result {
        Ok(path) => {
            // Must preserve /proc/PID/root prefix even for non-existing paths
            assert!(
                path.starts_with(&proc_pid_root),
                "CRITICAL: Must preserve /proc/PID/root even for non-existing anchors: {:?}",
                path
            );

            // Should contain our fictional path components
            let path_str = path.to_string_lossy();
            assert!(
                path_str.contains("fictional_app_12345"),
                "Should preserve non-existing anchor components: {:?}",
                path
            );
            assert!(
                path_str.contains("settings.json"),
                "Should contain requested filename: {:?}",
                path
            );

            println!("✓ Non-existing subdirectory anchor preserves /proc prefix");
        }
        Err(e) => {
            println!("Error: {}", e);
            // For non-existing anchors, error might be acceptable depending on implementation
        }
    }
}

/// Test escape from non-existing subdirectory stays within /proc boundary.
#[test]
#[cfg(feature = "anchored")]
fn test_anchored_escape_from_nonexisting_subdirectory() {
    let pid = process::id();
    let proc_pid_root = PathBuf::from(format!("/proc/{}/root", pid));

    if !proc_pid_root.exists() {
        println!("Skipping: /proc/{}/root doesn't exist", pid);
        return;
    }

    // Non-existing anchor
    let nonexisting_anchor = proc_pid_root.join("opt").join("fake_service");

    // Aggressive escape attempt
    let escape_attempt = "../../../../../../../../etc/shadow";
    let result = anchored_canonicalize(&nonexisting_anchor, escape_attempt);

    println!("Non-existing anchor: {:?}", nonexisting_anchor);
    println!("Escape attempt:      {:?}", escape_attempt);
    println!("Result:              {:?}", result);

    match result {
        Ok(path) => {
            // SECURITY CRITICAL: Must NEVER escape /proc/PID/root
            assert!(
                path.starts_with(&proc_pid_root),
                "SECURITY VIOLATION: Escaped /proc/PID/root boundary! Got: {:?}",
                path
            );

            // Should NOT be the host's /etc/shadow
            assert_ne!(
                path,
                PathBuf::from("/etc/shadow"),
                "SECURITY VIOLATION: Resolved to host path!"
            );

            println!("✓ Aggressive escape clamped to /proc boundary");
        }
        Err(e) => {
            println!("Blocked with error (good): {}", e);
        }
    }
}
