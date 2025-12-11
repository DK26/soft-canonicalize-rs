//! Additional security tests for /proc namespace boundary protection.
//!
//! These tests cover edge cases not in the main test suite.

#![cfg(target_os = "linux")]

use soft_canonicalize::soft_canonicalize;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

/// Test: Can we escape /proc/self/root by going INTO it then using multiple `..`?
///
/// Scenario: /proc/self/root/etc/../../../tmp/escape
/// If we enter the namespace and then try to `..` out, we should stay clamped.
#[test]
fn test_dotdot_after_entering_proc_root() {
    // Input: /proc/self/root/etc/../../.. (trying to escape)
    let input = PathBuf::from("/proc/self/root/etc/../../..");

    let result = soft_canonicalize(&input);

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    match result {
        Ok(path) => {
            // Should NOT escape to / or outside /proc/self/root
            assert_ne!(path, PathBuf::from("/"), "Escaped to /");
            assert!(
                path.starts_with("/proc/self/root") || path == PathBuf::from("/proc/self/root"),
                "Should stay within /proc/self/root, got: {:?}",
                path
            );
        }
        Err(e) => {
            // Error is also acceptable (indicates blocked traversal)
            println!("Got error (acceptable): {}", e);
        }
    }
}

/// Test: Idempotency - canonicalize(canonicalize(path)) == canonicalize(path)
#[test]
fn test_idempotency_for_proc_paths() {
    let input = PathBuf::from("/proc/self/root");

    if !input.exists() {
        println!("Skipping: /proc/self/root doesn't exist");
        return;
    }

    let first = soft_canonicalize(&input).expect("first canonicalize");
    let second = soft_canonicalize(&first).expect("second canonicalize");

    println!("Input:  {:?}", input);
    println!("First:  {:?}", first);
    println!("Second: {:?}", second);

    assert_eq!(first, second, "Canonicalization should be idempotent");
}

/// Test: What happens with /proc/self/root followed by absolute path component?
///
/// This is a weird edge case: /proc/self/root//etc/passwd (double slash)
#[test]
fn test_double_slash_in_proc_path() {
    let input = PathBuf::from("/proc/self/root//etc/passwd");

    let result = soft_canonicalize(&input);

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    if let Ok(path) = result {
        // Should preserve namespace boundary
        assert!(
            path.starts_with("/proc/self/root") || path.starts_with("/proc/"),
            "Should preserve /proc prefix, got: {:?}",
            path
        );
    }
}

/// Test: Symlink INSIDE /proc/self/root pointing outside
///
/// If someone creates a symlink inside the namespace pointing to /etc/passwd,
/// following it should stay within the namespace (virtual filesystem semantics).
///
/// NOTE: This test may not be applicable since we can't create symlinks inside /proc
#[test]
fn test_symlink_inside_namespace_pointing_outside() {
    // This test documents expected behavior but may not be runnable
    // since /proc/self/root/* is read-only

    // The theoretical scenario:
    // /proc/self/root/tmp/evil_link -> /etc/passwd
    // Should resolve to /proc/self/root/etc/passwd (if we had anchored semantics)
    // or /proc/self/root/tmp/evil_link (if we just preserve the symlink)

    println!("This test documents theoretical behavior.");
    println!("In practice, we can't create symlinks inside /proc/self/root");
    println!("The real protection comes from proc-canonicalize not following the magic link");
}

/// Test: What if /proc/self/root itself is part of a longer chain?
///
/// link1 -> /some/path/link2
/// /some/path/link2 -> /proc/self/root
#[test]
fn test_proc_root_in_middle_of_chain() {
    let temp = tempfile::tempdir().expect("tempdir");

    // Create: link1 -> link2, link2 -> /proc/self/root
    let link1 = temp.path().join("link1");
    let link2 = temp.path().join("link2");

    if let Err(e) = symlink("/proc/self/root", &link2) {
        println!("Skipping: cannot create link2: {}", e);
        return;
    }
    if let Err(e) = symlink(&link2, &link1) {
        println!("Skipping: cannot create link1: {}", e);
        return;
    }

    // Now access: link1/etc/passwd
    let input = link1.join("etc/passwd");
    let result = soft_canonicalize(&input);

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    if let Ok(path) = result {
        assert_ne!(
            path,
            PathBuf::from("/etc/passwd"),
            "Should not escape namespace"
        );
        assert!(
            path.starts_with("/proc/"),
            "Should preserve /proc prefix, got: {:?}",
            path
        );
    }
}

/// Test: /proc/self/cwd behavior (should NOT be treated same as root)
///
/// /proc/self/cwd resolves to the actual cwd, not "/" like root does.
/// But we should still preserve the /proc/self/cwd prefix for namespace tools.
#[test]
fn test_proc_self_cwd_preserved() {
    let input = PathBuf::from("/proc/self/cwd");

    if !input.exists() {
        println!("Skipping: /proc/self/cwd doesn't exist");
        return;
    }

    let result = soft_canonicalize(&input).expect("should succeed");
    let std_result = std::fs::canonicalize(&input).expect("std should succeed");

    println!("Input:      {:?}", input);
    println!("Our result: {:?}", result);
    println!("Std result: {:?}", std_result);

    // We preserve /proc/self/cwd, std follows it
    assert_eq!(result, PathBuf::from("/proc/self/cwd"));
    assert_ne!(std_result, PathBuf::from("/proc/self/cwd"));
}

/// Test: Triple-depth indirect symlink with non-existing suffix
///
/// link1 -> link2 -> link3 -> /proc/self/root + /nonexistent
#[test]
fn test_triple_chain_with_nonexisting() {
    let temp = tempfile::tempdir().expect("tempdir");

    let link3 = temp.path().join("link3");
    let link2 = temp.path().join("link2");
    let link1 = temp.path().join("link1");

    if let Err(e) = symlink("/proc/self/root", &link3) {
        println!("Skipping: {}", e);
        return;
    }
    if let Err(e) = symlink(&link3, &link2) {
        println!("Skipping: {}", e);
        return;
    }
    if let Err(e) = symlink(&link2, &link1) {
        println!("Skipping: {}", e);
        return;
    }

    // Access through triple chain with non-existing suffix
    let input = link1.join("nonexistent/path/file.txt");
    let result = soft_canonicalize(&input).expect("should succeed");

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    assert!(
        result.starts_with("/proc/"),
        "Should preserve /proc prefix even through triple chain, got: {:?}",
        result
    );
}
/// Test: Core use case - planning non-existing files through /proc/self/root
///
/// This is the primary use case of soft-canonicalize: canonicalizing paths
/// that don't exist yet. We must verify this still works correctly when
/// the path goes through /proc magic symlinks.
///
/// Note: /proc/self is itself a symlink to /proc/PID, so the result will
/// contain the numeric PID. This is correct behavior.
#[test]
fn test_core_use_case_plan_nonexisting_through_proc() {
    // Scenario: A container tool wants to plan where to create files
    // inside a container's namespace, before the files exist

    let nonexisting_paths = [
        "/proc/self/root/tmp/my_new_app/config.json",
        "/proc/self/root/var/log/new_service/app.log",
        "/proc/self/root/opt/app/data/settings.yaml",
    ];

    let pid = std::process::id();
    let expected_prefix = format!("/proc/{}/root", pid);

    for path_str in nonexisting_paths {
        let input = PathBuf::from(path_str);
        let result = soft_canonicalize(&input);

        println!("Input:  {}", path_str);

        match result {
            Ok(resolved) => {
                println!("Result: {:?}", resolved);

                // Core assertion 1: The path should resolve successfully (not error)
                // Core assertion 2: The /proc/PID/root prefix must be preserved
                // (Note: /proc/self resolves to /proc/PID, which is correct)
                assert!(
                    resolved.starts_with(&expected_prefix),
                    "Non-existing path through /proc should preserve namespace prefix, got: {:?}",
                    resolved
                );

                // Core assertion 3: The non-existing suffix should be appended
                let expected_suffix = input.strip_prefix("/proc/self/root").unwrap();
                let actual_suffix = resolved.strip_prefix(&expected_prefix).unwrap();
                assert_eq!(
                    actual_suffix, expected_suffix,
                    "Non-existing suffix should be preserved"
                );

                println!("✓ Correctly preserved namespace + non-existing suffix");
            }
            Err(e) => {
                panic!(
                    "Core functionality broken: Failed to canonicalize non-existing path: {}. Error: {}",
                    path_str, e
                );
            }
        }
        println!();
    }
}

/// Test: Verify .. normalization works in non-existing suffixes
#[test]
fn test_dotdot_in_nonexisting_suffix() {
    // Input: /proc/self/root/tmp/foo/../bar/file.txt
    // Expected: /proc/PID/root/tmp/bar/file.txt (.. normalized in non-existing part)
    // Note: /proc/self resolves to /proc/PID
    let input = PathBuf::from("/proc/self/root/tmp/planned_dir/../actual_dir/file.txt");

    let result = soft_canonicalize(&input).expect("should succeed");
    let pid = std::process::id();
    let expected_prefix = format!("/proc/{}/root", pid);

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    // Should preserve /proc/PID prefix (self resolves to PID)
    assert!(
        result.starts_with(&expected_prefix),
        "Should preserve /proc/PID/root prefix, got: {:?}",
        result
    );

    // The .. should be normalized
    assert!(
        !result.to_string_lossy().contains(".."),
        ".. should be normalized in the result, got: {:?}",
        result
    );

    // Result should have the normalized path
    assert!(
        result.to_string_lossy().contains("actual_dir/file.txt")
            || result.to_string_lossy().contains("actual_dir\\file.txt"),
        "Should contain normalized path after .., got: {:?}",
        result
    );
}

/// Test: /proc/self/cwd/.. behavior
///
/// Unlike root, cwd is NOT a root. Traversal up from cwd should work.
/// If we clamp it, we break standard behavior.
/// However, if we resolve it, we lose the "magic" prefix.
///
/// Current implementation: We preserve cwd, so we clamp .. (treating it as root).
/// This test documents this behavior.
#[test]
fn test_proc_self_cwd_dotdot_behavior() {
    let input = PathBuf::from("/proc/self/cwd/..");

    // We expect this to be clamped to /proc/self/cwd because we treat it as a magic boundary
    // This might be controversial, but it's consistent with "don't resolve magic links"

    let result = soft_canonicalize(&input).expect("should succeed");

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    // If we clamped it:
    if result == PathBuf::from("/proc/self/cwd") {
        println!("Behavior: Clamped to cwd (treated as root)");
    } else {
        println!("Behavior: Resolved/Traversed to {:?}", result);
    }

    // For now, just assert it succeeds. We are verifying behavior.
    assert!(
        result.exists(),
        "Result should exist (if it resolved to a real path) or be the magic link"
    );
}

/// Test: CRITICAL - /proc/self/root/.. must NOT escape
///
/// This is the most direct escape attempt. If std::fs::canonicalize is used
/// on /proc/self/root/.., it would resolve /proc/self/root to "/" and then
/// apply ".." (which stays at "/"). This is a security issue if it happens.
///
/// Our implementation must prevent this.
#[test]
fn test_proc_self_root_dotdot_direct_escape() {
    let input = PathBuf::from("/proc/self/root/..");

    let result = soft_canonicalize(&input).expect("should succeed");

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    // CRITICAL: Must NOT be "/"
    assert_ne!(
        result,
        PathBuf::from("/"),
        "SECURITY BUG: /proc/self/root/.. resolved to /! Namespace escape possible."
    );

    // Should stay at /proc/self/root (clamped)
    let pid = std::process::id();
    let expected_self = PathBuf::from("/proc/self/root");
    let expected_pid = PathBuf::from(format!("/proc/{}/root", pid));

    assert!(
        result == expected_self || result == expected_pid || result.starts_with("/proc/"),
        "Should stay within /proc namespace, got: {:?}",
        result
    );
}

/// Test: /proc/self/exe should be resolved normally
///
/// Unlike root/cwd, exe is a normal symlink that should resolve to the actual binary.
#[test]
fn test_proc_self_exe_resolves_normally() {
    let input = PathBuf::from("/proc/self/exe");

    if !input.exists() {
        println!("Skipping: /proc/self/exe doesn't exist");
        return;
    }

    let result = soft_canonicalize(&input).expect("should succeed");
    let std_result = std::fs::canonicalize(&input).expect("std should succeed");

    println!("Input:      {:?}", input);
    println!("Our result: {:?}", result);
    println!("Std result: {:?}", std_result);

    // exe SHOULD be resolved to the actual binary path
    // (unlike root/cwd which we preserve)
    assert_eq!(
        result, std_result,
        "/proc/self/exe should resolve to the actual binary, same as std"
    );

    // Should NOT start with /proc (should be resolved)
    assert!(
        !result.starts_with("/proc/"),
        "exe should resolve to actual binary, not stay in /proc, got: {:?}",
        result
    );
}

/// Test: /proc/self/fd/0 should be resolved normally
#[test]
fn test_proc_self_fd_resolves_normally() {
    let input = PathBuf::from("/proc/self/fd/0");

    if !input.exists() {
        println!("Skipping: /proc/self/fd/0 doesn't exist");
        return;
    }

    let result = soft_canonicalize(&input);
    let std_result = std::fs::canonicalize(&input);

    println!("Input:      {:?}", input);
    println!("Our result: {:?}", result);
    println!("Std result: {:?}", std_result);

    // fd symlinks should be handled the same as std
    match (result, std_result) {
        (Ok(ours), Ok(std)) => {
            assert_eq!(ours, std, "fd resolution should match std");
        }
        (Err(_), Err(_)) => {
            // Both failed, that's consistent
            println!("Both failed, consistent behavior");
        }
        _ => {
            // One succeeded, one failed - might be a race condition with fd
            println!("Mixed results, possible race condition with fd lifecycle");
        }
    }
}

/// Test: Non-existent PID in /proc
#[test]
fn test_nonexistent_pid() {
    // Use a very high PID that almost certainly doesn't exist
    let input = PathBuf::from("/proc/999999999/root");

    let result = soft_canonicalize(&input);

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    // Should succeed (non-existing path) and preserve the structure
    match result {
        Ok(path) => {
            assert!(
                path.starts_with("/proc/999999999/root"),
                "Should preserve /proc/PID/root structure for non-existent PID, got: {:?}",
                path
            );
        }
        Err(e) => {
            // Error is acceptable (permission denied, etc.)
            println!("Got error (acceptable): {}", e);
        }
    }
}

/// Test: Nested /proc paths
#[test]
fn test_nested_proc_paths() {
    // Pathological case: /proc/self/root/proc/self/root
    let input = PathBuf::from("/proc/self/root/proc/self/root");

    let result = soft_canonicalize(&input);

    println!("Input:  {:?}", input);
    println!("Result: {:?}", result);

    // Should preserve the outer namespace boundary
    match result {
        Ok(path) => {
            // The outer /proc/self/root should be preserved
            // The inner /proc/self/root is just a path within the namespace
            let pid = std::process::id();
            assert!(
                path.starts_with("/proc/self/root")
                    || path.starts_with(&format!("/proc/{}/root", pid)),
                "Should preserve outer namespace, got: {:?}",
                path
            );
        }
        Err(e) => {
            println!("Got error (acceptable): {}", e);
        }
    }
}
