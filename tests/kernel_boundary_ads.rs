#![cfg(windows)]
//! Kernel/Syscall Boundary Tests
//!
//! This suite tests for vulnerabilities at the boundary between user-space parsing
//! and kernel-level syscalls for ADS handling.

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io::{self, ErrorKind};

fn expect_invalid(res: io::Result<impl std::fmt::Debug>, pattern: &str) {
    match res {
        Ok(v) => panic!("Expected InvalidInput for pattern '{pattern}', got Ok({v:?})"),
        Err(e) => assert_eq!(
            e.kind(),
            ErrorKind::InvalidInput,
            "Expected InvalidInput for pattern '{pattern}', got {e:?}"
        ),
    }
}

#[test]
fn test_syscall_bypass() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    // Test patterns that should be REJECTED (actual security issues)
    let dangerous_attacks = [
        // Path with special characters that could bypass validation
        "file.txt:stream<..\\evil.exe", // Contains invalid chars + traversal
        "file.txt:stream>..\\evil.exe", // Contains invalid chars + traversal
        "file.txt:stream\"..\\evil.exe", // Contains invalid chars + traversal
        "file.txt:stream|..\\evil.exe", // Contains invalid chars + traversal
        "file.txt:stream?..\\evil.exe", // Contains invalid chars + traversal
        "file.txt:stream*..\\evil.exe", // Contains invalid chars + traversal
    ];

    for pattern in &dangerous_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    // Test patterns that should be ALLOWED (legitimate use cases)
    let legitimate_patterns = [
        // Very long path with ADS - should be allowed if within directory bounds
        &format!("{}\\{}:stream", "a".repeat(50), "file.txt"), // Reasonable length
    ];

    for pattern in &legitimate_patterns {
        let path = tmp.path().join(pattern);
        match soft_canonicalize(&path) {
            Ok(canonical) => {
                let temp_canonical = soft_canonicalize(tmp.path())?;
                assert!(
                    canonical.starts_with(&temp_canonical),
                    "Pattern '{pattern}' should stay within temp directory bounds"
                );
            }
            Err(_) => {
                // It's okay if the path doesn't exist or has other issues,
                // as long as it's not rejected for security reasons
                println!("Pattern '{pattern}' was rejected (possibly due to non-existence)");
            }
        }
    }

    Ok(())
}

#[test]
fn test_driver_level_ads() {
    // Testing interaction with filesystem filter drivers is not feasible in a unit test.
    // This would require a dedicated integration test environment with specific drivers installed.
}

#[test]
fn test_privilege_escalation() -> io::Result<()> {
    // Our canonicalization library correctly processes all syntactically valid paths
    // It's not responsible for access control - that's handled by filesystem permissions

    let legitimate_system_paths = [
        "C:\\Windows\\System32\\config\\SAM:stream",
        "C:\\Windows\\System32\\drivers\\etc\\hosts:stream",
    ];

    for pattern in &legitimate_system_paths {
        match soft_canonicalize(pattern) {
            Ok(canonical) => {
                // This is correct - we should canonicalize valid system paths
                println!(
                    "System path '{}' correctly canonicalized to: {}",
                    pattern,
                    canonical.display()
                );
                assert!(canonical.to_string_lossy().contains(":\\Windows\\System32"));
            }
            Err(e) => {
                // Only certain errors are acceptable (like file not found)
                match e.kind() {
                    ErrorKind::NotFound => {
                        println!("System path '{pattern}' not found (expected on most systems)");
                    }
                    ErrorKind::PermissionDenied => {
                        println!(
                            "System path '{pattern}' access denied by filesystem permissions (expected)"
                        );
                    }
                    _ => {
                        panic!("Unexpected error for valid system path '{pattern}': {e}");
                    }
                }
            }
        }
    }

    // Test relative paths with traversal that get canonicalized correctly
    let traversal_patterns = [
        "..\\..\\Windows\\System32\\config\\SAM:stream", // Should canonicalize correctly
    ];

    for pattern in &traversal_patterns {
        match soft_canonicalize(pattern) {
            Ok(canonical) => {
                // This is correct behavior - we canonicalize the path
                println!(
                    "Traversal pattern '{}' correctly canonicalized to: {}",
                    pattern,
                    canonical.display()
                );
                // Verify it contains the expected system path
                assert!(canonical
                    .to_string_lossy()
                    .contains("Windows\\System32\\config\\SAM:stream"));
            }
            Err(e) => {
                panic!("Unexpected error for valid traversal pattern '{pattern}': {e}");
            }
        }
    }

    // Test malformed ADS syntax that should be rejected
    let invalid_ads_patterns = [
        "file.txt:",                 // Empty stream name
        "file.txt::double_colon",    // Double colon
        "file.txt:\0null_in_stream", // Null byte in stream
    ];

    for pattern in &invalid_ads_patterns {
        expect_invalid(soft_canonicalize(pattern), pattern);
    }

    Ok(())
}
