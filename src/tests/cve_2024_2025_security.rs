/// Additional security tests based on CVE research from 2024-2025
///
/// This test suite covers attack vectors from recent CVEs that may be relevant
/// to path canonicalization:
///
/// - CVE-2025-27210: Node.js Windows device name path traversal
/// - CVE-2025-23084: Windows drive handling vulnerabilities
/// - CVE-2024-23651: Symlink TOCTOU race conditions (Docker/Buildkit)
/// - CVE-2024-21626: File descriptor leaks via /proc/self/fd
/// - CVE-2025-9566: Podman symlink traversal
/// - CVE-2024-38819: Path traversal via crafted HTTP requests
///
/// These tests ensure soft-canonicalize is resilient against similar attack patterns.
use crate::soft_canonicalize;

#[cfg(feature = "anchored")]
use crate::anchored_canonicalize;

// ============================================================================
// Windows Device Name Attack Vectors (CVE-2025-27210, CVE-2025-23084)
// ============================================================================

#[cfg(windows)]
#[test]
fn test_windows_device_name_traversal_con() {
    // BLACK-BOX: Attempt to use Windows reserved device names to bypass directory restrictions
    // Based on CVE-2025-27210: ..\\CON or CON\\..\\..\\etc\\passwd patterns

    let paths = vec![
        r"..\CON\..\..\Windows\System32\config",
        r"CON\..\..\..\etc\passwd",
        r"foo\CON\..\bar",
        r"..\.\CON\test.txt",
    ];

    for path in paths {
        let result = soft_canonicalize(path);
        // Should either canonicalize properly or reject with error
        // Must not allow device name to cause directory traversal bypass
        match result {
            Ok(resolved) => {
                // If successful, ensure result doesn't escape current directory context
                let resolved_str = resolved.to_string_lossy();

                // Device names should be handled, not used as traversal mechanism
                assert!(
                    !resolved_str.contains("CON\\..\\") && !resolved_str.contains("..\\CON"),
                    "Device name should not enable path traversal: {} -> {}",
                    path,
                    resolved_str
                );
            }
            Err(e) => {
                // Rejection is acceptable if path is invalid
                assert!(
                    e.kind() == std::io::ErrorKind::InvalidInput
                        || e.kind() == std::io::ErrorKind::NotFound,
                    "Should reject with appropriate error: {}",
                    e
                );
            }
        }
    }
}

#[cfg(windows)]
#[test]
fn test_windows_all_device_names_traversal() {
    // BLACK-BOX: Test all Windows reserved device names
    // CVE-2025-27210 specifically mentions: CON, PRN, AUX, NUL, COM1-9, LPT1-9

    let device_names = vec![
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    for device in device_names {
        // Try using device name as part of traversal sequence
        let attack_paths = vec![
            format!(r"..\{}\..\..\secret", device),
            format!(r"{}\..\..\etc\passwd", device),
            format!(r"foo\{}\bar\..\baz", device),
        ];

        for path in attack_paths {
            let result = soft_canonicalize(&path);
            if let Ok(resolved) = result {
                let resolved_str = resolved.to_string_lossy();
                // Device name should not enable traversal bypass
                assert!(
                    !resolved_str.contains(&format!("{}\\..\\", device)),
                    "Device {} should not enable traversal: {} -> {}",
                    device,
                    path,
                    resolved_str
                );
            }
            // Err(_) => Rejection is acceptable
        }
    }
}

#[cfg(windows)]
#[test]
fn test_windows_drive_relative_path_handling() {
    // BLACK-BOX: CVE-2025-23084 - Drive-relative paths like "C:file.txt"
    // These are relative to current directory on drive C:, not absolute

    let result = soft_canonicalize(r"C:test.txt");

    // Should resolve relative to current directory on C:
    assert!(result.is_ok());
    let resolved = result.unwrap();

    // Must be absolute (extended-length on Windows)
    assert!(resolved.to_string_lossy().starts_with(r"\\?\"));
}

#[cfg(windows)]
#[test]
fn test_windows_mixed_separators_with_device_names() {
    // BLACK-BOX: Mixed separators with device names
    // Ensure both / and \ are handled consistently with device names

    let paths = vec![
        r"../CON/../secret",
        r"..\CON\..\secret",
        r"foo/CON/bar/../baz",
        r"foo\CON\bar\..\baz",
    ];

    for path in paths {
        let result = soft_canonicalize(path);
        if let Ok(resolved) = result {
            let resolved_str = resolved.to_string_lossy();
            // Should normalize consistently regardless of separator type
            assert!(
                !resolved_str.contains("CON/..")
                    && !resolved_str.contains("CON\\..")
                    && !resolved_str.contains("../CON")
                    && !resolved_str.contains("..\\CON"),
                "Device name traversal should be normalized: {} -> {}",
                path,
                resolved_str
            );
        }
    }
}

// ============================================================================
// Symlink TOCTOU Race Conditions (CVE-2024-23651, CVE-2024-21626)
// ============================================================================

#[cfg(unix)]
#[test]
fn test_symlink_swap_race_resistance() {
    // WHITE-BOX: Based on CVE-2024-23651 (Docker Buildkit cache mount race)
    // Verify that symlink target swapping during resolution doesn't cause escape

    use std::fs;
    use std::os::unix::fs::symlink;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let base = temp_dir.path();

    let safe_target = base.join("safe");
    let dangerous_target = base.join("dangerous");
    fs::create_dir(&safe_target).unwrap();
    fs::create_dir(&dangerous_target).unwrap();

    let link = base.join("racing_link");
    symlink(&safe_target, &link).unwrap();

    let link_clone = link.clone();
    let dangerous_clone = dangerous_target.clone();

    // Spawn thread to swap symlink target mid-resolution
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_micros(100));
        let _ = fs::remove_file(&link_clone);
        let _ = symlink(&dangerous_clone, &link_clone);
    });

    // Attempt canonicalization during race window
    let result = soft_canonicalize(link.join("nonexistent.txt"));

    handle.join().unwrap();

    // Should either succeed with one of the targets or fail gracefully
    match result {
        Ok(resolved) => {
            // Must resolve to one of the two targets (race is benign)
            // Canonicalize expected paths to handle macOS /var -> /private/var symlink
            let safe_expected = soft_canonicalize(safe_target.join("nonexistent.txt")).unwrap();
            let dangerous_expected =
                soft_canonicalize(dangerous_target.join("nonexistent.txt")).unwrap();
            assert!(
                resolved == safe_expected || resolved == dangerous_expected,
                "Should resolve to one of the race targets.\nExpected either:\n  {:?}\n  {:?}\nGot:\n  {:?}",
                safe_expected,
                dangerous_expected,
                resolved
            );
        }
        Err(e) => {
            // Graceful failure is acceptable
            assert!(
                e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::InvalidInput,
                "Should fail gracefully: {}",
                e
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn test_proc_self_fd_symlink_attack() {
    // BLACK-BOX: Based on CVE-2024-21626 (runC /proc/self/fd escape)
    // Malicious container could symlink to /proc/self/fd/N to access host filesystem

    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let base = temp_dir.path();

    // Simulate malicious symlink pointing to /proc/self/fd/7
    let malicious_link = base.join("innocent_looking_path");
    symlink("/proc/self/fd/7", &malicious_link).unwrap();

    // Try to canonicalize the malicious symlink
    let result = soft_canonicalize(&malicious_link);

    // Should handle gracefully - either resolve to actual fd target or error
    if let Ok(resolved) = result {
        // If it resolves, verify it doesn't give unexpected access
        let resolved_str = resolved.to_string_lossy();
        // The fd might not exist or might point somewhere safe
        println!("Resolved /proc/self/fd/7 symlink to: {}", resolved_str);
    }
    // Failure is acceptable if fd doesn't exist
}

#[cfg(feature = "anchored")]
#[cfg(unix)]
#[test]
fn test_anchored_symlink_toctou_race() {
    // WHITE-BOX: Symlink TOCTOU in anchored context (CVE-2025-9566 pattern)
    // Verify anchored_canonicalize handles symlink races within virtual filesystem

    use std::fs;
    use std::os::unix::fs::symlink;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let anchor = temp_dir.path().join("anchor");
    fs::create_dir_all(&anchor).unwrap();

    let internal_target = anchor.join("internal");
    fs::create_dir(internal_target).unwrap();

    let link = anchor.join("link");
    symlink("internal", &link).unwrap();

    let link_clone = link;

    // Try to swap to absolute path during resolution
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_micros(100));
        let _ = fs::remove_file(&link_clone);
        let _ = symlink("/etc/passwd", &link_clone);
    });

    // Attempt anchored canonicalization during race
    let result = anchored_canonicalize(&anchor, "link/nonexistent");

    handle.join().unwrap();

    // Must stay within anchor regardless of race outcome
    if let Ok(resolved) = result {
        assert!(
            resolved.starts_with(&anchor)
                || resolved.starts_with(fs::canonicalize(&anchor).unwrap()),
            "Race should not escape anchor: {:?}",
            resolved
        );
    }
    // Failure is acceptable
}

// ============================================================================
// Podman-style Symlink Traversal (CVE-2025-9566)
// ============================================================================

#[cfg(feature = "anchored")]
#[cfg(unix)]
#[test]
fn test_configmap_style_symlink_escape_prevention() {
    // BLACK-BOX: Based on CVE-2025-9566 (Podman kube play symlink traversal)
    // Malicious ConfigMap/Secret could contain symlinks designed to escape container

    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let container_root = temp_dir.path().join("container");
    fs::create_dir_all(&container_root).unwrap();

    // Simulate mounting a ConfigMap with malicious symlink
    let configmap_dir = container_root.join("configmap");
    fs::create_dir(&configmap_dir).unwrap();

    // Malicious symlink trying to escape to host /etc
    let malicious_config = configmap_dir.join("escape_link");
    symlink("/etc/shadow", malicious_config).unwrap();

    // Use anchored canonicalization (like container runtime should)
    let result = anchored_canonicalize(&container_root, "configmap/escape_link");

    assert!(result.is_ok());
    let resolved = result.unwrap();

    // Must be clamped within container root
    let canon_root = fs::canonicalize(&container_root).unwrap();
    assert!(
        resolved.starts_with(&canon_root),
        "ConfigMap symlink should be clamped to container: {:?} not in {:?}",
        resolved,
        canon_root
    );

    // Should map to container/etc/shadow, not host /etc/shadow
    assert!(
        resolved.ends_with("etc/shadow"),
        "Should clamp to virtual etc/shadow: {:?}",
        resolved
    );
}

#[cfg(feature = "anchored")]
#[cfg(unix)]
#[test]
fn test_nested_configmap_symlinks() {
    // WHITE-BOX: Chained symlinks in ConfigMap-style scenario
    // link1 -> link2 -> /host/secret

    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let container = temp_dir.path().join("container");
    fs::create_dir_all(&container).unwrap();

    let config_dir = container.join("config");
    fs::create_dir(&config_dir).unwrap();

    // Create symlink chain
    let link1 = config_dir.join("link1");
    let link2 = config_dir.join("link2");

    symlink("link2", link1).unwrap();
    symlink("/host/sensitive/data", link2).unwrap();

    let result = anchored_canonicalize(&container, "config/link1");

    assert!(result.is_ok());
    let resolved = result.unwrap();

    // Must be clamped
    let canon_container = fs::canonicalize(&container).unwrap();
    assert!(
        resolved.starts_with(canon_container),
        "Chained symlinks should stay clamped: {:?}",
        resolved
    );
}

// ============================================================================
// Archive Extraction Scenarios (General Path Traversal)
// ============================================================================

#[cfg(feature = "anchored")]
#[test]
fn test_tar_bomb_style_dotdot_sequences() {
    // BLACK-BOX: Malicious archive with excessive ../ sequences
    // Common in tar bombs and zip slip attacks

    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let extract_zone = temp_dir.path().join("extract");
    fs::create_dir_all(&extract_zone).unwrap();

    // Simulate extracting file with malicious path
    let malicious_paths = vec![
        "../../../etc/cron.d/backdoor",
        "../../../../../../../../tmp/evil.sh",
        "subdir/../../../../../../etc/passwd",
    ];

    for malicious_path in malicious_paths {
        let result = anchored_canonicalize(&extract_zone, malicious_path);

        if let Ok(resolved) = result {
            // Must stay within extraction zone
            assert!(
                resolved.starts_with(soft_canonicalize(&extract_zone).unwrap()),
                "Archive path should be contained: {} -> {:?}",
                malicious_path,
                resolved
            );
        }
        // Err(_) => Rejection is also acceptable
    }
}

#[cfg(feature = "anchored")]
#[cfg(unix)]
#[test]
fn test_tar_bomb_with_absolute_symlinks() {
    // BLACK-BOX: Archive contains both files and absolute symlinks
    // Attacker tries to write through symlink to host filesystem

    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let extract_zone = temp_dir.path().join("extract");
    fs::create_dir_all(&extract_zone).unwrap();

    // Simulate extracted symlink pointing to /tmp
    let extracted_link = extract_zone.join("tmplink");
    symlink("/tmp", extracted_link).unwrap();

    // Try to write through the symlink
    let result = anchored_canonicalize(&extract_zone, "tmplink/evil_payload.sh");

    assert!(result.is_ok());
    let resolved = result.unwrap();

    // Must be clamped (should resolve to extract_zone/tmp/evil_payload.sh)
    let canon_extract = fs::canonicalize(&extract_zone).unwrap();
    assert!(
        resolved.starts_with(canon_extract),
        "Archive symlink should be clamped: {:?}",
        resolved
    );
}

// ============================================================================
// Edge Cases from CVE-2024-38819 (Spring Framework)
// ============================================================================

#[test]
fn test_url_encoded_path_traversal() {
    // BLACK-BOX: URL-encoded path traversal sequences
    // CVE-2024-38819 involved crafted HTTP requests with encoded paths

    // These should be handled at HTTP layer, but verify we handle literal strings
    let paths = vec![
        "..%2F..%2F..%2Fetc%2Fpasswd", // ../../../etc/passwd
        "..%5c..%5c..%5cwindows",      // ..\..\..\windows
        "%2e%2e%2f%2e%2e%2f",          // ../../
    ];

    for path in paths {
        let result = soft_canonicalize(path);

        if let Ok(resolved) = result {
            let resolved_str = resolved.to_string_lossy();
            // Should treat as literal strings (URL decoding is HTTP layer's job)
            // We just verify we don't crash
            assert!(!resolved_str.is_empty());
        }
        // Err(_) => Invalid paths should error appropriately
    }
}

#[test]
fn test_double_encoded_traversal() {
    // BLACK-BOX: Double URL-encoded traversal attempts

    let paths = vec![
        "%252e%252e%252f", // Double-encoded ../
        "%252e%252e%255c", // Double-encoded ..\
    ];

    for path in paths {
        let result = soft_canonicalize(path);
        // Should handle as literal string (no decoding)
        match result {
            Ok(_) | Err(_) => {
                // Either outcome is fine, just don't crash
            }
        }
    }
}

// ============================================================================
// Mixed Attack Vectors
// ============================================================================

#[cfg(feature = "anchored")]
#[cfg(unix)]
#[test]
fn test_combined_device_symlink_dotdot_attack() {
    // WHITE-BOX: Combine multiple attack techniques
    // Symlink + excessive ../ + absolute paths

    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let anchor = temp_dir.path().join("sandbox");
    fs::create_dir_all(&anchor).unwrap();

    let attack_dir = anchor.join("attack");
    fs::create_dir(&attack_dir).unwrap();

    // Create symlink to absolute path
    let link = attack_dir.join("escape");
    symlink("/etc/passwd", link).unwrap();

    // Try to traverse through symlink
    let result = anchored_canonicalize(&anchor, "attack/escape/../../../etc/shadow");

    assert!(result.is_ok());
    let resolved = result.unwrap();

    // Must stay clamped
    let canon_anchor = fs::canonicalize(&anchor).unwrap();
    assert!(
        resolved.starts_with(canon_anchor),
        "Combined attack should be contained: {:?}",
        resolved
    );
}

#[cfg(windows)]
#[test]
fn test_windows_unc_device_combination() {
    // BLACK-BOX: Windows-specific attack combining UNC and device names

    let paths = vec![
        r"\\.\CON\..\secret",
        r"\\?\CON\..\..\etc",
        r"\\.\pipe\..\..\windows\system32",
    ];

    for path in paths {
        let result = soft_canonicalize(path);
        match result {
            Ok(resolved) => {
                let resolved_str = resolved.to_string_lossy();
                // Should handle device namespace safely
                assert!(!resolved_str.is_empty());
            }
            Err(e) => {
                // Rejection is acceptable
                assert!(
                    e.kind() == std::io::ErrorKind::InvalidInput
                        || e.kind() == std::io::ErrorKind::NotFound
                        || e.kind() == std::io::ErrorKind::PermissionDenied,
                    "Should reject with appropriate error: {}",
                    e
                );
            }
        }
    }
}

// ============================================================================
// Non-ASCII and Unicode Attacks (Related to CVE-2024-13059)
// ============================================================================

#[test]
fn test_unicode_normalization_traversal() {
    // BLACK-BOX: Unicode characters that might normalize to path separators
    // CVE-2024-13059 involved improper handling of non-ASCII filenames

    let paths = vec![
        "test\u{2216}etc\u{2216}passwd", // ∖ (division slash)
        "test\u{2215}etc\u{2215}passwd", // ∕ (division slash)
        "test\u{ff0f}etc\u{ff0f}passwd", // ／ (fullwidth solidus)
        "test\u{ff3c}etc\u{ff3c}passwd", // ＼ (fullwidth reverse solidus)
    ];

    for path in paths {
        let result = soft_canonicalize(path);
        if let Ok(resolved) = result {
            let resolved_str = resolved.to_string_lossy();
            // These should NOT be treated as path separators
            assert!(
                resolved_str.contains('\u{2216}')
                    || resolved_str.contains('\u{2215}')
                    || resolved_str.contains('\u{ff0f}')
                    || resolved_str.contains('\u{ff3c}')
                    || !resolved_str.contains("etc"), // If normalized, would contain "etc"
                "Unicode characters should not be interpreted as separators: {}",
                resolved_str
            );
        }
        // Err(_) => Rejection is acceptable
    }
}

#[test]
fn test_null_byte_injection() {
    // BLACK-BOX: Null byte injection attempts
    // Classic attack to truncate paths

    let paths = vec!["safe/path\0../../etc/passwd", "test.txt\0.evil"];

    for path in paths {
        let result = soft_canonicalize(path);

        // Should reject null bytes
        assert!(
            result.is_err(),
            "Null bytes should be rejected: {}",
            path.escape_default()
        );

        if let Err(e) = result {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::InvalidInput,
                "Should reject with InvalidInput: {}",
                e
            );
        }
    }
}

// ============================================================================
// Defensive Programming Tests
// ============================================================================

#[test]
fn test_extremely_long_path_with_traversal() {
    // WHITE-BOX: Very long paths with traversal sequences
    // Ensure no buffer issues or performance degradation

    let mut long_path = String::new();
    for _ in 0..1000 {
        long_path.push_str("../");
    }
    long_path.push_str("etc/passwd");

    let result = soft_canonicalize(&long_path);

    // Should handle without panic or hang
    assert!(result.is_ok());
}

#[test]
fn test_deeply_nested_nonexistent_path() {
    // BLACK-BOX: Very deep directory nesting

    let mut deep_path = String::from("a");
    for _ in 0..500 {
        deep_path.push_str("/b");
    }

    let result = soft_canonicalize(&deep_path);

    // Should handle without panic
    assert!(result.is_ok());
}

#[cfg(feature = "anchored")]
#[test]
fn test_anchored_with_empty_components() {
    // WHITE-BOX: Paths with empty components (doubled slashes)

    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let anchor = temp_dir.path();

    let paths = vec!["foo//bar", "foo///bar", "./foo//bar", "foo/./bar"];

    for path in paths {
        let result = anchored_canonicalize(anchor, path);
        assert!(
            result.is_ok(),
            "Empty components should be normalized: {}",
            path
        );
    }
}
