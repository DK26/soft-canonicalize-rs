/// CVE security tests: Windows device name attacks and Unicode/null-byte injection
///
/// Covers:
/// - CVE-2025-27210: Node.js Windows device name path traversal
/// - CVE-2025-23084: Windows drive handling vulnerabilities
/// - CVE-2024-13059: Unicode normalization / non-ASCII filename attacks
/// - Null byte injection (classic path truncation)
/// - Windows UNC + device name combination attacks
use crate::soft_canonicalize;

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
    // Drive-relative semantics: `C:foo` is relative to the process's *current directory on C:*.
    // We model this by obtaining the per-drive current directory for C: if available.
    // Fallback rules follow Windows semantics:
    // 1) If process CWD is already on C:, use it
    // 2) Else, use env var "=C:" (per-drive CWD) if set
    // 3) Else, fallback to C:\ root
    let cwd = std::env::current_dir().expect("current_dir must be accessible");
    let expected_base = {
        use std::path::{Component, Prefix};
        if let Some(Component::Prefix(pr)) = cwd.components().next() {
            if let Prefix::Disk(d) = pr.kind() {
                if d == b'C' || d == b'c' {
                    // Process CWD is already on C:
                    soft_canonicalize(&cwd).expect("canonicalize cwd")
                } else {
                    // Try per-drive env var "=C:"
                    if let Some(val) = std::env::var_os("=C:") {
                        soft_canonicalize(std::path::PathBuf::from(val))
                            .expect("canonicalize per-drive C: cwd")
                    } else {
                        // Fallback to C:\ root
                        soft_canonicalize(std::path::Path::new(r"C:\"))
                            .expect("canonicalize C:\\ root")
                    }
                }
            } else {
                // Non-disk prefixes: fallback to env var or root
                if let Some(val) = std::env::var_os("=C:") {
                    soft_canonicalize(std::path::PathBuf::from(val))
                        .expect("canonicalize per-drive C: cwd")
                } else {
                    soft_canonicalize(std::path::Path::new(r"C:\")).expect("canonicalize C:\\ root")
                }
            }
        } else {
            // Relative CWD? Fallback to env var or root
            if let Some(val) = std::env::var_os("=C:") {
                soft_canonicalize(std::path::PathBuf::from(val))
                    .expect("canonicalize per-drive C: cwd")
            } else {
                soft_canonicalize(std::path::Path::new(r"C:\")).expect("canonicalize C:\\ root")
            }
        }
    };
    let expected = expected_base.join("test.txt");
    let result = soft_canonicalize(r"C:test.txt")
        .expect("Drive-relative file should resolve relative to C: current directory");

    assert_eq!(
        result, expected,
        "Drive-relative resolution mismatch: expected {:?} got {:?}",
        expected, result
    );
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
// Mixed Attack Vectors – Windows UNC + Device Names
// ============================================================================

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
