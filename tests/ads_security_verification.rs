#![cfg(windows)]

// Manual verification of specific high-risk ADS attack vectors

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io::{self, ErrorKind};

#[test]
fn verify_cve_2025_8088_pattern_blocked() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("decoy.txt");
    fs::write(base, b"decoy")?;

    // Original CVE-2025-8088 pattern
    let exploit = "decoy.txt:..\\..\\evil.exe";
    let path = tmp.path().join(exploit);

    match soft_canonicalize(path) {
        Ok(p) => panic!("SECURITY FAILURE: CVE pattern not blocked! Got: {p:?}"),
        Err(e) => {
            assert_eq!(
                e.kind(),
                ErrorKind::InvalidInput,
                "Wrong error type for CVE pattern"
            );
            println!("✓ CVE-2025-8088 pattern correctly blocked: {e}");
        }
    }
    Ok(())
}

#[test]
fn verify_whitespace_injection_blocked() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(base, b"test")?;

    let attacks = [
        "file.txt: malicious",  // leading space
        "file.txt:malicious ",  // trailing space
        "file.txt:\tmalicious", // tab injection
        "file.txt:malicious\r", // carriage return
        "file.txt:malicious\n", // newline
    ];

    for attack in attacks {
        let path = tmp.path().join(attack);
        match soft_canonicalize(path) {
            Ok(p) => {
                panic!("SECURITY FAILURE: Whitespace injection not blocked in '{attack}': {p:?}")
            }
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidInput,
                    "Wrong error type for whitespace injection"
                );
                println!("✓ Whitespace injection blocked for: {attack}");
            }
        }
    }
    Ok(())
}

#[test]
fn verify_device_name_injection_blocked() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(base, b"test")?;

    let device_attacks = [
        "file.txt:CON",
        "file.txt:PRN",
        "file.txt:AUX",
        "file.txt:NUL",
        "file.txt:COM1",
        "file.txt:LPT1",
    ];

    for attack in device_attacks {
        let path = tmp.path().join(attack);
        match soft_canonicalize(path) {
            Ok(p) => {
                panic!("SECURITY FAILURE: Device name injection not blocked in '{attack}': {p:?}")
            }
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidInput,
                    "Wrong error type for device name injection"
                );
                println!("✓ Device name injection blocked for: {attack}");
            }
        }
    }
    Ok(())
}

#[test]
fn verify_unicode_attack_vectors_handled() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(base, b"test")?;

    let unicode_attacks = [
        "file.txt:stream\0hidden",     // null byte injection
        "file.txt:stream\u{200B}evil", // zero-width space
        "file.txt:stream\u{FEFF}evil", // BOM injection
    ];

    for attack in unicode_attacks {
        let path = tmp.path().join(attack);
        match soft_canonicalize(path) {
            Ok(p) => panic!("SECURITY FAILURE: Unicode attack not blocked in '{attack}': {p:?}"),
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidInput,
                    "Wrong error type for unicode attack"
                );
                println!("✓ Unicode attack blocked for: {attack}");
            }
        }
    }
    Ok(())
}

#[test]
fn verify_valid_ads_still_works() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(base, b"test")?;

    let valid_patterns = [
        "file.txt:backup",
        "file.txt:metadata:$DATA",
        "file.txt:summary_2023",
    ];

    for pattern in valid_patterns {
        let path = tmp.path().join(pattern);
        match soft_canonicalize(path) {
            Ok(_) => println!("✓ Valid ADS pattern accepted: {pattern}"),
            Err(e) => panic!("FAILURE: Valid ADS pattern rejected '{pattern}': {e}"),
        }
    }
    Ok(())
}
