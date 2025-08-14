#![cfg(windows)]
//! Filesystem Metadata Exploitation Tests
//!
//! This suite tests how ADS parsing interacts with filesystem-level metadata patterns
//! like extended attributes, junctions, reparse points, and case folding.

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

fn expect_ok(res: io::Result<impl std::fmt::Debug>, pattern: &str) {
    match res {
        Ok(_) => {} // Correctly handles the Ok case without unnecessary panic.
        Err(e) => panic!("Expected Ok for pattern '{pattern}', got Err({e:?})"),
    }
}

#[test]
fn test_extended_attributes_confusion() {
    // On Windows, ADS is the primary mechanism for extended attributes.
    // This test is more relevant for Unix, where extended attributes and colons in filenames can coexist.
    // The main concern is ensuring that a filename with a colon, which is valid on Unix,
    // is not misinterpreted as an ADS stream that can be exploited.
    // This is covered in `ads_cross_platform_security.rs`.
}

#[test]
fn test_ntfs_junction_plus_ads() -> io::Result<()> {
    // Test ADS patterns on junction-style names (no need to create real junctions)
    let attacks = [
        "junction:stream..\\..\\evil.exe",
        "junction:stream:$DATA..\\..\\evil.exe",
        "my_junction:hidden_stream:..\\sensitive.txt",
        "link_target:metadata:..\\..\\system32\\backdoor.dll",
    ];

    for pattern in &attacks {
        expect_invalid(soft_canonicalize(pattern), pattern);
    }

    Ok(())
}

#[test]
fn test_reparse_point_plus_ads() -> io::Result<()> {
    // Test ADS patterns on reparse point names (no need to create real reparse points)
    let attacks = [
        "reparse_point:stream..\\..\\evil.exe",
        "reparse_point:stream:$DATA..\\..\\evil.exe",
        "symlink_target:hidden:..\\sensitive.conf",
        "mount_point:metadata:..\\..\\windows\\system32\\cmd.exe",
    ];

    for pattern in &attacks {
        expect_invalid(soft_canonicalize(pattern), pattern);
    }

    Ok(())
}

#[test]
fn test_case_folding_plus_ads() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    // Test that case folding doesn't bypass ADS security checks
    let attacks = [
        "FILE.TXT:stream..\\..\\evil.exe",
        "file.txt:STREAM:..\\..\\evil.exe",
        "FiLe.TxT:StReAm:..\\..\\evil.exe",
    ];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    // Test valid ADS patterns (no traversal) work with case folding
    let valid_patterns = ["FILE.TXT:stream", "file.txt:STREAM", "FiLe.TxT:StReAm"];

    for pattern in &valid_patterns {
        let path = tmp.path().join(pattern);
        expect_ok(soft_canonicalize(&path), pattern);
    }

    Ok(())
}
