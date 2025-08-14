#![cfg(windows)]
//! Advanced Unicode/Encoding Attack Tests
//!
//! This suite focuses on penetration tests using Unicode and other encoding techniques
//! to bypass security validation in ADS stream parsing.

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
fn test_homoglyph_ads_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    // These Unicode characters LOOK like path separators but are treated as literal filename characters
    // They should canonicalize successfully as part of the filename, not as path separators
    let visual_spoofing_patterns = [
        "file.txt:stream..\u{2215}evil.exe", // division slash ∕ - should be literal
        "file.txt:stream..\u{29F8}evil.exe", // big solidus ⧸ - should be literal
        "file.txt:stream..\u{2044}evil.exe", // fraction slash ⁄ - should be literal
    ];

    for pattern in &visual_spoofing_patterns {
        let path = tmp.path().join(pattern);
        let result = soft_canonicalize(&path)?;

        // Verify the Unicode characters are preserved as literal filename characters
        let result_str = result.to_string_lossy();
        assert!(
            result_str.contains('\u{2215}')
                || result_str.contains('\u{29F8}')
                || result_str.contains('\u{2044}'),
            "Visual spoofing pattern '{pattern}' should preserve Unicode characters in result: {result_str}"
        );
    }

    // These patterns contain ACTUAL path traversal and should be rejected
    let real_traversal_attacks = [
        "file.txt:str\u{00EB}\u{03B1}m..\\evil.exe", // strëαm with real traversal
        "file.txt:stream:..\\bypass.exe",            // direct traversal
        "file.txt:hidden:..\\..\\escape.exe",        // multi-level traversal
    ];

    for pattern in &real_traversal_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}

#[test]
fn test_unicode_normalization_bypass() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    let attacks = [
        // NFC vs NFD forms in ADS streams
        "file.txt:cafe\u{0301}:..\\evil.exe", // e + combining acute
        "file.txt:caf\u{00E9}:..\\evil.exe",  // precomposed é
    ];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}

#[test]
fn test_bidirectional_text_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    let attacks = [
        // Right-to-left override in ADS names
        "file.txt:stream\u{202E}..\\evil.exe",
        "file.txt:\u{202E}maerts..\\evil.exe",
    ];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}

#[test]
fn test_punycode_in_ads() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    let attacks = ["file.txt:xn--nxasmq6b..\\evil.exe"];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}

#[test]
fn test_zero_width_character_injection() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    let attacks = [
        // Hidden characters in stream names
        "file.txt:str\u{200B}eam..\\evil.exe", // zero-width space
        "file.txt:str\u{200C}eam..\\evil.exe", // zero-width non-joiner
        "file.txt:str\u{200D}eam..\\evil.exe", // zero-width joiner
        "file.txt:\u{FEFF}eam..\\evil.exe",    // byte order mark
    ];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}
