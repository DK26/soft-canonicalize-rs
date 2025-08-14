#![cfg(windows)]
// Comprehensive ADS attack vector test suite covering all known CVEs and security issues

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
        Ok(_) => {}
        Err(e) => panic!("Expected Ok for pattern '{pattern}', got Err({e:?})"),
    }
}

#[test]
fn ads_comprehensive_attack_vectors() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Known CVE patterns and attack vectors
    let attack_patterns = [
        // CVE-2025-8088 inspired patterns (WinRAR-style ADS + traversal)
        "test.txt:..\\..\\exploit.exe",
        "test.txt:placeholder..\\..\\malware.bat",
        "test.txt:XXXXXXXXXXXXXXXXXXXXXX..\\..\\evil.exe",
        // Path traversal injection via ADS stream names
        "test.txt:..\\parent\\evil.exe",
        "test.txt:..\\..\\..\\..\\windows\\system32\\calc.exe",
        "test.txt:/etc/passwd", // Unix-style in ADS
        "test.txt:..\\Documents and Settings\\All Users\\evil.exe",
        // Multi-colon traversal attacks
        "test.txt:stream:..\\..\\evil.exe:$DATA",
        "test.txt:a:b:c:..\\evil.exe",
        "test.txt:legitimate:..\\bypass.exe:$BITMAP",
        // Directory separator injection
        "test.txt:stream\\subdir\\file.exe",
        "test.txt:stream/unix/style/path",
        "test.txt:..\\",
        "test.txt:../",
        "test.txt:..\\/mixed",
        // Null byte injection attempts
        "test.txt:stream\0",
        "test.txt:stream\0..\\evil.exe",
        // Unicode normalization bypass attempts
        "test.txt:strëam..\\evil.exe",
        "test.txt:stream\u{200B}..\\evil.exe", // zero-width space
        "test.txt:stre\u{0430}m..\\evil.exe",  // Cyrillic 'a' homoglyph
        // Control character injection
        "test.txt:stream\r\n..\\evil.exe",
        "test.txt:stream\t..\\evil.exe",
        // Empty/special stream names
        "test.txt:",
        "test.txt:.",
        "test.txt:..",
        "test.txt: ",  // space-only
        "test.txt:\t", // tab-only
        // Invalid type tokens
        "test.txt:stream:DATA",              // missing $
        "test.txt:stream:$",                 // $ only
        "test.txt:stream:$DATA$",            // extra $
        "test.txt:stream:$DA TA",            // space in type
        "test.txt:stream:$DATA..\\evil.exe", // traversal after type
        // Long name attacks - use exactly 256 to trigger over-limit
        &format!("test.txt:{}", "A".repeat(256)),
        &format!("test.txt:{}..\\evil.exe", "X".repeat(255)),
        // Mixed case bypass attempts (these should be accepted as valid lowercase is ok)
        // "test.txt:Stream:$data", // lowercase $data - should actually be valid
        // "test.txt:STREAM:$DATA", // uppercase - should be valid

        // Device name injection (lexically valid but FS would reject - not our concern for ADS suffix)
        // "test.txt:CON",  // Actually valid as stream name
        // "test.txt:PRN:$DATA", // valid
        "test.txt:AUX..\\evil.exe", // has traversal
        // "test.txt:NUL:$DATA", // valid

        // Short name + ADS combinations
        "PROGRA~1:stream..\\evil.exe",
        "MICROS~1:..\\bypass.exe:$DATA",
        // UNC + ADS traversal
        "test.txt:..\\..\\\\malicious\\server\\share\\evil.exe",
        "test.txt:..\\\\?\\C:\\Windows\\System32\\evil.exe",
        // Extended length prefix injection
        "test.txt:..\\\\?\\evil.exe",
        "test.txt:stream\\\\?\\C:\\bypass.exe",
    ];

    for pattern in attack_patterns {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}

#[test]
fn ads_valid_patterns_accepted() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"content")?;

    // Valid ADS patterns that should be accepted
    let valid_patterns = [
        // Standard ADS syntax
        "file.txt:stream",
        "file.txt:mystream",
        "file.txt:backup_2023",
        // With valid type tokens (basic ones that should work)
        "file.txt:stream:$DATA",
        // Valid characters in stream names
        "file.txt:stream_with_underscores",
        "file.txt:stream-with-dashes",
        "file.txt:stream.with.dots",
        "file.txt:stream123",
        "file.txt:123stream",
        "file.txt:CamelCaseStream",
        // Leading dots (but not .. traversal)
        "file.txt:.hidden",
        "file.txt:..hidden", // not traversal, just starts with ..
        "file.txt:...dots",
        // Unicode stream names (valid)
        "file.txt:résumé",
        "file.txt:文档",
        "file.txt:ñoño",
        // Mixed case type tokens
        "file.txt:stream:$Data", // mixed case should be ok
    ];

    for pattern in valid_patterns {
        let path = tmp.path().join(pattern);
        expect_ok(soft_canonicalize(&path), pattern);
    }

    Ok(())
}

#[test]
fn ads_edge_cases_boundary_conditions() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("boundary.txt");
    fs::write(&base, b"test")?;

    // Edge cases at validation boundaries
    let boundary_rejected = [
        // Just over limits
        &format!("boundary.txt:{}", "a".repeat(256)), // over limit
        // Colon position edge cases
        "boundary.txt:stream::extra", // double colon
        "boundary.txt:stream:",       // trailing colon after stream
        "boundary.txt::stream",       // leading colon in stream
        // Whitespace handling
        "boundary.txt: stream",  // leading space
        "boundary.txt:stream ",  // trailing space
        "boundary.txt: stream ", // both
        "boundary.txt:\tstream", // tab prefix
        "boundary.txt:stream\t", // tab suffix
    ];

    let boundary_accepted = [
        // Exactly at limits (255 chars should be accepted)
        &format!("boundary.txt:{}", "a".repeat(255)), // max typical stream name
        "boundary.txt:a:$A",                          // minimal type token
        "boundary.txt:stream:$A_B_C_123",             // complex valid type
    ];

    for pattern in boundary_rejected {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    for pattern in boundary_accepted {
        let path = tmp.path().join(pattern);
        expect_ok(soft_canonicalize(&path), pattern);
    }

    Ok(())
}
