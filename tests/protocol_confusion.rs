#![cfg(windows)]
//! Protocol Confusion Tests
//!
//! This suite tests for vulnerabilities arising from the confusion of different protocols
//! (e.g., UNC, HTTP, file URIs) within ADS stream names.

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
fn test_unc_plus_ads_plus_http() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    let attacks = [
        "\\\\server\\share\\file.txt:http://evil.com/..\\evil.exe",
        "\\\\server\\share\\file.txt:https://evil.com/..\\evil.exe",
    ];

    for pattern in &attacks {
        // We can't create a file with this name, so we pass the full path to soft_canonicalize
        expect_invalid(soft_canonicalize(pattern), pattern);
    }

    Ok(())
}

#[test]
fn test_file_uri_plus_ads() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    let attacks = [
        "file.txt:file:///C:/Windows/evil.exe",
        "file.txt:file:///C:/Windows/evil.exe:..\\..\\evil.exe",
    ];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}

#[test]
fn test_custom_protocol_injection() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"test")?;

    let attacks = [
        "file.txt:steam://rungame/../evil.exe",
        "file.txt:ftp://evil.com/..\\evil.exe",
        "file.txt:telnet://evil.com:23",
    ];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }

    Ok(())
}
