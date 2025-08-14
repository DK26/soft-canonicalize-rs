#![cfg(windows)]
//! Cryptographic Bypass Tests
//!
//! This suite tests for vulnerabilities where ADS patterns could be used to bypass
//! cryptographic checks like hash collision, encryption, or signature verification.

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
fn test_hash_collision_plus_ads() {
    // It is not trivial to create a hash collision for a stream name.
    // This test is a placeholder for a more sophisticated test that could be written
    // if a hash collision is found in the future.
    // The goal would be to have two different stream names that produce the same hash,
    // and then check if the library can distinguish between them.
}

#[test]
fn test_encryption_bypass() {
    // Testing interaction with encrypted file systems (like BitLocker or EFS)
    // is not possible in a unit test. This would require a dedicated integration test
    // environment with an encrypted file system.
    // The test would involve creating an encrypted file, adding an ADS to it, and then
    // checking if the ADS is also encrypted.
}

#[test]
fn test_signature_verification() {
    // Testing if code signing works with ADS suffixes is not possible in a unit test.
    // This would require a code signing certificate and tools, which are not available
    // in the test environment.
    // The test would involve signing a file, adding an ADS to it, and then checking
    // if the signature is still valid.
    // However, we can test that our library rejects paths that try to use ADS to
    // impersonate a signed file.

    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("signed.exe");
    fs::write(&base, b"signed content").unwrap();

    let attacks = [
        "signed.exe:..\\unsigned.exe",
        "signed.exe:stream:$DATA..\\unsigned.exe",
    ];

    for pattern in &attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
    }
}
