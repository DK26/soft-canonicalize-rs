#![cfg(windows)]
//! Race Condition Exploits Tests
//!
//! This suite tests for vulnerabilities related to race conditions (TOCTOU)
//! during ADS parsing and canonicalization.

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::sync::Arc;
use std::thread;

#[test]
fn test_ads_creation_race() {
    // This test attempts to create a race condition by creating and deleting the base file
    // while `soft_canonicalize` is running. This is not guaranteed to catch race conditions,
    // as it depends on the timing of the threads.

    let tmp = Arc::new(tempfile::tempdir().unwrap());
    let base_path = Arc::new(tmp.path().join("base_file.txt"));
    let ads_path = Arc::new(tmp.path().join("base_file.txt:stream"));

    let mut handles = vec![];

    for _ in 0..10 {
        let ads_path = Arc::clone(&ads_path);
        let base_path = Arc::clone(&base_path);

        let handle = thread::spawn(move || {
            let _ = soft_canonicalize(&*ads_path);
        });
        handles.push(handle);

        let handle = thread::spawn(move || {
            let _ = fs::write(&*base_path, b"test");
            let _ = fs::remove_file(&*base_path);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_type_token_race() {
    // It is difficult to test a race condition on the type token, because the validation
    // happens within the `validate_windows_ads_layout` function without intermediate
    // file system access. This test is a placeholder for a more sophisticated test
    // that could potentially be written with more control over thread scheduling.
}

#[test]
fn test_filesystem_race() {
    // This test attempts to create a race condition by creating and deleting directories
    // in the path while `soft_canonicalize` is running.

    let tmp = Arc::new(tempfile::tempdir().unwrap());
    let path_to_manipulate = Arc::new(tmp.path().join("a/b/c/file.txt:stream"));

    let mut handles = vec![];

    for _ in 0..10 {
        let path = Arc::clone(&path_to_manipulate);
        let tmp_path = Arc::clone(&tmp);

        let handle = thread::spawn(move || {
            let _ = soft_canonicalize(&*path);
        });
        handles.push(handle);

        let handle = thread::spawn(move || {
            let dir_a = tmp_path.path().join("a");
            let _dir_b = tmp_path.path().join("a/b");
            let dir_c = tmp_path.path().join("a/b/c");
            let _ = fs::create_dir_all(dir_c);
            let _ = fs::remove_dir_all(dir_a);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
