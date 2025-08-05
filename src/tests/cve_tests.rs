#![cfg(unix)]

use crate::soft_canonicalize;
use std::{fs, thread, time::Duration};
use tempfile::Builder;

#[test]
fn test_cve_2022_21658_race_condition() {
    let temp_dir = Builder::new().prefix("cve_test").tempdir().unwrap();
    let root = temp_dir.path();

    let real_target = root.join("real_target");
    fs::create_dir(&real_target).unwrap();

    let symlink_path = root.join("symlink");
    std::os::unix::fs::symlink(&real_target, &symlink_path).unwrap();

    let secret_target = root.join("secret_target");
    fs::create_dir(&secret_target).unwrap();

    let symlink_path_clone = symlink_path.clone();
    let secret_target_clone = secret_target.clone();

    let handle = thread::spawn(move || {
        // Give the main thread a chance to start processing the path
        thread::sleep(Duration::from_millis(10));

        // Simulate the attack: quickly replace the symlink
        fs::remove_file(&symlink_path_clone).unwrap();
        std::os::unix::fs::symlink(&secret_target_clone, &symlink_path_clone).unwrap();
    });

    // Attempt to canonicalize the path. This should be safe and not follow the new symlink.
    let result = soft_canonicalize(&symlink_path);

    handle.join().unwrap();

    // The result should be the *original* target, not the secret one.
    // soft_canonicalize should have resolved the symlink before it was replaced.
    assert_eq!(result.unwrap(), real_target);
}
