//! Security tests: Permission-change TOCTOU during path resolution (Unix).
//!
//! Verifies that soft_canonicalize returns clean errors — never panics — when
//! directory permissions are altered concurrently by another thread.

#[cfg(unix)]
use soft_canonicalize::soft_canonicalize;
#[cfg(unix)]
use std::io;

// ─── 2. Permission-Change TOCTOU ────────────────────────────────────────────

#[cfg(unix)]
mod permission_toctou {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn permission_removed_during_resolution() -> io::Result<()> {
        // Create a deep path: tmp/a/b/c/d/file.txt
        // While soft_canonicalize is working, remove read+exec permissions on 'b'
        // The function should either succeed or return a clean error — never panic.
        let tmp = TempDir::new()?;
        let a = tmp.path().join("a");
        let b = a.join("b");
        let c = b.join("c");
        let d = c.join("d");
        fs::create_dir_all(&d)?;
        fs::write(d.join("file.txt"), b"data")?;

        let barrier = Arc::new(Barrier::new(2));
        let b_clone = b.clone();
        let barrier_clone = barrier.clone();

        // Thread that removes permissions mid-walk
        let handle = thread::spawn(move || {
            barrier_clone.wait();
            // Remove read+exec from 'b', which should cause the walk to fail
            let _ = fs::set_permissions(&b_clone, fs::Permissions::from_mode(0o000));
            // Restore after a brief delay so cleanup works
            thread::sleep(std::time::Duration::from_millis(50));
            let _ = fs::set_permissions(&b_clone, fs::Permissions::from_mode(0o755));
        });

        // Try to canonicalize the deep path. The permission change may or may not
        // take effect during our walk.
        barrier.wait();

        let path = d.join("file.txt");
        // Run multiple times to increase chance of hitting the race window
        for _ in 0..20 {
            let result = soft_canonicalize(&path);
            match result {
                Ok(_) => {} // Successfully resolved despite race
                Err(e) => {
                    // PermissionDenied or NotFound are acceptable race outcomes
                    assert!(
                        e.kind() == io::ErrorKind::PermissionDenied
                            || e.kind() == io::ErrorKind::NotFound
                            || e.kind() == io::ErrorKind::Other,
                        "Unexpected error kind during permission TOCTOU: {e:?}"
                    );
                }
            }
        }

        handle.join().unwrap();

        // Ensure cleanup can proceed
        let _ = fs::set_permissions(&b, fs::Permissions::from_mode(0o755));
        Ok(())
    }

    #[test]
    fn permission_restored_during_resolution() -> io::Result<()> {
        // Start with an inaccessible directory, and restore permissions during walk
        let tmp = TempDir::new()?;
        let a = tmp.path().join("a");
        let b = a.join("b");
        fs::create_dir_all(&b)?;
        fs::write(b.join("file.txt"), b"data")?;

        // Remove permissions
        fs::set_permissions(&a, fs::Permissions::from_mode(0o000))?;

        let a_clone = a.clone();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            barrier_clone.wait();
            thread::sleep(std::time::Duration::from_millis(5));
            let _ = fs::set_permissions(&a_clone, fs::Permissions::from_mode(0o755));
        });

        barrier.wait();

        for _ in 0..10 {
            let result = soft_canonicalize(b.join("file.txt"));
            match result {
                Ok(_) | Err(_) => {} // Both are fine
            }
        }

        handle.join().unwrap();
        let _ = fs::set_permissions(&a, fs::Permissions::from_mode(0o755));
        Ok(())
    }
}
