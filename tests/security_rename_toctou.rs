//! Security tests: Rename TOCTOU during path resolution (cross-platform).
//!
//! Verifies that soft_canonicalize never panics when a directory is renamed
//! by another thread while a resolution walk is in progress.

use soft_canonicalize::soft_canonicalize;
use std::io;

// ─── 7. Rename TOCTOU (cross-platform) ──────────────────────────────────────

mod rename_toctou {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn directory_renamed_during_resolution() -> io::Result<()> {
        // Create tmp/original/deep/file.txt
        // While resolving, rename 'original' to 'renamed'
        let tmp = TempDir::new()?;
        let original = tmp.path().join("original");
        let renamed = tmp.path().join("renamed");
        let deep = original.join("deep");
        fs::create_dir_all(&deep)?;
        fs::write(deep.join("file.txt"), b"data")?;

        let barrier = Arc::new(Barrier::new(2));
        let orig_clone = original.clone();
        let renamed_clone = renamed.clone();
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            barrier_clone.wait();
            // Rename the directory mid-walk
            for _ in 0..50 {
                let _ = fs::rename(&orig_clone, &renamed_clone);
                thread::sleep(std::time::Duration::from_millis(1));
                let _ = fs::rename(&renamed_clone, &orig_clone);
                thread::sleep(std::time::Duration::from_millis(1));
            }
        });

        barrier.wait();

        let path = original.join("deep").join("file.txt");
        for _ in 0..100 {
            let result = soft_canonicalize(&path);
            // Must not panic. May succeed or fail with NotFound/Other
            match result {
                Ok(_) | Err(_) => {}
            }
        }

        handle.join().unwrap();
        // Ensure the directory is back in the expected place for cleanup
        if renamed.exists() && !original.exists() {
            let _ = fs::rename(&renamed, &original);
        }
        Ok(())
    }
}
