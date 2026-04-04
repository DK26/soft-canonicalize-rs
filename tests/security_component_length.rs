//! Security tests: Component length extremes (cross-platform).
//!
//! Verifies that soft_canonicalize does not panic or stack-overflow when
//! given path components at or beyond OS limits, or paths with thousands of
//! redundant ".." / separator sequences.

use soft_canonicalize::soft_canonicalize;
use std::io;

// ─── 8. Component length extremes ───────────────────────────────────────────

mod component_length_attacks {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn single_component_at_os_limit() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // Most filesystems limit component names to 255 bytes
        let max_name = "A".repeat(255);
        let path = tmp.path().join(max_name);

        let result = soft_canonicalize(path);
        // Must not panic. Will likely fail with NotFound (file doesn't exist)
        // or succeed on some filesystems.
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }

    #[test]
    fn single_component_over_os_limit() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let huge_name = "B".repeat(1000);
        let path = tmp.path().join(huge_name);

        let result = soft_canonicalize(path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }

    #[test]
    fn deeply_nested_dotdot_and_components() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // a/../a/../a/../... repeated 5000 times
        let mut segments = String::new();
        for _ in 0..5000 {
            segments.push_str("a/../");
        }
        segments.push_str("final.txt");
        let path = tmp.path().join(&segments);

        let result = soft_canonicalize(path);
        // Must not panic, must not stack overflow
        if let Ok(p) = result {
            // All the a/../ should cancel out
            assert!(
                p.to_string_lossy().contains("final.txt"),
                "All a/../ should cancel: {p:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn path_with_thousands_of_slashes() -> io::Result<()> {
        let tmp = TempDir::new()?;
        // Excessive consecutive separators
        let excessive = format!("{}{}", "/".repeat(5000), "file.txt");
        let path = tmp.path().join(excessive);

        let result = soft_canonicalize(path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }
}
