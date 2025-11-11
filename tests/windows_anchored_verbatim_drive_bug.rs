//! Positive regression tests for anchored_canonicalize verbatim drive paths on Windows.
//!
//! Goal: Validate ONLY the correct expected outputs. We do not match against incorrect
//! patterns. For a canonicalized temp-dir anchor and various absolute-like candidates
//! (starting with '/'), the result must equal anchor joined with the candidate tail.
//! Without `dunce`, expect extended-length equality; with `dunce`, expect simplified equality.

#![cfg(all(feature = "anchored", windows))]

use soft_canonicalize::anchored_canonicalize;
use std::path::Path;

#[test]
fn anchored_canonicalize_verbatim_drive_path_expected_equality() -> std::io::Result<()> {
    // 1) Use canonicalized temp dir as anchor (common usage pattern)
    let anchor = std::fs::canonicalize(std::env::temp_dir())?;

    // 2) Candidates with root components (absolute-like). Anchored semantics interpret these
    //    relative to the anchor (i.e., should end up under `anchor`).
    let candidates = ["/data/dir", "/Users/test", "/etc/passwd", "/foo/bar/baz"];

    for candidate in candidates {
        let candidate_path = Path::new(candidate);
        let result = anchored_canonicalize(&anchor, candidate_path)?;
        let expected = anchor.join(candidate.trim_start_matches('/'));

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                result, expected,
                "expected exact extended-length anchor + tail for {:?}",
                candidate
            );
        }
        #[cfg(feature = "dunce")]
        {
            let res_s = result.to_string_lossy();
            let exp_s = expected.to_string_lossy();
            assert_eq!(
                res_s.as_ref(),
                exp_s.trim_start_matches(r"\\?\"),
                "expected simplified absolute path for {:?}",
                candidate
            );
        }
    }

    Ok(())
}

#[test]
fn anchored_canonicalize_verbatim_drive_positive_eq() -> std::io::Result<()> {
    // This test verifies that the result is actually under the anchor,
    // which can fail if the path is malformed.

    let anchor = std::fs::canonicalize(std::env::temp_dir())?;
    let candidate = Path::new("/data/dir");

    let result = anchored_canonicalize(&anchor, candidate)?;

    let expected = anchor.join("data").join("dir");

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            result, expected,
            "expected exact extended-length absolute path"
        );
    }
    #[cfg(feature = "dunce")]
    {
        let res_s = result.to_string_lossy();
        let exp_s = expected.to_string_lossy();
        assert_eq!(
            res_s.as_ref(),
            exp_s.trim_start_matches(r"\\?\"),
            "expected simplified absolute path"
        );
    }

    Ok(())
}

#[test]
fn anchored_canonicalize_various_root_like_paths_positive_eq() -> std::io::Result<()> {
    // Test various root-like candidates that could trigger the bug
    let anchor = std::fs::canonicalize(std::env::temp_dir())?;

    let test_cases = vec![
        ("/", "root only"),
        ("/a", "single letter after root"),
        ("/abc", "short name after root"),
        ("/data", "common directory name"),
        ("/data/subdir", "nested path"),
        ("/x/y/z", "deeply nested"),
    ];

    for (candidate, description) in test_cases {
        let result = anchored_canonicalize(&anchor, candidate)?;
        // For root-only '/', the expected path is exactly the anchor.
        let expected = if candidate == "/" {
            anchor.clone()
        } else {
            anchor.join(candidate.trim_start_matches('/'))
        };

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                result, expected,
                "{}: expected exact extended-length anchor + tail for {:?}",
                description, candidate
            );
        }
        #[cfg(feature = "dunce")]
        {
            let res_s = result.to_string_lossy();
            let exp_s = expected.to_string_lossy();
            assert_eq!(
                res_s.as_ref(),
                exp_s.trim_start_matches(r"\\?\"),
                "{}: expected simplified absolute path for {:?}",
                description,
                candidate
            );
        }
    }

    Ok(())
}

#[test]
fn anchored_canonicalize_relative_paths_expected_eq() -> std::io::Result<()> {
    // Verify that relative paths (without leading /) don't have the bug either
    let anchor = std::fs::canonicalize(std::env::temp_dir())?;

    let relative_candidates = ["data/dir", "a/b/c", "test", "foo/bar"];

    for candidate in relative_candidates {
        let result = anchored_canonicalize(&anchor, candidate)?;
        let expected = anchor.join(candidate);

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                result, expected,
                "expected exact extended-length path for {:?}",
                candidate
            );
        }
        #[cfg(feature = "dunce")]
        {
            let res_s = result.to_string_lossy();
            let exp_s = expected.to_string_lossy();
            assert_eq!(
                res_s.as_ref(),
                exp_s.trim_start_matches(r"\\?\"),
                "expected simplified path for {:?}",
                candidate
            );
        }
    }

    Ok(())
}

#[test]
fn anchored_canonicalize_explicit_temp_path_structure_positive_eq() -> std::io::Result<()> {
    // Replicate the exact pattern from the bug report
    let anchor = std::fs::canonicalize(std::env::temp_dir())?;
    let candidate = Path::new("/data/dir");

    let result = anchored_canonicalize(&anchor, candidate)?;

    let expected = anchor.join("data").join("dir");

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            result, expected,
            "expected exact extended-length absolute path"
        );
    }
    #[cfg(feature = "dunce")]
    {
        let res_s = result.to_string_lossy();
        let exp_s = expected.to_string_lossy();
        assert_eq!(
            res_s.as_ref(),
            exp_s.trim_start_matches(r"\\?\"),
            "expected simplified absolute path"
        );
    }

    Ok(())
}

#[test]
fn anchored_canonicalize_non_canonicalized_anchor_with_root_candidate_positive_eq(
) -> std::io::Result<()> {
    // Test with a non-canonicalized anchor that may trigger the bug path
    // The bug report mentions using canonicalized anchor, but the issue might occur
    // in the internal path construction

    use tempfile::TempDir;
    let tmpdir = TempDir::new()?;

    // Create a non-existing path as anchor (this will be soft-canonicalized internally)
    let anchor = tmpdir.path().join("jail");
    std::fs::create_dir_all(&anchor)?;

    // Try different root-like candidates
    let candidates = [
        "/data/dir",
        "/etc/passwd",
        "/config/app.conf",
        "/usr/local/bin",
    ];

    for candidate in candidates {
        let result = anchored_canonicalize(&anchor, candidate)?;
        let anchor_canonical = std::fs::canonicalize(&anchor)?;
        let expected = anchor_canonical.join(candidate.trim_start_matches('/'));

        #[cfg(not(feature = "dunce"))]
        {
            assert_eq!(
                result, expected,
                "expected exact extended-length absolute path for {:?}",
                candidate
            );
        }
        #[cfg(feature = "dunce")]
        {
            let res_s = result.to_string_lossy();
            let exp_s = expected.to_string_lossy();
            assert_eq!(
                res_s.as_ref(),
                exp_s.trim_start_matches(r"\\?\"),
                "expected simplified absolute path for {:?}",
                candidate
            );
        }
    }

    Ok(())
}
