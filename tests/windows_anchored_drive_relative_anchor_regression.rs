//! Positive regression test: drive-relative anchor is normalized to a correct absolute verbatim path.
//!
//! We construct a synthetic drive-relative anchor (e.g. `C:Users\...`) from the canonical
//! temp directory and ensure `anchored_canonicalize` returns the correct absolute result.
//!
//! Validation focus: assert ONLY the correct expected output (never enumerate incorrect forms).
//! On Windows without the `dunce` feature we expect an extended-length path beginning with
//! `\\?\C:\`. With `dunce` enabled we expect the simplified absolute path (`C:\...`).

#![cfg(all(feature = "anchored", windows))]

use soft_canonicalize::anchored_canonicalize;
use std::path::{Component, PathBuf};

// Keep test focused on asserting correct output only.

#[test]
fn drive_relative_anchor_is_normalized_to_absolute() -> std::io::Result<()> {
    // Canonical temp dir (absolute, extended-length already on Windows)
    let abs_temp = std::fs::canonicalize(std::env::temp_dir())?;
    let abs_str = abs_temp.to_string_lossy();

    // Derive drive-relative form: strip the first backslash after drive colon.
    // Handle both `C:\` and `\\?\C:\` prefixes.
    let drive_relative = if let Some(rest) = abs_str.strip_prefix(r"\\?\") {
        // rest starts with `C:\Users...`
        if rest.len() >= 3 && &rest[1..2] == ":" && &rest[2..3] == "\\" {
            // Build `C:Users\...`
            let mut s = String::from(&rest[0..2]); // `C:`
            s.push_str(&rest[3..]);
            PathBuf::from(s)
        } else {
            // Unexpected structure; fall back to absolute path (skip test silently)
            eprintln!(
                "Skipping: unexpected extended-length drive prefix format: {}",
                abs_str
            );
            return Ok(());
        }
    } else if abs_str.len() >= 3 && &abs_str[1..2] == ":" && &abs_str[2..3] == "\\" {
        // Form `C:Users\...` from `C:\Users\...`
        let mut s = String::from(&abs_str[0..2]);
        s.push_str(&abs_str[3..]);
        PathBuf::from(s)
    } else {
        eprintln!(
            "Skipping: temp dir path not in expected absolute drive form: {}",
            abs_str
        );
        return Ok(());
    };

    // Intentionally not printing the synthetic drive-relative anchor to keep test output clean.

    // Sanity: components should show Prefix(Disk) followed directly by Normal, not RootDir.
    let comps: Vec<_> = drive_relative.components().collect();
    // Preconditions: first component is a disk prefix and next is a normal component (drive-relative form).
    assert!(
        matches!(comps.first(), Some(Component::Prefix(_))),
        "expected disk prefix in drive-relative form"
    );
    assert!(
        matches!(comps.get(1), Some(Component::Normal(_))),
        "expected normal component after prefix (drive-relative)"
    );
    assert!(
        !matches!(comps.get(1), Some(Component::RootDir)),
        "did not expect RootDir here (would be absolute already)"
    );

    // Invoke anchored_canonicalize with the drive-relative anchor.
    // We expect the implementation to normalize it to an absolute extended-length form.
    let out = anchored_canonicalize(&drive_relative, "/data/dir")?;
    // Keep output quiet; assert only on the expected value below.

    // Assert the correct expected output only.
    // Build expected by taking the canonical absolute anchor and joining the candidate tail.
    let expected_abs_anchor = std::fs::canonicalize(std::env::temp_dir())?;
    let expected = expected_abs_anchor.join("data").join("dir");

    #[cfg(not(feature = "dunce"))]
    {
        // Without dunce: expect verbatim extended-length exact match.
        assert_eq!(
            out, expected,
            "expected exact extended-length absolute anchor + tail"
        );
    }
    #[cfg(feature = "dunce")]
    {
        // With dunce: result simplified (no verbatim prefix); compare string forms accordingly.
        let out_s = out.to_string_lossy();
        let exp_s = expected.to_string_lossy();
        assert_eq!(
            out_s.as_ref(),
            exp_s.trim_start_matches(r"\\?\"),
            "expected simplified absolute anchor + tail"
        );
    }

    Ok(())
}
