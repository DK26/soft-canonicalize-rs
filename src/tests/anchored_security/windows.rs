use crate::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn ads_layout_validation_applies_to_input() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("x");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    // Colon in non-final component is invalid
    let err = anchored_canonicalize(&base, r"bad:part\tail").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Valid ADS only as final component should be accepted lexically
    let ok = anchored_canonicalize(&base, r"file.txt:stream");
    assert!(ok.is_ok());
    Ok(())
}

#[test]
fn extended_length_prefix_on_absolute_results() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("a").join("b");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;
    let out = anchored_canonicalize(&base, r"c\d\e.txt")?;
    let base_str = base.to_string_lossy();
    let expected = std::path::PathBuf::from(format!(r"{}\c\d\e.txt", base_str));
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn non_existing_anchor_supported_windows() -> std::io::Result<()> {
    // Anchor path does not exist; function should still succeed (soft behavior)
    let td = TempDir::new()?;
    let anchor = td.path().join("does_not_exist").join("still_missing");

    let out = anchored_canonicalize(&anchor, r"subdir\file.txt")?;
    let base = soft_canonicalize(&anchor)?;
    let expected = std::path::PathBuf::from(format!(r"{}\subdir\file.txt", base.to_string_lossy()));
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn anchor_with_dotdot_normalization_windows() -> std::io::Result<()> {
    // Verifies that an anchor containing `..` is soft-canonicalized internally
    // and that both simple and nested input cases resolve identically under the normalized base.
    // Scenario inspired by:
    //   anchor: C:\Users\non-existing\dir1\dir2\..\..\folder
    //   path1:  hello\world
    //   path2:  hello\dir1\dir2\..\..\world
    let td = TempDir::new()?;
    let users = td.path().join("Users");
    fs::create_dir_all(&users)?; // ensure a small existing prefix

    // Use a single relative tail string with dot-dot segments for clarity
    let anchor_raw = users.join(r"non-existing\dir1\dir2\..\..\folder");

    // Expected normalized anchor base: Users/non-existing/folder (extended-length absolute)
    let expected_base = soft_canonicalize(users.join(r"non-existing\folder"))?;

    let out1 = anchored_canonicalize(&anchor_raw, r"hello\world")?;
    let out2 = anchored_canonicalize(&anchor_raw, r"hello\dir1\dir2\..\..\world")?;

    // Both should resolve to the same final path under the normalized base
    let expected =
        std::path::PathBuf::from(format!(r"{}\hello\world", expected_base.to_string_lossy()));
    assert_eq!(out1, expected);
    assert_eq!(out2, expected);

    // Full equality already implies correct prefix formatting via soft_canonicalize
    Ok(())
}

#[test]
fn anchor_users_literal_nonexisting_windows() -> std::io::Result<()> {
    // Uses a literal Users-based anchor and compares against a full literal expected value.
    let anchor = std::path::Path::new(r"C:\\Users\\non-existing\\dir1\\dir2\\..\\..\\folder");
    let out1 = anchored_canonicalize(anchor, r"hello\\world")?;
    let out2 = anchored_canonicalize(anchor, r"hello\\dir1\\dir2\\..\\..\\world")?;

    #[cfg(not(feature = "dunce"))]
    {
        // WITHOUT dunce: MUST return UNC format
        let expected =
            std::path::PathBuf::from(r"\\?\C:\\Users\\non-existing\\folder\\hello\\world");
        assert_eq!(
            out1, expected,
            "First output should match expected UNC format"
        );
        assert_eq!(
            out2, expected,
            "Second output should match expected UNC format"
        );
    }

    #[cfg(feature = "dunce")]
    {
        // WITH dunce: Should return simplified (non-UNC) format
        let expected = std::path::PathBuf::from(r"C:\Users\non-existing\folder\hello\world");
        assert_eq!(
            out1, expected,
            "First output should match expected simplified format"
        );
        assert_eq!(
            out2, expected,
            "Second output should match expected simplified format"
        );

        // Both outputs should be identical
        assert_eq!(
            out1, out2,
            "Both traversal paths should resolve to same result"
        );
    }

    Ok(())
}
