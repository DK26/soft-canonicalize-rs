use crate::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn absolute_and_relative_inputs_under_anchor() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("sandbox");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let cases = [
        ("/etc/passwd", base.join("etc/passwd")),
        ("./foo/bar", base.join("foo/bar")),
        ("a/b/./c", base.join("a/b/c")),
        ("a//b///c", base.join("a/b/c")),
        (
            "path with spaces/file.txt",
            base.join("path with spaces/file.txt"),
        ),
        (
            "path.with.dots/file.txt",
            base.join("path.with.dots/file.txt"),
        ),
    ];
    for (inp, expected_suffix) in cases {
        let out = anchored_canonicalize(&base, inp)?;
        assert!(out.is_absolute());
        assert_eq!(out, expected_suffix);
    }
    Ok(())
}

#[test]
fn long_tail_and_component_limits_do_not_break() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("sandbox");
    fs::create_dir_all(&anchor)?;
    let base = soft_canonicalize(&anchor)?;

    let long_component = "a".repeat(255);
    let path = format!("dir/{}/deep/file.txt", long_component);
    let out = anchored_canonicalize(&base, path)?;

    // Verify output starts with the base (semantic relationship)
    #[cfg(windows)]
    {
        #[cfg(not(feature = "dunce"))]
        {
            // WITHOUT dunce: Both should be in UNC format, direct comparison works
            assert!(
                out.starts_with(&base),
                "Output should start with base (both UNC format)"
            );
        }

        #[cfg(feature = "dunce")]
        {
            // WITH dunce: Normalize for comparison (both may be simplified or mixed)
            let out_str = out.to_string_lossy();
            let base_str = base.to_string_lossy();

            let out_normalized =
                std::path::PathBuf::from(out_str.strip_prefix(r"\\?\").unwrap_or(&out_str));
            let base_normalized =
                std::path::PathBuf::from(base_str.strip_prefix(r"\\?\").unwrap_or(&base_str));

            assert!(
                out_normalized.starts_with(base_normalized),
                "Output should start with base (normalized)"
            );
        }
    }
    #[cfg(not(windows))]
    {
        assert!(out.starts_with(&base));
    }

    assert!(out.to_string_lossy().contains("file.txt"));
    Ok(())
}
