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
    assert!(out.starts_with(&base));
    assert!(out.to_string_lossy().contains("file.txt"));
    Ok(())
}
