use crate::anchored_canonicalize;
use std::fs;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn anchored_strips_root_and_clamps_dotdot() -> std::io::Result<()> {
    // Anchor under a temp root
    let td = TempDir::new()?;
    let anchor = td.path().join("home").join("myuser");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Inputs with leading slash and with excessive .. should both resolve under anchor
    let out1 = anchored_canonicalize(&abs_anchor, "/etc/passwd")?;
    let out2 = anchored_canonicalize(&abs_anchor, "../../../../../etc/passwd")?;

    assert_eq!(out1, abs_anchor.join("etc").join("passwd"));
    assert_eq!(out2, abs_anchor.join("etc").join("passwd"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn absolute_symlink_inside_anchor_keeps_within_anchor() -> std::io::Result<()> {
    // Layout inside anchor
    let td = TempDir::new()?;
    let anchor = td.path().join("home").join("myuser");
    let docs = anchor.join("docs");
    let project = anchor.join("project");
    fs::create_dir_all(docs.join("dir1/dir2/dir3"))?;
    fs::create_dir_all(&project)?;
    fs::create_dir_all(&project)?;
    fs::create_dir_all(&anchor)?; // ensure anchor exists
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create absolute symlink: anchor/project/docs -> anchor/docs/dir1/dir2/dir3/project
    let target = abs_anchor.join("docs/dir1/dir2/dir3/project");
    let link = abs_anchor.join("project/docs");
    fs::create_dir_all(link.parent().unwrap())?;
    std::os::unix::fs::symlink(target, &link)?;

    // Input per example: project/docs/../../etc/passwd
    let out = anchored_canonicalize(&abs_anchor, "project/docs/../../etc/passwd")?;
    assert_eq!(out, abs_anchor.join("docs/dir1/dir2/etc/passwd"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn absolute_symlink_allows_escape() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("home").join("myuser");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create an external absolute target outside the anchor
    let outside = td.path().join("etc/outside/anchor/path");
    fs::create_dir_all(&outside)?;
    let abs_outside = fs::canonicalize(&outside)?;

    // Symlink inside anchor pointing to absolute outside
    let link = abs_anchor.join("escape_anchor_dir");
    std::os::unix::fs::symlink(&abs_outside, link)?;

    // Following the absolute symlink should escape the anchor (clamp removed)
    let out = anchored_canonicalize(&abs_anchor, "escape_anchor_dir")?;
    assert_eq!(out, abs_outside);
    Ok(())
}

#[cfg(unix)]
#[test]
fn relative_symlink_resolves_under_anchor_and_clamps() -> std::io::Result<()> {
    // Setup anchor and directories
    let td = TempDir::new()?;
    let anchor = td.path().join("home").join("myuser");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create target at docs/dir1/dir2/dir3/project
    let docs = abs_anchor.join("docs/dir1/dir2/dir3/project");
    fs::create_dir_all(docs)?;

    // Create relative symlink: project/docs -> ../../docs/dir1/dir2/dir3/project
    let project = abs_anchor.join("project");
    fs::create_dir_all(&project)?;
    let link_parent = project;
    let link = link_parent.join("docs");
    // target relative to link parent (project)
    std::os::unix::fs::symlink("../docs/dir1/dir2/dir3/project", link)?;

    // Input per example: project/docs/../../etc/passwd
    let out = anchored_canonicalize(&abs_anchor, "project/docs/../../etc/passwd")?;
    assert_eq!(out, abs_anchor.join("docs/dir1/dir2/etc/passwd"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn hop_limit_and_cycles_are_detected() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;

    let td = TempDir::new()?;
    let anchor = td.path().join("x");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create a small cycle: a -> b, b -> a
    let a = abs_anchor.join("a");
    let b = abs_anchor.join("b");
    symlink("b", a)?; // relative links
    symlink("a", b)?;

    let err = anchored_canonicalize(&abs_anchor, "a").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    Ok(())
}

#[cfg(unix)]
#[test]
fn anchor_can_be_non_existing() -> std::io::Result<()> {
    let missing = std::path::Path::new("/definitely/does/not/exist/soft_canon_anchor_test");
    let out = anchored_canonicalize(missing, "foo")?;
    // Should return an absolute path anchored to the deepest existing prefix of `missing`
    assert!(out.is_absolute());
    assert!(out.ends_with("foo"));
    Ok(())
}

// Windows: We avoid symlink creation in CI environments lacking privileges. We still
// validate basic clamping and root stripping semantics without symlinks.
#[cfg(windows)]
#[test]
fn anchored_basic_clamp_windows() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("a").join("b");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = crate::soft_canonicalize(&anchor)?; // yields extended-length

    let out1 = anchored_canonicalize(&abs_anchor, r"/etc/passwd")?;
    let out2 = anchored_canonicalize(&abs_anchor, r"..\\..\\..\\etc\\passwd")?;

    let expected =
        std::path::PathBuf::from(format!(r"{}\etc\passwd", abs_anchor.to_string_lossy()));
    assert_eq!(out1, expected);
    assert_eq!(out2, expected);
    Ok(())
}

#[cfg(windows)]
#[test]
fn ads_validation_applies() -> std::io::Result<()> {
    let td = TempDir::new()?;
    let anchor = td.path().join("x");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = crate::soft_canonicalize(&anchor)?;

    // A colon in non-final component should be rejected
    let err = anchored_canonicalize(&abs_anchor, r"bad:part\tail").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Valid ADS only as final component should pass lexically (we don't touch filesystem here)
    let ok = anchored_canonicalize(&abs_anchor, r"file.txt:stream");
    assert!(ok.is_ok());
    Ok(())
}

#[cfg(unix)]
#[test]
fn security_wrapper_rejects_symlink_escapes() -> std::io::Result<()> {
    use std::fs;

    /// Security wrapper that rejects ALL anchor escapes, including via absolute symlinks
    fn secure_anchored_canonicalize(
        anchor: &std::path::Path,
        input: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        let result = anchored_canonicalize(anchor, input)?;

        // Security check: ensure result is still within the anchor
        if result.starts_with(anchor) {
            Ok(result)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Path escapes virtual boundary via symlink",
            ))
        }
    }

    let td = TempDir::new()?;
    let anchor = td.path().join("secure_root");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create external target outside anchor
    let outside = td.path().join("external");
    fs::create_dir_all(&outside)?;
    let abs_outside = fs::canonicalize(&outside)?;

    // Create absolute symlink pointing outside
    let escape_link = abs_anchor.join("escape_link");
    std::os::unix::fs::symlink(&abs_outside, escape_link)?;

    // anchored_canonicalize allows the escape (correct canonicalize behavior)
    let escaped = anchored_canonicalize(&abs_anchor, "escape_link")?;
    assert_eq!(escaped, abs_outside);
    assert!(!escaped.starts_with(&abs_anchor)); // Confirms escape

    // Security wrapper rejects the escape
    let err = secure_anchored_canonicalize(&abs_anchor, "escape_link").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("escapes virtual boundary"));

    // But normal paths within anchor still work
    let safe = secure_anchored_canonicalize(&abs_anchor, "safe/path")?;
    assert!(safe.starts_with(&abs_anchor));

    Ok(())
}
