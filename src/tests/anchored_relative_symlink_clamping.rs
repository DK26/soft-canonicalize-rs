/// Tests for anchored_canonicalize relative symlink clamping behavior
///
/// These tests verify that relative symlinks cannot escape the anchor boundary,
/// implementing true virtual filesystem semantics where the anchor acts as root.
use crate::anchored_canonicalize;
use std::fs;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn test_relative_symlink_escaping_upwards_is_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("vroot");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create directory structure:
    // vroot/
    //   subdir/
    //     link -> ../../../etc/passwd
    let subdir = abs_anchor.join("subdir");
    fs::create_dir_all(&subdir).unwrap();

    let symlink_path = subdir.join("link");
    // This relative target tries to escape THREE levels up, then go to /etc/passwd
    symlink("../../../etc/passwd", symlink_path).unwrap();

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "subdir/link").unwrap();

    // EXPECTED: Should clamp to anchor/etc/passwd, NOT system /etc/passwd
    assert!(
        result.starts_with(&abs_anchor),
        "Relative symlink should be clamped to anchor. Got: {:?}, Anchor: {:?}",
        result,
        abs_anchor
    );

    let expected = abs_anchor.join("etc/passwd");
    assert_eq!(
        result, expected,
        "Relative symlink ../../../etc/passwd from anchor/subdir should resolve to anchor/etc/passwd"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_symlink_with_moderate_escape_is_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("vroot");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create directory structure:
    // vroot/
    //   a/
    //     b/
    //       c/
    //         link -> ../../../../opt/file
    let deep_dir = abs_anchor.join("a/b/c");
    fs::create_dir_all(&deep_dir).unwrap();

    let symlink_path = deep_dir.join("link");
    // This relative target tries to escape FOUR levels up, then go to /opt/file
    symlink("../../../../opt/file", symlink_path).unwrap();

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "a/b/c/link").unwrap();

    // EXPECTED: Should clamp to anchor/opt/file, NOT system /opt/file
    assert!(
        result.starts_with(&abs_anchor),
        "Relative symlink should be clamped to anchor. Got: {:?}, Anchor: {:?}",
        result,
        abs_anchor
    );

    let expected = abs_anchor.join("opt/file");
    assert_eq!(
        result, expected,
        "Relative symlink ../../../../opt/file from anchor/a/b/c should resolve to anchor/opt/file"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_symlink_within_anchor_no_escape() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("vroot");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create directory structure:
    // vroot/
    //   dir1/
    //     link -> ../dir2/file
    //   dir2/
    //     file (target)
    let dir1 = abs_anchor.join("dir1");
    let dir2 = abs_anchor.join("dir2");
    fs::create_dir_all(&dir1).unwrap();
    fs::create_dir_all(&dir2).unwrap();
    fs::write(dir2.join("file"), b"test data").unwrap();

    let symlink_path = dir1.join("link");
    // This relative target stays within anchor bounds
    symlink("../dir2/file", symlink_path).unwrap();

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "dir1/link").unwrap();

    // EXPECTED: Should resolve normally to anchor/dir2/file
    let expected = abs_anchor.join("dir2/file");
    assert_eq!(
        result, expected,
        "Relative symlink within anchor bounds should resolve normally"
    );
}

#[cfg(windows)]
#[test]
fn test_windows_relative_symlink_escaping_is_clamped() -> std::io::Result<()> {
    use std::os::windows::fs::symlink_file;

    let td = TempDir::new()?;
    let anchor = td.path().join("vroot");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create directory structure:
    // vroot\
    //   subdir\
    //     link -> ..\..\..\Windows\System32\cmd.exe
    let subdir = abs_anchor.join("subdir");
    fs::create_dir_all(&subdir)?;

    let symlink_path = subdir.join("link");
    // This relative target tries to escape THREE levels up to access Windows directory
    let create_result = symlink_file(r"..\..\..\Windows\System32\cmd.exe", symlink_path);

    // Check for privilege error (error 1314 = ERROR_PRIVILEGE_NOT_HELD)
    if let Err(e) = create_result {
        if let Some(1314) = e.raw_os_error() {
            eprintln!("Skipping test: symlink creation requires elevated privileges on Windows");
            return Ok(());
        }
        return Err(e);
    }

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, r"subdir\link")?;

    // EXPECTED: Should clamp to anchor\Windows\System32\cmd.exe, NOT system C:\Windows\System32\cmd.exe
    let expected = abs_anchor.join(r"Windows\System32\cmd.exe");

    // Feature-conditional assertion for dunce
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            result, expected,
            "Relative symlink should be clamped to anchor\\Windows\\System32\\cmd.exe"
        );
    }

    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        let expected_str = expected.to_string_lossy();
        assert!(
            !result_str.starts_with(r"\\?\"),
            "dunce should simplify: {:?}",
            result_str
        );
        assert_eq!(
            result_str.as_ref(),
            expected_str.trim_start_matches(r"\\?\"),
            "Relative symlink should be clamped to anchor\\Windows\\System32\\cmd.exe"
        );
    }

    Ok(())
}

#[cfg(windows)]
#[test]
fn test_windows_relative_symlink_within_anchor() -> std::io::Result<()> {
    use std::os::windows::fs::symlink_file;

    let td = TempDir::new()?;
    let anchor = td.path().join("vroot");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create directory structure:
    // vroot\
    //   dir1\
    //     link -> ..\dir2\file.txt
    //   dir2\
    //     file.txt (target)
    let dir1 = abs_anchor.join("dir1");
    let dir2 = abs_anchor.join("dir2");
    fs::create_dir_all(&dir1)?;
    fs::create_dir_all(&dir2)?;
    fs::write(dir2.join("file.txt"), b"test data")?;

    let symlink_path = dir1.join("link");
    // This relative target stays within anchor bounds
    let create_result = symlink_file(r"..\dir2\file.txt", symlink_path);

    // Check for privilege error
    if let Err(e) = create_result {
        if let Some(1314) = e.raw_os_error() {
            eprintln!("Skipping test: symlink creation requires elevated privileges on Windows");
            return Ok(());
        }
        return Err(e);
    }

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, r"dir1\link")?;

    // EXPECTED: Should resolve normally to anchor\dir2\file.txt
    let expected = abs_anchor.join(r"dir2\file.txt");

    // Feature-conditional assertion for dunce
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            result, expected,
            "Relative symlink within anchor should resolve normally"
        );
    }

    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        let expected_str = expected.to_string_lossy();
        assert!(
            !result_str.starts_with(r"\\?\"),
            "dunce should simplify: {:?}",
            result_str
        );
        assert_eq!(
            result_str.as_ref(),
            expected_str.trim_start_matches(r"\\?\"),
            "Relative symlink within anchor should resolve normally"
        );
    }

    Ok(())
}

#[cfg(unix)]
#[test]
fn test_absolute_symlink_to_etc_is_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("vroot");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create symlink INSIDE anchor pointing to /etc/passwd
    let symlink_path = abs_anchor.join("link_to_etc");
    symlink("/etc/passwd", symlink_path).unwrap();

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "link_to_etc").unwrap();

    // EXPECTED: Should clamp to anchor/etc/passwd, NOT system /etc/passwd
    assert!(
        result.starts_with(&abs_anchor),
        "Absolute symlink should be clamped to anchor. Got: {:?}, Anchor: {:?}",
        result,
        abs_anchor
    );

    let expected = abs_anchor.join("etc/passwd");
    assert_eq!(
        result, expected,
        "Absolute symlink /etc/passwd should resolve to anchor/etc/passwd"
    );
}

#[cfg(windows)]
#[test]
fn test_windows_absolute_symlink_to_windows_dir_is_clamped() -> std::io::Result<()> {
    use std::os::windows::fs::symlink_dir;

    let td = TempDir::new()?;
    let anchor = td.path().join("vroot");
    fs::create_dir_all(&anchor)?;
    let abs_anchor = fs::canonicalize(&anchor)?;

    // Create symlink INSIDE anchor pointing to C:\Windows
    let symlink_path = abs_anchor.join("link_to_windows");
    let create_result = symlink_dir(r"C:\Windows", symlink_path);

    // Check for privilege error
    if let Err(e) = create_result {
        if let Some(1314) = e.raw_os_error() {
            eprintln!("Skipping test: symlink creation requires elevated privileges on Windows");
            return Ok(());
        }
        return Err(e);
    }

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "link_to_windows")?;

    // EXPECTED: Should clamp to anchor\Windows, NOT system C:\Windows
    let expected = abs_anchor.join("Windows");

    // Feature-conditional assertion for dunce
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(
            result, expected,
            "Absolute symlink should be clamped to anchor\\Windows"
        );
    }

    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        let expected_str = expected.to_string_lossy();
        assert!(
            !result_str.starts_with(r"\\?\"),
            "dunce should simplify: {:?}",
            result_str
        );
        assert_eq!(
            result_str.as_ref(),
            expected_str.trim_start_matches(r"\\?\"),
            "Absolute symlink should be clamped to anchor\\Windows"
        );
    }

    Ok(())
}
