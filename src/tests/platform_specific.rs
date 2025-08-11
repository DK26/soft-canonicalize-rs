//! Platform-specific tests for soft_canonicalize
//!
//! Tests Windows-specific and Unix-specific path formats
//! to validate cross-platform claims.

use crate::soft_canonicalize;

#[cfg(unix)]
use std::fs;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(unix)]
use tempfile::tempdir;

#[cfg(windows)]
#[test]
fn test_windows_specific_paths() -> std::io::Result<()> {
    // Test Windows-specific path formats to validate cross-platform claims

    // Test UNC path format (if possible)
    let unc_style = r"\\?\C:\temp\non\existing\file.txt";
    if let Ok(result) = soft_canonicalize(unc_style) {
        assert!(result.is_absolute());
        assert!(result.to_string_lossy().contains("file.txt"));
    }

    // Test drive letter paths
    let drive_path = "C:/non/existing/file.txt";
    let result = soft_canonicalize(drive_path)?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("file.txt"));

    // Test mixed separators (Windows should handle both / and \)
    let mixed_path = r"C:\non/existing\file.txt";
    let result = soft_canonicalize(mixed_path)?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("file.txt"));

    Ok(())
}

#[cfg(windows)]
#[test]
fn test_windows_unc_nonexistent_absolute_has_expected_prefix() {
    // Explicitly validate the extended-length prefix formatting for a non-existent absolute path
    let got = soft_canonicalize(r"C:\NonExistent\Path\That\Does\Not\Exist").unwrap();
    assert_eq!(
        got,
        PathBuf::from(r"\\?\C:\\NonExistent\Path\That\Does\Not\Exist")
    );
}

#[cfg(windows)]
#[test]
fn test_windows_nonexistent_jail_starts_with_consistency() {
    // Given a non-existent absolute jail, canonicalize jail and an inside child
    let jail_raw = r"C:\NonExistent\Path\That\Does\Not\Exist";
    let child_raw = format!("{}\\foo.txt", jail_raw);

    let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
    let child = soft_canonicalize(child_raw).expect("canonicalize child");

    assert!(
        child.starts_with(&jail),
        "Canonicalized child must start with canonicalized jail: child={:?}, jail={:?}",
        child,
        jail
    );
}

#[cfg(windows)]
#[test]
fn test_windows_extended_prefix_idempotent_for_nonexistent() {
    // Canonicalizing a verbatim (\\?\) path should be idempotent
    let verbatim = PathBuf::from(r"\\?\C:\\NonExistent\Path\That\Does\Not\Exist");
    let again = soft_canonicalize(&verbatim).expect("canonicalize verbatim");
    assert_eq!(
        again, verbatim,
        "Verbatim path canonicalization must be idempotent"
    );
}

#[cfg(windows)]
#[test]
fn test_windows_unc_server_share_nonexistent_starts_with() {
    // UNC server/share should become \\?\UNC\server\share and preserve starts_with
    let jail_raw = r"\\server\share\nonexistent";
    let child_raw = format!("{}\\foo.txt", jail_raw);

    let jail = soft_canonicalize(jail_raw).expect("canonicalize UNC jail");
    let child = soft_canonicalize(child_raw).expect("canonicalize UNC child");

    assert!(
        child.starts_with(&jail),
        "UNC child must start with UNC jail: child={:?}, jail={:?}",
        child,
        jail
    );
}

#[cfg(windows)]
#[test]
fn test_windows_raw_vs_canonicalized_starts_with_is_false() {
    // Documented behavior: mixing raw jail with canonicalized child should not pass starts_with
    let jail_raw = PathBuf::from(r"C:\NonExistent\Path\That\Does\Not\Exist");
    let child = soft_canonicalize(jail_raw.join("foo.txt")).expect("canonicalize child");

    // Compare against the raw (non-canonical) jail; should be false
    assert!(
        !child.starts_with(&jail_raw),
        "Raw jail must not be used for starts_with against canonicalized child"
    );
}

#[cfg(windows)]
#[test]
fn test_windows_relative_path_becomes_absolute_with_extended_prefix() {
    use std::env;
    let rel = r".\non\existent\file.txt";
    let abs = soft_canonicalize(rel).expect("canonicalize relative");
    assert!(abs.is_absolute());

    let cwd = soft_canonicalize(env::current_dir().unwrap()).expect("canonicalize cwd");
    assert!(
        abs.starts_with(&cwd),
        "Canonicalized relative path should start with canonicalized cwd: abs={:?}, cwd={:?}",
        abs,
        cwd
    );
}

#[cfg(windows)]
#[test]
fn test_windows_nonexistent_shortname_component_preserved() {
    // Non-existent 8.3-like component should be preserved (no expansion attempt)
    let p = r"C:\NonExistent\PROGRA~1\foo.txt";
    let got = soft_canonicalize(p).expect("canonicalize with shortname component");
    assert!(
        got.ends_with(PathBuf::from(r"PROGRA~1\foo.txt")),
        "Expected to preserve shortname component in non-existent path: {:?}",
        got
    );
}

#[cfg(unix)]
#[test]
fn test_unix_specific_paths() -> std::io::Result<()> {
    // Test Unix-specific path formats to validate cross-platform claims

    // Test absolute Unix paths
    let unix_path = "/tmp/non/existing/file.txt";
    let result = soft_canonicalize(unix_path)?;
    assert!(result.is_absolute());
    assert!(result.starts_with("/"));
    assert!(result.to_string_lossy().contains("file.txt"));

    // Test paths with multiple slashes - verify they get normalized
    let multi_slash = "/tmp//non///existing/file.txt";
    let result = soft_canonicalize(multi_slash)?;
    assert!(result.is_absolute());
    assert!(result.to_string_lossy().contains("file.txt"));

    // Compare with std::fs::canonicalize behavior on an existing path
    // to ensure our normalization is consistent
    let temp_dir = tempdir()?;
    let existing_with_slashes = format!("{}//subdir", temp_dir.path().display());
    fs::create_dir_all(temp_dir.path().join("subdir"))?;

    if let (Ok(our_result), Ok(std_result)) = (
        soft_canonicalize(existing_with_slashes),
        fs::canonicalize(temp_dir.path().join("subdir")),
    ) {
        assert_eq!(
            our_result, std_result,
            "Our path normalization should match std::fs::canonicalize"
        );
    }

    Ok(())
}
