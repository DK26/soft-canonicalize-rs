//! Linux, macOS, and general Unix platform tests for soft_canonicalize
//!
//! Tests Unix path formats, Linux /proc namespace alias resolution, and
//! macOS /private/var symlink normalization.

#[cfg(unix)]
use crate::soft_canonicalize;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use tempfile::tempdir;

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

#[cfg(target_os = "linux")]
#[test]
fn test_linux_bin_alias_resolves_for_nonexisting_tail() -> std::io::Result<()> {
    // Many distros link /bin -> /usr/bin. Ensure our result matches canonicalize(base)+tail.
    let leaf = "softcanon_nonexist_linux_bin_1.txt";
    // If /bin is missing or inaccessible, treat as not applicable
    let Ok(base) = std::fs::canonicalize("/bin") else {
        return Ok(());
    };
    let got = soft_canonicalize(format!("/bin/{leaf}"))?;
    let expected = base.join(leaf);
    assert_eq!(got, expected);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn test_linux_var_run_alias_resolves_for_nonexisting_tail() -> std::io::Result<()> {
    // Many distros link /var/run -> /run. Ensure our result matches canonicalize(base)+tail.
    let leaf = "softcanon_nonexist_linux_varrun_1.pid";
    let Ok(base) = std::fs::canonicalize("/var/run") else {
        return Ok(());
    };
    let got = soft_canonicalize(format!("/var/run/{leaf}"))?;
    let expected = base.join(leaf);
    assert_eq!(got, expected);
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_tempdir_nonexisting_tail_uses_private_var() -> std::io::Result<()> {
    // On macOS, ensure that when appending a non-existing tail to a TempDir base (often under /var),
    // the result normalizes to the canonical /private/var anchor.
    let td = tempfile::tempdir()?;
    let base = td.path();
    let child = base.join("softcanon_nonexist_1.txt");

    let got = soft_canonicalize(&child)?;
    let expected = std::fs::canonicalize(base)?.join("softcanon_nonexist_1.txt");
    assert_eq!(got, expected);
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_var_tmp_nonexisting_tail_normalizes_to_private() -> std::io::Result<()> {
    // /var/tmp exists but is an alias; verify we stabilize to /private/var/tmp for non-existing tails
    let leaf = "softcanon_ci_unique_abcd1234.txt"; // extremely unlikely to exist
    let input = format!("/var/tmp/{leaf}");

    let got = soft_canonicalize(&input)?;
    let expected = std::fs::canonicalize("/var/tmp")?.join(leaf);
    assert_eq!(got, expected);
    Ok(())
}
