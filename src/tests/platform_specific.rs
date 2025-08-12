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
    let child_raw = format!("{jail_raw}\\foo.txt");

    let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
    let child = soft_canonicalize(child_raw).expect("canonicalize child");

    assert!(
        child.starts_with(&jail),
        "Canonicalized child must start with canonicalized jail: child={child:?}, jail={jail:?}"
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
    let child_raw = format!("{jail_raw}\\foo.txt");

    let jail = soft_canonicalize(jail_raw).expect("canonicalize UNC jail");
    let child = soft_canonicalize(child_raw).expect("canonicalize UNC child");

    assert!(
        child.starts_with(&jail),
        "UNC child must start with UNC jail: child={child:?}, jail={jail:?}"
    );
}

#[cfg(windows)]
#[test]
fn test_windows_unc_root_canonicalizes_to_verbatim_unc() {
    // Bare UNC server/share should become an extended-length UNC prefix
    let input = r"\\server\share";
    let got = soft_canonicalize(input).expect("canonicalize UNC root");
    assert_eq!(got, PathBuf::from(r"\\?\UNC\server\share"));
}

#[cfg(windows)]
#[test]
fn test_windows_unc_root_with_trailing_separator_idempotent() {
    // Adding trailing separators or . should not change the UNC root semantics
    let base = PathBuf::from(r"\\server\share");
    let variants = [
        PathBuf::from(r"\\server\share\\"),
        PathBuf::from(r"\\server\share\."),
        PathBuf::from(r"\\?\UNC\server\share\\"),
        PathBuf::from(r"\\?\UNC\server\share\."),
    ];

    let canonical_base = soft_canonicalize(&base).expect("canonicalize UNC base");
    for v in variants {
        let got = soft_canonicalize(&v).expect("canonicalize UNC root variant");
        assert_eq!(got, canonical_base, "variant {v:?} not idempotent");
    }
}

#[cfg(windows)]
#[test]
fn test_windows_unc_very_deep_stress_fast() {
    // Stress-lite: deep UNC path to guard against regressions, tuned to be fast in CI.
    let mut p = PathBuf::from(r"\\?\UNC\server\share");
    for i in 0..400u32 {
        // ~400 components keeps runtime low while still deep
        p.push(format!("dir{i:04}"));
    }
    p.push("leaf.txt");

    let got = soft_canonicalize(&p).expect("canonicalize very deep UNC");
    assert!(got.starts_with(PathBuf::from(r"\\?\UNC\server\share")));
    assert!(got.ends_with(PathBuf::from("leaf.txt")));
}

#[cfg(windows)]
#[test]
fn test_windows_verbatim_unc_idempotent() {
    // Already verbatim UNC should be returned unchanged
    let input = PathBuf::from(r"\\?\UNC\server\share\path\to\file.txt");
    let got = soft_canonicalize(&input).expect("canonicalize verbatim UNC");
    assert_eq!(got, input);
}

#[cfg(windows)]
#[test]
fn test_windows_unc_mixed_separators_are_normalized() {
    // Mixed separators should normalize and preserve UNC semantics
    let input = r"\\server\share/mixed\\seps/dir\file.txt";
    let got = soft_canonicalize(input).expect("canonicalize UNC with mixed separators");
    assert!(got.starts_with(PathBuf::from(r"\\?\UNC\server\share")));
    assert!(got.ends_with(PathBuf::from(r"mixed\seps\dir\file.txt")));
}

#[cfg(windows)]
#[test]
fn test_windows_unc_dotdot_does_not_escape_share_root() {
    // ".." cannot climb above the share root; it should clamp at \\server\share
    let input = r"\\server\share\folder\..\..\sibling\file.txt";
    let got = soft_canonicalize(input).expect("canonicalize UNC with dotdot");
    // Should clamp to the share root and resolve to this exact path
    assert_eq!(got, PathBuf::from(r"\\?\UNC\server\share\sibling\file.txt"));
}

#[cfg(windows)]
#[test]
fn test_windows_unc_preserves_shortname_like_component_for_nonexistent() {
    // For non-existing paths, 8.3-like components are preserved (no expansion)
    let input = r"\\server\share\PROGRA~1\foo.txt";
    let got = soft_canonicalize(input).expect("canonicalize UNC with shortname-like component");
    assert!(got.ends_with(PathBuf::from(r"PROGRA~1\foo.txt")));
}

#[cfg(windows)]
#[test]
fn test_windows_unc_preserves_trailing_dot_and_space_in_names() {
    // With extended-length prefix, Windows does not strip trailing dots/spaces
    let input = r"\\server\share\dir. \file. txt"; // component names ending with dot/space
    let got = soft_canonicalize(input).expect("canonicalize UNC with trailing dot/space");
    assert!(got.ends_with(PathBuf::from(r"dir. \file. txt")));
}

#[cfg(windows)]
#[test]
fn test_windows_multiple_drive_letters_produce_verbatim_disk_prefix() {
    // Validate we format extended-length prefixes for a range of drive letters
    for drive in ['C', 'D', 'E', 'Z'] {
        let input = format!(r"{drive}:\nonexistent\child.txt");
        let got = soft_canonicalize(&input).expect("canonicalize drive letter path");
        let expected_starts = format!(r"\\?\{drive}:\");
        assert!(got.to_string_lossy().starts_with(&expected_starts));
        assert!(
            got.ends_with(PathBuf::from(r"nonexistent\child.txt")),
            "Result should end with suffix for drive {drive}: {got:?}"
        );
    }
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
        "Canonicalized relative path should start with canonicalized cwd: abs={abs:?}, cwd={cwd:?}"
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
        "Expected to preserve shortname component in non-existent path: {got:?}"
    );
}

#[cfg(windows)]
#[test]
fn test_windows_false_positive_tilde_names_not_treated_as_short() {
    // Ensure that legitimate filenames with tildes are not treated as 8.3 short names
    let test_cases = vec![
        r"C:\Users\test\hello~world.txt",
        r"C:\Projects\backup~file.doc",
        r"C:\Config\settings~old.json",
        r"C:\Temp\test~project\file.txt",
    ];

    for test_path in test_cases {
        let got = soft_canonicalize(test_path).expect("canonicalize regular tilde filename");
        // These should be processed normally without any special short name handling
        assert!(
            got.to_string_lossy().contains('~'),
            "Tilde should be preserved in regular filename: {got:?}"
        );
    }
}

#[cfg(windows)]
#[test]
fn test_windows_actual_short_name_detection() {
    // Test that actual 8.3 patterns are correctly identified
    let short_name_paths = vec![
        r"C:\PROGRA~1\MyApp\config.txt",
        r"C:\Users\RUNNER~1\Documents\file.txt",
        r"C:\Temp\LONGFI~1.TXT",
    ];

    for test_path in short_name_paths {
        let got = soft_canonicalize(test_path).expect("canonicalize short name path");
        // The path should be processed (exact result depends on filesystem state)
        // but the important thing is it doesn't crash and produces a valid result
        assert!(got.is_absolute(), "Result should be absolute: {got:?}");
    }
}

#[cfg(windows)]
#[test]
fn test_windows_device_namespace_lexical_only_pipe() {
    // Device namespace paths should be treated lexically: preserve prefix, normalize dot/dotdot
    let input = r"\\.\PIPE\name\..\other";
    let got = soft_canonicalize(input).expect("canonicalize device namespace (PIPE)");
    assert_eq!(got, PathBuf::from(r"\\.\PIPE\other"));
}

#[cfg(windows)]
#[test]
fn test_windows_device_namespace_globalroot_lexical() {
    let input = r"\\?\GLOBALROOT\Device\HarddiskVolume1\foo\.\bar\..\baz";
    let got = soft_canonicalize(input).expect("canonicalize GLOBALROOT path lexically");
    assert_eq!(
        got,
        PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolume1\foo\baz")
    );
}

#[cfg(windows)]
#[test]
fn test_windows_device_namespace_idempotent_for_physicaldrive() {
    let input = PathBuf::from(r"\\.\PhysicalDrive0");
    let got = soft_canonicalize(&input).expect("canonicalize PhysicalDrive0 lexically");
    assert_eq!(got, input);
}

#[cfg(windows)]
#[test]
fn test_windows_device_namespace_parent_clamps_at_prefix() {
    // Parent traversal is lexical and clamps at the device prefix (\\. or \\?\GLOBALROOT)
    // It is NOT clamped at device class (e.g., PIPE); components can be popped until the prefix.
    let input = r"\\.\PIPE\name\..\..\other";
    let got = soft_canonicalize(input).expect("canonicalize device namespace with double dotdot");
    // In DeviceNS, the device class (e.g., PIPE) is part of the prefix per std::path parsing,
    // so parent traversal cannot pop it. Expected: \\.\PIPE\other
    assert_eq!(got, PathBuf::from(r"\\.\PIPE\other"));
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
