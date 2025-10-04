/// Tests to verify strip_root_prefix handles all Windows path types correctly
use std::path::{Component, Path, PathBuf};

// Inline the strip_root_prefix logic for testing
fn strip_root_prefix(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();

    for comp in path.components() {
        match comp {
            // Skip all prefix and root components
            Component::Prefix(_) | Component::RootDir => continue,
            // Keep all normal components
            _ => result.push(comp),
        }
    }

    // If result is empty, return current directory marker
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

#[test]
fn test_strip_disk_prefix() {
    // C:\Windows\System32 -> Windows\System32
    let path = Path::new(r"C:\Windows\System32");
    let stripped = strip_root_prefix(path);

    assert_eq!(stripped, Path::new(r"Windows\System32"));
}

#[test]
fn test_strip_unc_path() {
    // \\server\share\path\file.txt -> path\file.txt
    let path = Path::new(r"\\server\share\path\file.txt");
    let stripped = strip_root_prefix(path);

    assert_eq!(stripped, Path::new(r"path\file.txt"));
}

#[test]
fn test_strip_extended_length_path() {
    // \\?\C:\Windows\System32 -> Windows\System32
    let path = Path::new(r"\\?\C:\Windows\System32");
    let stripped = strip_root_prefix(path);

    assert_eq!(stripped, Path::new(r"Windows\System32"));
}

#[test]
fn test_strip_extended_unc_path() {
    // \\?\UNC\server\share\path -> path
    let path = Path::new(r"\\?\UNC\server\share\path\file.txt");
    let stripped = strip_root_prefix(path);

    assert_eq!(stripped, Path::new(r"path\file.txt"));
}

#[test]
fn test_strip_root_only_returns_dot() {
    // C:\ -> .
    let path = Path::new(r"C:\");
    let stripped = strip_root_prefix(path);

    assert_eq!(stripped, Path::new("."));
}

#[test]
fn test_relative_path_unchanged() {
    // relative\path -> relative\path (but normalized through components)
    let path = Path::new(r"relative\path\file.txt");
    let stripped = strip_root_prefix(path);

    // Relative paths have no Prefix or RootDir components, so nothing is stripped
    assert_eq!(stripped, Path::new(r"relative\path\file.txt"));
}

#[test]
fn test_drive_relative_path() {
    // C:file.txt (drive-relative, rare but valid)
    // This has a Prefix but no RootDir
    let path = Path::new(r"C:file.txt");
    let stripped = strip_root_prefix(path);

    // Should strip the C: prefix
    assert_eq!(stripped, Path::new(r"file.txt"));
}

#[test]
fn test_verbatim_path() {
    // \\?\C:\path is an extended-length path (verbatim)
    // This is the most common form that appears in real Windows usage
    let path = Path::new(r"\\?\C:\Windows\System32\file.dll");
    let stripped = strip_root_prefix(path);

    // Should strip the \\?\C:\ prefix
    assert_eq!(stripped, Path::new(r"Windows\System32\file.dll"));
}
