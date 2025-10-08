//! API compatibility tests for soft_canonicalize
//!
//! Tests that verify our API matches std::fs::canonicalize patterns exactly
//! and supports all the same input types.

use crate::soft_canonicalize;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_generic_path_parameter_str() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test with &str (like std::fs::canonicalize supports)
    let temp_str = temp_dir.path().to_string_lossy();
    let result = soft_canonicalize(temp_str.as_ref())?;
    let expected = fs::canonicalize(temp_dir.path())?;

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected, "Without dunce: exact match with std");
    }

    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected);
        }
    }
    Ok(())
}

#[test]
fn test_generic_path_parameter_string() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test with String (owned)
    let temp_string = temp_dir.path().to_string_lossy().to_string();
    let result = soft_canonicalize(temp_string)?;
    let expected = fs::canonicalize(temp_dir.path())?;

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected, "Without dunce: exact match with std");
    }

    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected);
        }
    }
    Ok(())
}

#[test]
fn test_generic_path_parameter_pathbuf() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test with PathBuf (like std::fs::canonicalize supports)
    let path_buf = temp_dir.path().to_path_buf();
    let result = soft_canonicalize(path_buf)?;
    let expected = fs::canonicalize(temp_dir.path())?;

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected, "Without dunce: exact match with std");
    }

    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected);
        }
    }
    Ok(())
}

#[test]
fn test_generic_path_parameter_pathbuf_ref() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test with &PathBuf (common usage pattern)
    let path_buf = temp_dir.path().to_path_buf();
    let result = soft_canonicalize(path_buf)?;
    let expected = fs::canonicalize(temp_dir.path())?;

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected, "Without dunce: exact match with std");
    }

    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected);
        }
    }
    Ok(())
}

#[test]
fn test_generic_path_parameter_path_ref() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test with &Path (original API still works)
    let path_ref = temp_dir.path();
    let result = soft_canonicalize(path_ref)?;
    let expected = fs::canonicalize(temp_dir.path())?;

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected, "Without dunce: exact match with std");
    }

    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected);
        }
    }
    Ok(())
}

#[test]
fn test_generic_path_parameter_str_non_existing() -> std::io::Result<()> {
    let temp_dir = tempdir()?;

    // Test string with non-existing path
    let non_existing_str = format!("{}/non/existing/file.txt", temp_dir.path().display());
    let result = soft_canonicalize(non_existing_str)?;
    let expected = fs::canonicalize(temp_dir.path())?.join("non/existing/file.txt");

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, expected, "Without dunce: exact match with std");
    }

    #[cfg(feature = "dunce")]
    {
        #[cfg(windows)]
        {
            let result_str = result.to_string_lossy();
            let expected_str = expected.to_string_lossy();
            assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
            assert!(expected_str.starts_with(r"\\?\"), "std returns UNC");
            // Verify path ends correctly
            assert!(result_str.ends_with(r"non\existing\file.txt"));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(result, expected);
        }
    }
    Ok(())
}
