//! # soft-canonicalize
//!
//! A pure Rust library for path canonicalization that works with non-existing paths.
//!
//! Unlike `std::fs::canonicalize()`, this library can resolve and normalize paths
//! even when some or all of the path components don't exist on the filesystem.
//! This is useful for security validation, path preprocessing, and working with
//! paths before creating files.
//!
//! ## Features
//!
//! - **Works with non-existing paths**: Canonicalizes paths even when they don't exist
//! - **Cross-platform**: Supports Windows, macOS, and Linux
//! - **Zero dependencies**: No external dependencies beyond std
//! - **Security focused**: Proper handling of `..` components and symlinks
//! - **Pure algorithm**: No filesystem modification during canonicalization
//!
//! ## Example
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//! use std::path::Path;
//!
//! # fn example() -> std::io::Result<()> {
//! // Works with existing paths (same as std::fs::canonicalize)
//! let existing = soft_canonicalize(&std::env::temp_dir())?;
//!
//! // Also works with non-existing paths
//! let non_existing = soft_canonicalize(
//!     &std::env::temp_dir().join("some/deep/non/existing/path.txt")
//! )?;
//!
//! // Resolves .. components logically
//! let traversal = soft_canonicalize(
//!     Path::new("some/path/../other/file.txt")
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security
//!
//! This library is designed with security in mind:
//!
//! - Properly handles directory traversal (`..`) components
//! - Resolves symlinks when they exist
//! - Normalizes path separators and case (on case-insensitive filesystems)
//! - Does not create or modify filesystem entries during canonicalization
//!
//! ## Algorithm
//!
//! The soft canonicalization algorithm works by:
//!
//! 1. Converting relative paths to absolute paths
//! 2. Logically processing `..` components to resolve traversals
//! 3. Finding the longest existing ancestor directory
//! 4. Canonicalizing the existing portion using `std::fs::canonicalize`
//! 5. Appending the non-existing components to the canonicalized base
//!
//! This approach provides the security benefits of full canonicalization while
//! supporting paths that don't exist yet.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{fs, io};

/// Internal helper function that performs soft canonicalization with symlink cycle detection.
///
/// This function tracks visited symlinks to detect and prevent infinite recursion cycles.
fn soft_canonicalize_internal(path: &Path, visited: &mut HashSet<PathBuf>) -> io::Result<PathBuf> {
    // Handle empty path like std::fs::canonicalize - should fail
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "The system cannot find the path specified.",
        ));
    }

    // Convert to absolute path if relative
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    // Step 1: Lexical resolution (Python-style) - process .. and . components logically
    let mut resolved_components = Vec::new();
    let mut result = PathBuf::new();

    // First, collect all the root components (Prefix, RootDir)
    for component in absolute_path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                result.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                resolved_components.push(name);
            }
            std::path::Component::ParentDir => {
                // Handle .. by removing the last component if possible
                if !resolved_components.is_empty() {
                    resolved_components.pop();
                }
                // If at root level, .. is ignored (cannot go above root)
            }
            std::path::Component::CurDir => {
                // Ignore . components
            }
        }
    }

    // Step 2: Incremental symlink resolution - build path component by component
    for component in resolved_components {
        result.push(component);

        // Check if this path is a symlink (even if target doesn't exist)
        if result.is_symlink() {
            // Check for symlink cycle by seeing if we've already visited this symlink
            if visited.contains(&result) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Too many levels of symbolic links",
                ));
            }

            // Try to read the symlink target
            match fs::read_link(&result) {
                Ok(target) => {
                    // Add this symlink to the visited set to detect cycles
                    let symlink_path = result.clone();
                    visited.insert(symlink_path.clone());

                    // Remove the symlink component we just added
                    result.pop();

                    // Resolve the target path
                    let resolved_target = if target.is_absolute() {
                        target
                    } else {
                        result.join(target)
                    };

                    // Recursively canonicalize the target with cycle detection
                    match soft_canonicalize_internal(&resolved_target, visited) {
                        Ok(canonical_target) => {
                            result = canonical_target;
                        }
                        Err(e) => {
                            // If we get an error (like cycle detection), propagate it
                            return Err(e);
                        }
                    }

                    // Remove from visited set when we're done with this symlink
                    visited.remove(&symlink_path);
                }
                Err(_) => {
                    // If we can't read the symlink, treat it as a regular path
                    // and continue
                }
            }
        } else if result.exists() {
            // For non-symlink existing paths, use standard canonicalization
            if let Ok(canonical) = fs::canonicalize(&result) {
                result = canonical;
            }
            // If canonicalization fails, continue with the current path
            // This handles cases where we have permission to see the path exists
            // but not to canonicalize it
        }
    }

    Ok(result)
}

/// Performs "soft" canonicalization on a path.
///
/// Unlike `std::fs::canonicalize()`, this function works with non-existent paths by:
/// 1. Finding the deepest existing ancestor directory
/// 2. Canonicalizing that existing part (resolving symlinks, normalizing case, etc.)
/// 3. Appending the non-existing path components to the canonicalized base
///
/// This provides the security benefits of canonicalization (symlink resolution,
/// path normalization) without requiring the entire path to exist.
///
/// # Algorithm Details
///
/// The function performs the following steps:
///
/// 1. **Absolute Path Conversion**: Converts relative paths to absolute paths
/// 2. **Logical Processing**: Processes `..` components mathematically without filesystem access
/// 3. **Symlink Cycle Detection**: Tracks visited symlinks to prevent infinite recursion
/// 4. **Existing Prefix Discovery**: Finds the longest existing ancestor
/// 5. **Canonicalization**: Uses `std::fs::canonicalize` on the existing portion
/// 6. **Reconstruction**: Appends non-existing components to the canonical base
///
/// # Security Considerations
///
/// - **Directory Traversal**: `..` components are resolved logically before filesystem access
/// - **Symlink Resolution**: Existing symlinks are resolved with proper cycle detection
/// - **No Side Effects**: No temporary files or directories are created during the process
///
/// # Cross-Platform Support
///
/// This function works correctly on:
/// - **Windows**: Handles drive letters, UNC paths, and case normalization
/// - **Unix-like systems**: Handles absolute paths starting with `/`
/// - **All platforms**: Proper handling of path separators and components
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use soft_canonicalize::soft_canonicalize;
/// use std::path::Path;
///
/// # fn example() -> std::io::Result<()> {
/// // Works with existing paths (same as std::fs::canonicalize)
/// let existing = soft_canonicalize(&std::env::temp_dir())?;
/// println!("Existing path: {:?}", existing);
///
/// // Also works with non-existing paths
/// let non_existing = soft_canonicalize(
///     &std::env::temp_dir().join("some/deep/non/existing/path.txt")
/// )?;
/// println!("Non-existing path: {:?}", non_existing);
/// # Ok(())
/// # }
/// ```
///
/// ## Directory Traversal Handling
///
/// ```rust
/// use soft_canonicalize::soft_canonicalize;
/// use std::path::Path;
///
/// # fn example() -> std::io::Result<()> {
/// // Resolves .. components logically
/// let traversal = soft_canonicalize(
///     Path::new("some/path/../other/file.txt")
/// )?;
/// // Result: /current/working/dir/some/other/file.txt
///
/// // Works with complex traversal patterns
/// let complex = soft_canonicalize(
///     Path::new("deep/nested/path/../../final/file.txt")
/// )?;
/// // Result: /current/working/dir/deep/final/file.txt
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an `io::Error` in the following cases:
/// - **Permission Denied**: When the current directory cannot be accessed (for relative paths)
/// - **Invalid Path**: When the path contains invalid Unicode or system-specific issues
/// - **Canonicalization Failure**: When the existing portion cannot be canonicalized
/// - **Symlink Cycles**: When circular symlink references are detected
///
/// Note: This function does NOT return an error for non-existent paths, as supporting
/// such paths is the primary purpose of soft canonicalization.
///
/// # Performance
///
/// - **Time Complexity**: O(n) where n is the number of path components
/// - **Space Complexity**: O(n) for component storage during processing
/// - **Filesystem Access**: Minimal - only to find existing ancestors and canonicalize them
///
pub fn soft_canonicalize(path: &Path) -> io::Result<PathBuf> {
    let mut visited = HashSet::new();
    soft_canonicalize_internal(path, &mut visited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_temp_dir() -> io::Result<PathBuf> {
        let temp_base = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let temp_dir = temp_base.join(format!(
            "soft_canonicalize_test_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&temp_dir)?;
        Ok(temp_dir)
    }

    fn cleanup_temp_dir(path: &Path) {
        if path.exists() {
            let _ = fs::remove_dir_all(path);
        }
    }

    #[test]
    fn test_existing_path() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Test with existing directory
        let result = soft_canonicalize(&temp_dir)?;
        let expected = fs::canonicalize(&temp_dir)?;

        assert_eq!(result, expected);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_non_existing_path() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;
        let non_existing = temp_dir.join("non_existing_file.txt");

        let result = soft_canonicalize(&non_existing)?;
        let expected = fs::canonicalize(&temp_dir)?.join("non_existing_file.txt");

        assert_eq!(result, expected);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_deeply_non_existing_path() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;
        let deep_path = temp_dir.join("a/b/c/d/e/file.txt");

        let result = soft_canonicalize(&deep_path)?;
        let expected = fs::canonicalize(&temp_dir)?.join("a/b/c/d/e/file.txt");

        assert_eq!(result, expected);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_relative_path() -> io::Result<()> {
        let result = soft_canonicalize(Path::new("non/existing/relative/path.txt"))?;

        // Check that the result is absolute and starts with current directory
        assert!(result.is_absolute());
        assert!(result.ends_with("path.txt"));

        // The result should contain our relative path components
        let result_str = result.to_string_lossy();
        assert!(result_str.contains("non"));
        assert!(result_str.contains("existing"));
        assert!(result_str.contains("relative"));

        Ok(())
    }

    #[test]
    fn test_parent_directory_traversal() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Create: temp_dir/level1/level2/
        let level1 = temp_dir.join("level1");
        let level2 = level1.join("level2");
        fs::create_dir_all(&level2)?;

        // Test path: temp_dir/level1/level2/subdir/../../../target.txt
        // This should resolve to: temp_dir/target.txt
        let test_path = level2
            .join("subdir")
            .join("..")
            .join("..")
            .join("..")
            .join("target.txt");

        let result = soft_canonicalize(&test_path)?;
        let expected = fs::canonicalize(&temp_dir)?.join("target.txt");

        assert_eq!(result, expected);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_mixed_existing_and_nonexisting_with_traversal() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Create: temp_dir/existing/
        let existing_dir = temp_dir.join("existing");
        fs::create_dir(&existing_dir)?;

        // Test: temp_dir/existing/nonexisting/../sibling.txt
        // Should resolve to: temp_dir/existing/sibling.txt
        let test_path = existing_dir
            .join("nonexisting")
            .join("..")
            .join("sibling.txt");

        let result = soft_canonicalize(&test_path)?;
        let expected = fs::canonicalize(&existing_dir)?.join("sibling.txt");

        assert_eq!(result, expected);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_traversal_beyond_root() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Test path with more .. than depth (should stop at root)
        let test_path = temp_dir.join("../../../../../../../../../root_file.txt");

        let result = soft_canonicalize(&test_path)?;

        // Should not escape beyond the filesystem root
        assert!(result.is_absolute());
        assert!(!result.starts_with(&temp_dir));

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }
}
