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
//! // Works with string paths (like std::fs::canonicalize)
//! let from_str = soft_canonicalize("some/path/file.txt")?;
//!
//! // Works with existing paths (same as std::fs::canonicalize)
//! let existing = soft_canonicalize(&std::env::temp_dir())?;
//!
//! // Also works with non-existing paths
//! let non_existing = soft_canonicalize(
//!     std::env::temp_dir().join("some/deep/non/existing/path.txt")
//! )?;
//!
//! // Resolves .. components logically
//! let traversal = soft_canonicalize("some/path/../other/file.txt")?;
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

/// Maximum number of symlinks to follow before giving up.
/// This matches the behavior of std::fs::canonicalize and OS limits:
/// - Linux: ELOOP limit is typically 40
/// - Windows: Similar limit around 63
/// - Other Unix systems: Usually 32-40
pub const MAX_SYMLINK_DEPTH: usize = if cfg!(target_os = "windows") { 63 } else { 40 };

/// Internal helper function that finds the boundary between existing and non-existing path components.
///
/// Returns (existing_prefix, non_existing_suffix) where existing_prefix is the longest
/// existing directory path, and non_existing_suffix contains the remaining components.
/// This version properly handles symlinks by processing components incrementally.
fn find_existing_boundary_with_symlinks(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    symlink_depth: usize,
) -> io::Result<(PathBuf, Vec<std::ffi::OsString>)> {
    // Check symlink depth limit to match std::fs::canonicalize behavior
    if symlink_depth > MAX_SYMLINK_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Too many levels of symbolic links",
        ));
    }

    // Convert to absolute path first
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    // First, do lexical resolution of .. and . components
    let mut resolved_components = Vec::new();
    let mut result = PathBuf::new();

    // Collect root components (Prefix, RootDir)
    for component in absolute_path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                result.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                resolved_components.push(name.to_os_string());
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

    // Now build path incrementally, handling symlinks as we go
    let mut current_path = result;
    let mut remaining_components = resolved_components.clone();

    for (i, component) in resolved_components.iter().enumerate() {
        let test_path = current_path.join(component);

        if test_path.exists() {
            // Check if this is a symlink
            if test_path.is_symlink() {
                // Check for symlink cycle
                if visited.contains(&test_path) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Too many levels of symbolic links",
                    ));
                }

                match fs::read_link(&test_path) {
                    Ok(target) => {
                        // Add this symlink to visited set
                        visited.insert(test_path.clone());

                        // Resolve the target path
                        let resolved_target = if target.is_absolute() {
                            target
                        } else {
                            current_path.join(target)
                        };

                        // Append remaining components to the target
                        let mut full_target = resolved_target;
                        for remaining in &resolved_components[i + 1..] {
                            full_target.push(remaining);
                        }

                        // Recursively process the target
                        let (symlink_prefix, symlink_suffix) =
                            find_existing_boundary_with_symlinks(
                                &full_target,
                                visited,
                                symlink_depth + 1,
                            )?;

                        // Remove from visited set
                        visited.remove(&test_path);

                        return Ok((symlink_prefix, symlink_suffix));
                    }
                    Err(_) => {
                        // Broken symlink - we still need to resolve it lexically
                        // Continue processing as if it doesn't exist, but we'll handle the
                        // symlink target resolution in the calling function
                        remaining_components = resolved_components[i..].to_vec();
                        break;
                    }
                }
            } else {
                // Regular file/directory that exists
                current_path = test_path;
                remaining_components = resolved_components[i + 1..].to_vec();
            }
        } else {
            // Found the boundary - everything from this component onwards doesn't exist
            remaining_components = resolved_components[i..].to_vec();
            break;
        }
    }

    Ok((current_path, remaining_components))
}

/// Internal helper function that performs soft canonicalization.
///
/// This optimized version finds the existing/non-existing boundary and uses std::fs::canonicalize
/// only on the existing portion for maximum efficiency while maintaining security and symlink handling.
fn soft_canonicalize_internal(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    symlink_depth: usize,
) -> io::Result<PathBuf> {
    // Check symlink depth limit to match std::fs::canonicalize behavior
    if symlink_depth > MAX_SYMLINK_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Too many levels of symbolic links",
        ));
    }

    // Handle empty path like std::fs::canonicalize - should fail
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "The system cannot find the path specified.",
        ));
    }

    // Special handling for broken symlinks
    if path.is_symlink() {
        // Check for symlink cycle first
        if visited.contains(path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Too many levels of symbolic links",
            ));
        }

        // Check if we can canonicalize it (i.e., if the target exists)
        match fs::canonicalize(path) {
            Ok(canonical) => return Ok(canonical),
            Err(_) => {
                // It's a broken symlink - resolve it manually
                let target = fs::read_link(path)?;
                let resolved_target = if target.is_absolute() {
                    target
                } else {
                    path.parent().unwrap_or(Path::new("/")).join(target)
                };

                // Add this symlink to visited set before recursing
                visited.insert(path.to_path_buf());

                // Recursively canonicalize the target (which may not exist)
                let result =
                    soft_canonicalize_internal(&resolved_target, visited, symlink_depth + 1);

                // Remove from visited set after recursion
                visited.remove(path);

                return result;
            }
        }
    }

    // Find the boundary between existing and non-existing components
    let (existing_prefix, non_existing_suffix) =
        find_existing_boundary_with_symlinks(path, visited, symlink_depth)?;

    // Canonicalize the existing prefix (this handles all symlinks in the existing portion)
    let canonical_prefix = if existing_prefix.as_os_str().is_empty()
        || existing_prefix == Path::new("/")
        || existing_prefix.parent().is_none()
    {
        // Handle root paths - they're already canonical
        existing_prefix
    } else {
        // Use std::fs::canonicalize for existing paths - this is secure and handles all symlinks
        fs::canonicalize(&existing_prefix)?
    };

    // Append the non-existing components lexically (no symlinks possible in non-existing paths)
    let mut result = canonical_prefix;
    for component in non_existing_suffix {
        result.push(component);
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
/// use std::path::{Path, PathBuf};
///
/// # fn example() -> std::io::Result<()> {
/// // Works with &str (like std::fs::canonicalize)
/// let from_str = soft_canonicalize("some/path/file.txt")?;
///
/// // Works with &Path
/// let from_path = soft_canonicalize(Path::new("some/path/file.txt"))?;
///
/// // Works with &PathBuf
/// let path_buf = PathBuf::from("some/path/file.txt");
/// let from_pathbuf = soft_canonicalize(&path_buf)?;
///
/// // Works with existing paths (same as std::fs::canonicalize)
/// let existing = soft_canonicalize(&std::env::temp_dir())?;
/// println!("Existing path: {:?}", existing);
///
/// // Also works with non-existing paths
/// let non_existing = soft_canonicalize(
///     std::env::temp_dir().join("some/deep/non/existing/path.txt")
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
pub fn soft_canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();
    let mut visited = HashSet::new();
    soft_canonicalize_internal(path, &mut visited, 0)
}

#[cfg(test)]
mod tests {
    mod api_compatibility;
    mod basic_functionality;
    mod edge_cases;
    mod optimization;
    mod path_traversal;
    mod platform_specific;
    mod python_inspired_tests;
    mod python_lessons;
    mod security;
    mod std_behavior;
    mod symlink_depth;
}
