//! # soft-canonicalize
//!
//! A pure Rust library for path canonicalization that works with non-existing paths.
//!
//! Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths
//! even when components don't exist on the filesystem. This enables accurate path
//! comparison, resolution of future file locations, and preprocessing paths before
//! file creation.
//!
//! **Comprehensive test suite with 100 tests ensuring 100% behavioral compatibility
//! with std::fs::canonicalize for existing paths.**
//!
//! Inspired by Python's `pathlib.Path.resolve(strict=False)` behavior, introduced in Python 3.6+.
//!
//! ## What is Path Canonicalization?
//!
//! Path canonicalization converts paths to their canonical (standard) form, enabling
//! accurate comparison and ensuring two different path representations that point to
//! the same location are recognized as equivalent. This is essential for:
//!
//! - **Path Comparison**: Determining if two paths refer to the same file or directory
//! - **Deduplication**: Avoiding duplicate operations on the same file accessed via different paths
//! - **Build Systems**: Resolving output paths and dependencies accurately
//! - **Future Path Planning**: Computing paths for files that will be created later
//! - **Security Applications**: Preventing path traversal attacks and ensuring paths stay within intended boundaries
//!
//! The "soft" aspect means we can canonicalize paths even when the target doesn't exist yet -
//! extending traditional canonicalization to work with planned or future file locations.
//!
//! ## Features
//!
//! - **🚀 Works with non-existing paths**: Canonicalizes paths that don't exist yet
//! - **🌍 Cross-platform**: Windows, macOS, and Linux support
//! - **⚡ Zero dependencies**: Only uses std library
//! - **🔒 Robust path handling**: Proper `..` and symlink resolution
//!
//! ## Example
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//! use std::path::PathBuf;
//!
//! # fn example() -> std::io::Result<()> {
//! # std::env::set_current_dir("/home/user/myproject")?;
//! // Starting from working directory: /home/user/myproject
//!
//! // Input: "data/config.json" (relative path to non-existing file)
//! // Output: absolute canonical path (file doesn't need to exist!)
//! let result = soft_canonicalize("data/config.json")?;
//! assert_eq!(result, PathBuf::from("/home/user/myproject/data/config.json"));
//!
//! // Input: "src/../data/settings.toml" (path with .. traversal to non-existing file)  
//! // Output: .. resolved logically, no filesystem needed
//! let result = soft_canonicalize("src/../data/settings.toml")?;
//! assert_eq!(result, PathBuf::from("/home/user/myproject/data/settings.toml"));
//!
//! // Input: "src/../README.md" (existing file with .. traversal)
//! // Output: same as std::fs::canonicalize (resolves symlinks too)
//! # std::fs::create_dir_all("src")?;
//! # std::fs::File::create("README.md")?;
//! let result = soft_canonicalize("src/../README.md")?;
//! assert_eq!(result, PathBuf::from("/home/user/myproject/README.md"));
//! # Ok(())
//! # }
//! ```
//!
//! ## Security
//!
//! This library provides robust path handling features:
//!
//! - **Directory Traversal Prevention**: `..` components resolved before filesystem access
//! - **Symlink Resolution**: Existing symlinks properly resolved with cycle detection
//! - **Comprehensive Security Testing**: 25 dedicated security tests covering CVE protection, attack simulation, and vulnerability discovery
//! - **Cross-platform Normalization**: Handles platform-specific path quirks consistently
//!
//! ### Security Test Coverage
//!
//! - **White-box Security Audits**: 14 tests exploiting internal algorithm knowledge
//! - **Black-box Attack Simulation**: 18 tests treating the API as a black box
//! - **CVE Protection**: Tested against known vulnerabilities (CVE-2022-21658, etc.)
//! - **Attack Vectors**: Directory traversal, symlink escapes, race conditions, Unicode bypasses, NTFS ADS, filesystem limits
//!
//! Note: While this library can be used in security-critical applications, its primary
//! purpose is accurate path canonicalization and comparison. Security applications should
//! combine this with appropriate access controls and validation.
//!
//! ## Performance
//!
//! - **Time**: O(k) existing components (best: O(1), worst: O(n))
//! - **Space**: O(n) component storage
//! - **Filesystem Access**: Minimal - only existing portions are accessed
//! - **Comprehensive Testing**: 100 tests including security audits, Python-inspired edge cases and cross-platform validation
//! - **100% Behavioral Compatibility**: Passes all std::fs::canonicalize tests for existing paths
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
//! This approach provides the robustness benefits of full canonicalization while
//! supporting paths that don't exist yet.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
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
    visited: &mut HashSet<Rc<PathBuf>>,
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
                let test_path_rc = Rc::new(test_path.clone());
                // Check for symlink cycle
                if visited.contains(&test_path_rc) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Too many levels of symbolic links",
                    ));
                }

                match fs::read_link(&test_path) {
                    Ok(target) => {
                        // Add this symlink to visited set
                        visited.insert(test_path_rc.clone());

                        // Resolve the target path
                        let resolved_target = if target.is_absolute() {
                            target
                        } else {
                            current_path.join(target)
                        };

                        // Append remaining components to the target
                        let mut full_target = resolved_target;
                        for remaining in resolved_components.iter().skip(i + 1) {
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
                        visited.remove(&test_path_rc);

                        return Ok((symlink_prefix, symlink_suffix));
                    }
                    Err(_) => {
                        // Broken symlink - we still need to resolve it lexically
                        // Continue processing as if it doesn't exist, but we'll handle the
                        // symlink target resolution in the calling function
                        remaining_components =
                            resolved_components.iter().skip(i).cloned().collect();
                        break;
                    }
                }
            } else {
                // Regular file/directory that exists
                current_path = test_path;
                remaining_components = resolved_components.iter().skip(i + 1).cloned().collect();
            }
        } else {
            // Found the boundary - everything from this component onwards doesn't exist
            remaining_components = resolved_components.iter().skip(i).cloned().collect();
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
    visited: &mut HashSet<Rc<PathBuf>>,
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

    // Fast path: if absolute path exists entirely and has no dot components, use std::fs::canonicalize
    if path.is_absolute()
        && path.exists()
        && !path.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return fs::canonicalize(path);
    }

    // Explicitly check for null bytes in the path
    // Use direct byte inspection to avoid string allocation and ensure accuracy
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains null byte",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        if path.as_os_str().encode_wide().any(|c| c == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains null byte",
            ));
        }
    }

    // Special handling for broken symlinks
    if path.is_symlink() {
        let path_rc = Rc::new(path.to_path_buf());
        // Check for symlink cycle first
        if visited.contains(&path_rc) {
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
                    // For relative symlink targets, resolve relative to the symlink's parent directory
                    let parent = path.parent().unwrap_or_else(|| {
                        // If no parent, use the root directory as fallback
                        #[cfg(windows)]
                        {
                            Path::new("C:\\")
                        }
                        #[cfg(not(windows))]
                        {
                            Path::new("/")
                        }
                    });
                    parent.join(target)
                };

                // Add this symlink to visited set before recursing
                visited.insert(path_rc.clone());

                // Recursively canonicalize the target (which may not exist)
                let result =
                    soft_canonicalize_internal(&resolved_target, visited, symlink_depth + 1);

                // Remove from visited set after recursion
                visited.remove(&path_rc);

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
/// This provides the robustness benefits of canonicalization (symlink resolution,
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
///
/// Note: While this function provides robust path handling, security-critical applications
/// should combine it with appropriate access controls and validation.
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
/// - **Time Complexity**: O(k) where k is the number of existing path components (k ≤ n)
///   - **Best case**: O(1) when first component doesn't exist  
///   - **Average case**: O(k) where k is typically much smaller than total components
///   - **Worst case**: O(n) when entire path exists
/// - **Space Complexity**: O(n) for component storage during processing
/// - **Filesystem Access**: Minimal - only existing portions require filesystem calls
///
/// **Comparison with alternatives**: Provides unique combination of non-existing path
/// support with full symlink resolution and robust path handling that other libraries
/// may not offer.
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
    mod cve_tests;
    mod edge_case_robustness;
    mod edge_cases;
    mod optimization;
    mod path_traversal;
    mod platform_specific;
    mod python_inspired_tests;
    mod python_lessons;
    mod security;
    mod security_audit;
    mod security_hardening;
    mod std_behavior;
    mod symlink_depth;
    mod symlink_dotdot_resolution_order;
}
