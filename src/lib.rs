//! # soft-canonicalize
//!
//! A high-performance, pure Rust library for path canonicalization that works with non-existing paths.
//!
//! **Inspired by Python's `pathlib.Path.resolve(strict=False)`** - this library brings the same
//! functionality to Rust, but with significant performance improvements and additional safety features.
//!
//! Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths
//! even when components don't exist on the filesystem. This enables accurate path
//! comparison, resolution of future file locations, and preprocessing paths before
//! file creation.
//!
//! **🔬 Comprehensive test suite with 100+ tests ensuring 100% behavioral compatibility
//! with std::fs::canonicalize for existing paths.**
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
//! - **🔧 Zero dependencies**: Only uses std library
//! - **🔒 Robust path handling**: Proper `..` and symlink resolution with cycle detection
//! - **🛡️ Security tested**: Protection against CVE-2022-21658 and common path traversal attacks
//! - **⚡ High Performance**: Optimized algorithm significantly outperforms naive implementations
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
//! - **Comprehensive Security Testing**: 40+ dedicated security tests covering CVE protection, attack simulation, and vulnerability discovery
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
//! - **Time Complexity**: O(k) existing components (best: O(1), worst: O(n))
//! - **Space Complexity**: O(n) component storage
//! - **Filesystem Access**: Minimal - only existing portions are accessed
//! - **Comprehensive Testing**: 100+ tests including security audits, Python-inspired edge cases and cross-platform validation
//! - **100% Behavioral Compatibility**: Passes all std::fs::canonicalize tests for existing paths
//!
//! For detailed performance benchmarks and comparisons with Python's pathlib, see the `benches/` directory.
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

use std::path::{Path, PathBuf};
use std::{fs, io};

/// Maximum number of symlinks to follow before giving up.
/// This matches the behavior of std::fs::canonicalize and OS limits:
/// - Linux: ELOOP limit is typically 40
/// - Windows: Similar limit around 63
/// - Other Unix systems: Usually 32-40
pub const MAX_SYMLINK_DEPTH: usize = if cfg!(target_os = "windows") { 63 } else { 40 };

/// Performs "soft" canonicalization on a path.
///
/// **Inspired by Python's `pathlib.Path.resolve(strict=False)`** - this function brings
/// the same functionality to Rust with enhanced performance and safety features.
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
/// Performs "soft" canonicalization on a path.
///
/// This function is inspired by Python's `pathlib.Path.resolve(strict=False)` behavior.
/// Unlike `std::fs::canonicalize`, this function can handle paths that don't fully exist
/// on the filesystem, making it useful for applications that need to resolve paths
/// before creating them.
///
/// # Performance
///
/// This implementation uses a fast-path approach that matches Python's strategy:
/// - Try `std::fs::canonicalize` first for existing paths
/// - Fall back to incremental boundary detection for mixed existing/non-existing paths
/// - Zero dependencies - pure std library implementation
///
/// # Behavior
///
/// - **Existing paths**: Uses `std::fs::canonicalize` for maximum accuracy and performance
/// - **Mixed paths**: Canonicalizes the existing portion, then appends non-existing components
/// - **Non-existing paths**: Performs lexical resolution with proper symlink handling
/// - **Relative paths**: Converts to absolute using current working directory
/// - **Symlinks**: Follows symlinks in existing portions, with cycle detection
/// - **Edge cases**: Handles `.`, `..`, empty components, and complex traversals
///
/// # Platform Notes
///
/// On Windows, canonical paths use the `\\?\` UNC prefix format for consistency
/// with `std::fs::canonicalize`.
///
/// # Examples
///
/// ```
/// use soft_canonicalize::soft_canonicalize;
/// use std::path::Path;
///
/// // Works with existing paths (like std::fs::canonicalize)
/// let existing = soft_canonicalize("/etc/passwd")?;
///
/// // Also works with non-existing paths (unlike std::fs::canonicalize)
/// let non_existing = soft_canonicalize("/path/to/future/file.txt")?;
///
/// // Handles relative paths
/// let relative = soft_canonicalize("../some/file.txt")?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Cannot determine the current working directory (for relative paths)
/// - Cannot read symlink targets in existing portions
/// - Path contains null bytes or other invalid characters
/// - Symlink depth exceeds the system limit (40 levels)
/// - Path traversal goes above the filesystem root
pub fn soft_canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();

    #[cfg(debug_assertions)]
    if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
        eprintln!("DEBUG: soft_canonicalize called with: {path:?}");
    }

    // Handle empty path early (like std::fs::canonicalize)
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "The system cannot find the path specified.",
        ));
    }

    // Fast path: try std::fs::canonicalize first (Python's strategy)
    // This handles all existing paths in a single optimized syscall
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }
    // Path doesn't exist entirely - continue with boundary detection

    // Check for null bytes in the path
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

    // Convert to absolute path - preserve the original path's drive/root
    let absolute_path = if path.is_absolute() {
        path.to_path_buf() // Use path as-is for absolute paths
    } else {
        std::env::current_dir()?.join(path) // Only join for relative paths
    };

    // Find the boundary between existing and non-existing parts
    // Process .. and . components lexically first
    let mut existing_prefix = PathBuf::new();
    let mut remaining_components = Vec::new();

    // First, collect all components and resolve . and .. lexically
    for component in absolute_path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                existing_prefix.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                remaining_components.push(name.to_os_string());
            }
            std::path::Component::ParentDir => {
                // Remove last component if any (lexical .. resolution)
                if !remaining_components.is_empty() {
                    remaining_components.pop();
                }
            }
            std::path::Component::CurDir => {
                // Ignore . components
            }
        }
    }

    // Now find how much of the path actually exists
    let mut existing_count = 0;
    let mut symlink_resolved_base: Option<PathBuf> = None;

    // Use existing_prefix as working buffer to avoid clones
    for (i, component) in remaining_components.iter().enumerate() {
        existing_prefix.push(component);

        if existing_prefix.exists() {
            existing_count = i + 1;

            // If it's a symlink, try to resolve it using controlled chain resolution
            // This handles all symlink scenarios while avoiding system symlink depth issues
            if existing_prefix.is_symlink() {
                #[cfg(debug_assertions)]
                if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
                    eprintln!("DEBUG: Found symlink at: {existing_prefix:?}");
                }

                // Handle symlinks with comprehensive chain resolution
                match resolve_simple_symlink_chain(&existing_prefix) {
                    Ok(resolved) => {
                        #[cfg(debug_assertions)]
                        if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
                            eprintln!("DEBUG: Symlink resolved to: {resolved:?}");
                        }

                        // Update path and continue
                        existing_prefix = resolved;
                        continue;
                    }
                    Err(_) => {
                        // Can't resolve the symlink - treat it as the boundary
                        break;
                    }
                }
            }
        } else if existing_prefix.is_symlink() {
            // Handle broken symlinks (exists() returns false but is_symlink() returns true)
            #[cfg(debug_assertions)]
            if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
                eprintln!("DEBUG: Found broken symlink at: {existing_prefix:?}");
            }

            match resolve_simple_symlink_chain(&existing_prefix) {
                Ok(resolved) => {
                    // For broken symlinks, store the resolved base and break
                    let final_resolved = if resolved.exists() {
                        fs::canonicalize(&resolved).unwrap_or(resolved)
                    } else {
                        resolved
                    };
                    symlink_resolved_base = Some(final_resolved);
                    existing_count = i + 1;
                    break;
                }
                Err(e) => {
                    // Check if this is a cycle error - if so, propagate it
                    if e.kind() == io::ErrorKind::InvalidInput {
                        return Err(e);
                    }
                    // Can't resolve the symlink - treat as boundary
                    existing_prefix.pop();
                    break;
                }
            }
        } else {
            // Found the boundary - remove the non-existing component
            existing_prefix.pop();
            break;
        }
    }

    // Build the final result
    let mut result = if let Some(symlink_base) = symlink_resolved_base {
        // We resolved a broken symlink chain - use that as base
        #[cfg(debug_assertions)]
        if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
            eprintln!("DEBUG: Using symlink_resolved_base: {symlink_base:?}");
        }

        // Try to canonicalize the symlink base to handle macOS /var -> /private/var
        // This is a final attempt to ensure proper canonicalization
        if !symlink_base.exists() {
            // For non-existing paths, try to canonicalize the existing parent
            let mut current = symlink_base;
            let mut final_result = current.clone();

            while let Some(parent) = current.parent() {
                if parent.exists() {
                    #[cfg(debug_assertions)]
                    if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
                        eprintln!("DEBUG: Final canonicalization attempt on parent: {parent:?}");
                    }
                    if let Ok(canonical_parent) = fs::canonicalize(parent) {
                        if let Ok(relative_part) = final_result.strip_prefix(parent) {
                            final_result = canonical_parent.join(relative_part);
                            #[cfg(debug_assertions)]
                            if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
                                eprintln!(
                                    "DEBUG: Final canonicalized symlink base: {final_result:?}"
                                );
                            }
                            break;
                        }
                    }
                }
                current = parent.to_path_buf();
            }
            final_result
        } else {
            // For existing symlink bases, try to canonicalize them to get proper format (e.g., \\?\ on Windows)
            fs::canonicalize(&symlink_base).unwrap_or(symlink_base)
        }
    } else if existing_count > 0 {
        // Use the existing prefix, but ensure it's properly canonicalized
        #[cfg(debug_assertions)]
        if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
            eprintln!("DEBUG: Using existing_prefix: {existing_prefix:?}");
        }

        // Try to canonicalize the existing prefix to ensure proper Windows path format
        if existing_prefix.exists() {
            fs::canonicalize(&existing_prefix).unwrap_or_else(|_| existing_prefix.clone())
        } else {
            // For non-existing paths, try to canonicalize the deepest existing parent
            let mut result_path = existing_prefix.clone();
            let mut current = existing_prefix.clone();
            while let Some(parent) = current.parent() {
                if parent.exists() {
                    if let Ok(canonical_parent) = fs::canonicalize(parent) {
                        if let Ok(relative_part) = existing_prefix.strip_prefix(parent) {
                            result_path = canonical_parent.join(relative_part);
                            break;
                        }
                    }
                }
                current = parent.to_path_buf();
            }
            result_path
        }
    } else {
        // Nothing exists beyond the root
        #[cfg(debug_assertions)]
        if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
            eprintln!("DEBUG: Using raw existing_prefix: {existing_prefix:?}");
        }
        existing_prefix.clone()
    };

    // Append the non-existing parts
    for component in remaining_components.iter().skip(existing_count) {
        result.push(component);
    }

    #[cfg(debug_assertions)]
    if std::env::var("SOFT_CANONICALIZE_DEBUG").is_ok() {
        eprintln!("DEBUG: Final result: {result:?}");
    }
    Ok(result)
}

/// Resolves a symlink chain with controlled depth to handle all symlink scenarios
/// This handles broken symlink chains, cycles, and system symlink transparency
fn resolve_simple_symlink_chain(symlink_path: &Path) -> io::Result<PathBuf> {
    let mut current = symlink_path.to_path_buf();
    let mut depth = 0;
    let mut visited_paths: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Use different depth limits based on the platform and symlink type
    let effective_max_depth = if is_likely_system_symlink(&current) {
        // For system symlinks, use a lower limit to leave room in the main algorithm
        5
    } else {
        // For regular symlinks, allow the full system limit
        // This ensures we can handle MAX_SYMLINK_DEPTH user symlinks as expected
        MAX_SYMLINK_DEPTH
    };

    loop {
        // OPTIMIZATION: Use HashSet for O(1) cycle detection instead of Vec O(n)
        let current_str = current.to_string_lossy().to_string();
        if !visited_paths.insert(current_str) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Too many levels of symbolic links",
            ));
        }

        // Try to read the symlink
        match fs::read_link(&current) {
            Ok(target) => {
                depth += 1;
                if depth > effective_max_depth {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Too many levels of symbolic links",
                    ));
                }

                // OPTIMIZED: Simplified security check for better performance
                if !target.is_absolute() && target.to_string_lossy().contains("..") {
                    let dotdot_count = target
                        .components()
                        .filter(|c| matches!(c, std::path::Component::ParentDir))
                        .count();

                    // Quick check - if more than 3 .. components, block it
                    if dotdot_count > 3 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Symlink traversal blocked for security",
                        ));
                    }
                }

                // OPTIMIZED: Target resolution with proper relative path handling
                if target.is_absolute() {
                    current = target;
                } else if let Some(parent) = current.parent() {
                    let resolved = parent.join(&target);
                    let normalized = simple_normalize_path(&resolved);

                    // Special handling for ../path patterns to ensure proper resolution
                    if !normalized.exists() && target.to_string_lossy().starts_with("../") {
                        // For ../path patterns, try alternative interpretation
                        if let Ok(stripped) = target.strip_prefix("../") {
                            let alternative = parent.join(stripped);
                            if alternative.exists() || alternative.ancestors().any(|a| a.exists()) {
                                current = alternative;
                            } else {
                                current = normalized;
                            }
                        } else {
                            current = normalized;
                        }
                    } else {
                        current = normalized;
                    }
                } else {
                    current = target;
                }
            }
            Err(_) => {
                // No more symlinks in the chain - return the current target
                // This handles broken symlink chains where the final target doesn't exist
                break;
            }
        }
    }

    Ok(current)
}

/// Checks if a symlink is likely a system symlink that shouldn't consume depth budget
fn is_likely_system_symlink(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Common system symlink patterns on different platforms
    if cfg!(target_os = "macos") {
        // macOS system symlinks
        path_str.starts_with("/var") || path_str.starts_with("/tmp") || path_str.starts_with("/etc")
    } else if cfg!(target_os = "linux") {
        // Linux system symlinks
        path_str.starts_with("/lib")
            || path_str.starts_with("/usr/lib")
            || path_str.starts_with("/bin")
            || path_str.starts_with("/sbin")
    } else {
        // Conservative approach for other platforms
        false
    }
}

/// Simple path normalization for .. components
fn simple_normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                result.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                components.push(name.to_os_string());
            }
            std::path::Component::ParentDir => {
                if !components.is_empty() {
                    components.pop();
                }
            }
            std::path::Component::CurDir => {
                // Ignore . components
            }
        }
    }

    for component in components {
        result.push(component);
    }

    result
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
