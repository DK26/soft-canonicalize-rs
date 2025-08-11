//! # soft-canonicalize
//!
//! A high-performance, pure Rust library for path canonicalization that works with non-existing paths.
//!
//! **Inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`** - this library brings the same
//! functionality to Rust with enhanced performance and comprehensive testing.
//!
//! Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths
//! even when components don't exist on the filesystem. This enables accurate path
//! comparison, resolution of future file locations, and preprocessing paths before
//! file creation.
//!
//! **🔬 Comprehensive test suite with 111 tests including std::fs::canonicalize compatibility tests,
//! security penetration tests, Python pathlib validations, and CVE protections.**
//!
//! ## Why Use This?
//!
//! - **🚀 Works with non-existing paths** - Plan file locations before creating them  
//! - **⚡ Fast** - Windows: ~1.4–2.0x faster; Linux: ~2.5–4.7x faster than Python's pathlib (mixed workloads)  
//! - **✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths  
//! - **🔒 Security-tested** - 111 tests including CVE protections and path traversal prevention  
//! - **🛡️ Robust path handling** - Proper `..` and symlink resolution with cycle detection
//! - **🌍 Cross-platform** - Windows, macOS, Linux with proper UNC/symlink handling
//! - **🔧 Zero dependencies** - Only uses std library
//!
//! For detailed benchmarks, analysis, and testing procedures, see the [`benches/`](benches/) directory.
//!
//! > Performance varies by hardware and OS/filesystem. 
//! > See the bench outputs for per-scenario numbers.
//!
//! ## Quick Start
//!
//! ### Cargo.toml
//! ```toml
//! [dependencies]
//! soft-canonicalize = "0.2.2"
//! ```
//!
//! ### Code Example
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//! use std::path::PathBuf;
//!
//! # #[cfg(windows)]
//! # {
//! let non_existing_path = r"C:\Users\user\documents\..\non\existing\config.json";
//!
//! // Using Rust's own std canonicalize function:
//! let result = std::fs::canonicalize(non_existing_path);
//! assert!(result.is_err());
//!
//! // Using our crate's function:
//! let result = soft_canonicalize(non_existing_path);
//! assert!(result.is_ok());
//!
//! // Shows the UNC path conversion and path normalization
//! assert_eq!(
//!     result.unwrap().to_string_lossy(),
//!     r"\\?\C:\Users\user\non\existing\config.json"
//! );
//! # }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! ## How We Canonicalize
//!
//! This library implements an optimized, single-pass path resolution algorithm with the following stages:
//!
//! 1. **Input validation**: Handle empty paths early (matches `std::fs::canonicalize` behavior) — *O(1)*
//! 2. **Absolute path conversion**: Convert relative paths to absolute using the current working directory — *O(n)* (path join)
//! 3. **Streaming lexical normalization**: Resolve `.` and `..` components without filesystem calls using direct push/pop without intermediate allocations — *O(n)*
//! 4. **Fast-path attempt**: Try `std::fs::canonicalize` once for fully normalized existing paths; if it succeeds (path fully exists), return early — *O(s)* where s is symlink depth
//! 5. **Null byte validation**: Check for embedded null bytes (platform-specific error handling) — *O(n)*
//! 6. **Single-pass existing-prefix discovery**: Walk components left-to-right to find the deepest existing ancestor with minimal syscalls (early-exit when first component is missing); resolve symlinks inline with cycle detection — *O(k + s)* where k is existing components, s is symlink depth
//! 7. **Conditional anchor canonicalization**: If any symlink was encountered, canonicalize the deepest existing ancestor once to normalize casing/UNC details — *O(k)*
//! 8. **Result reconstruction**: Append non-existing components to the canonicalized base — *O(m)* where m is non-existing components
//! 9. **Platform-specific normalization**: Ensure extended-length prefix (\\?\) for absolute Windows paths when needed; robust Unix symlink behavior — *O(1)*
//!
//! **Overall Time Complexity**: Overall work is dominated by lexical normalization plus filesystem probes.
//! - End-to-end: *O(n + s)* where n is total components processed lexically and s is symlink depth
//! - Filesystem probes only: *O(k + s)* where k is existing components inspected
//! - **Best case (filesystem)**: *O(1)* probes when the first component doesn't exist (still incurs lexical *O(n)*)
//! - **Worst case**: *O(n + s)* when the entire path exists and/or deep symlinks are present
//! - **Average case**: *O(k)* where k is typically much smaller than total components
//!
//! ### Test Coverage
//!
//! **111 comprehensive tests** including:
//!
//! - **10 std::fs::canonicalize compatibility tests** ensuring 100% behavioral compatibility
//! - **32 security penetration tests** covering CVE-2022-21658 and path traversal attacks  
//! - **Python pathlib test suite adaptations** for cross-language validation
//! - **Platform-specific tests** for Windows, macOS, and Linux edge cases
//! - **Performance and stress tests** validating behavior under various conditions
//!
//! ### 🔍 Tested Against Known Vulnerabilities
//!
//! Our comprehensive security test suite specifically validates protection against real-world vulnerabilities found in other path handling libraries:
//!
//! - **CVE-2022-21658 Race Conditions**: Tests against Time-of-Check-Time-of-Use (TOCTOU) attacks where symlinks are replaced between canonicalization and file access
//! - **Unicode Normalization Bypasses**: Protection against attacks using Unicode normalization to disguise malicious paths
//! - **Double-Encoding Attacks**: Validates that percent-encoded sequences aren't automatically decoded (preventing bypass attempts)
//! - **Case Sensitivity Bypasses**: Tests on case-insensitive filesystems to prevent case-based security bypasses
//! - **Symlink Jail Escapes**: Comprehensive testing of symlinked directory attacks and nested symlink chains
//! - **NTFS Alternate Data Streams**: Windows-specific tests for ADS attack vectors that can hide malicious content
//! - **Filesystem Boundary Testing**: Edge cases around filename length limits and component count boundaries
//! - **Explicit Null Byte Detection**: Consistent error handling across platforms (unlike OS-dependent behavior)
//!
//! These tests ensure that `soft_canonicalize` doesn't inherit the security vulnerabilities that have affected other path canonicalization libraries, giving you confidence in production security-critical applications.
//!
//! ## Performance & Benchmarks
//!
//! Cross-platform performance (mixed workloads): Windows ~1.4–2.0x; Linux ~2.5–4.7x vs Python 3.x.
//!
//! **Windows mixed**: Rust ~9.5k–11.9k vs Python ~5.9k–6.9k paths/s (≈1.4–2.0x)
//! **Linux mixed**: Rust ~238k–448k vs Python ~95k paths/s (≈2.5–4.7x)
//!
//! *Performance varies by hardware and filesystem. Benchmarks run on Windows 11 and Linux.*
//!
//! For detailed benchmarks, analysis, and testing procedures, see the [`benches/`](benches/) directory.
//!
//! ## Known Limitations
//!
//! ### Windows Short Filename Equivalence
//!
//! On Windows, the filesystem may generate short filenames (8.3 format) for long directory names.
//! For **non-existing paths**, this library cannot determine if a short filename form (e.g., `PROGRA~1`)
//! and its corresponding long form (e.g., `Program Files`) refer to the same future location:
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//!
//! # fn example() -> std::io::Result<()> {
//! // These non-existing paths are treated as different (correctly)
//! let short_form = soft_canonicalize("C:/PROGRA~1/MyApp/config.json")?;
//! let long_form = soft_canonicalize("C:/Program Files/MyApp/config.json")?;
//!
//! // They will NOT be equal because we cannot determine equivalence
//! // without filesystem existence
//! assert_ne!(short_form, long_form);
//! # Ok(())
//! # }
//! ```
//!
//! **This is a fundamental limitation** shared by Python's `pathlib.Path.resolve(strict=False)`
//! and other path canonicalization libraries across languages. Short filename mapping only exists
//! when files/directories are actually created by the filesystem.
//!
//! **For existing paths**, this library correctly resolves short and long forms to the same
//! canonical result, maintaining 100% compatibility with `std::fs::canonicalize`.

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
/// **Inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`** - this function brings
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
/// 1. **Input validation**: Handle empty paths early (matches `std::fs::canonicalize` behavior)
/// 2. **Absolute path conversion**: Convert relative paths to absolute using the current working directory
/// 3. **Lexical normalization**: Resolve `.` and `..` components without filesystem calls
/// 4. **Fast-path attempt**: Try `std::fs::canonicalize` once; if it succeeds (path fully exists), return early
/// 5. **Null byte validation**: Check for embedded null bytes (platform-specific error handling)
/// 6. **Existing-prefix discovery**: Walk components left-to-right to find the deepest existing ancestor; resolve symlinks inline with cycle detection
/// 7. **Conditional anchor canonicalization**: If any symlink was encountered, canonicalize the deepest existing ancestor once to normalize casing/UNC details
/// 8. **Result reconstruction**: Append non-existing components to the canonicalized base
/// 9. **Windows normalization**: Ensure extended-length prefix (\\?\) for absolute Windows paths when needed
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
/// - **Time Complexity**:
///   - End-to-end: O(n + s) where n is total components processed lexically, s is symlink depth
///   - Filesystem probes: O(k + s) where k is the number of existing components (k ≤ n)
///   - Best (probes): O(1) when the first component doesn't exist; lexical normalization remains O(n)
///   - Worst: O(n + s) when the entire path exists and/or deep symlinks are present
/// - **Space Complexity**: O(n) for component storage during processing
/// - **Filesystem Access**: Minimal - only existing portions require filesystem calls
/// **Benchmark snapshot** (mixed workloads): Windows ~9.5k–11.9k vs Python ~5.9k–6.9k; Linux ~238k–448k vs Python ~95k.
///
/// **Comparison with alternatives**: Provides unique combination of non-existing path
/// support with full symlink resolution and robust path handling that other libraries
/// may not offer.
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
pub fn soft_canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();

    // Stage 0: guard-rail — handle empty path early (aligns with std::fs::canonicalize)
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "The system cannot find the path specified.",
        ));
    }

    // Stage 1: convert to absolute path (preserves drive/root semantics)
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    // Stage 2: pre-normalize lexically (resolve . and .. without touching the filesystem)
    let normalized_path = simple_normalize_path(&absolute_path);

    // Stage 3: fast-path — try fs::canonicalize once; for NotFound or non-fatal errors continue
    match fs::canonicalize(&normalized_path) {
        Ok(p) => return Ok(p),
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => { /* fall through to optimized boundary detection */ }
            io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied => return Err(e),
            _ => { /* fall through to optimized boundary detection */ }
        },
    }
    // At this point: path doesn't fully exist or canonicalize returned a recoverable error — continue.

    // Stage 3.1: sanity check — validate no embedded NUL bytes (platform-specific)
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

    // Stage 4: collect path components efficiently (root/prefix vs normal names)
    let mut components = Vec::new();
    let mut root_prefix = PathBuf::new();

    for component in normalized_path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                root_prefix.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                components.push(name.to_os_string());
            }
            // After normalization, we shouldn't see . or .. components
            _ => {}
        }
    }

    // Stage 5: discover the deepest existing prefix and resolve symlinks inline as encountered
    let (existing_prefix, existing_count, symlink_seen) =
        compute_existing_prefix(&root_prefix, &components)?;

    // Stage 6: Build the base result; optionally canonicalize the anchor once if any symlink was seen.
    let mut base = existing_prefix;

    // Rationale: If we didn't resolve any symlink, the existing prefix already reflects the
    // filesystem's view (case, UNC, etc.). If we did, canonicalizing the deepest existing
    // ancestor ensures consistent normalization across platforms without extra syscalls.
    if symlink_seen {
        let mut current: &Path = &base;
        while let Some(parent) = current.parent() {
            if parent.exists() {
                if let Ok(canonical_parent) = fs::canonicalize(parent) {
                    if let Ok(relative_part) = base.strip_prefix(parent) {
                        base = canonical_parent.join(relative_part);
                    } else {
                        base = canonical_parent;
                    }
                }
                break;
            }
            current = parent;
        }
    }

    // Windows-only: If no symlink was encountered but the existing prefix contains
    // any 8.3 short-name component (e.g., RUNNER~1), expand it once via canonicalize.
    // This keeps behavior stable across environments where temp/user dirs expose 8.3 names
    // while avoiding extra syscalls in the common case.
    #[cfg(windows)]
    {
        if !symlink_seen && existing_count > 0 && has_windows_short_component(&base) {
            if let Ok(canon_base) = fs::canonicalize(&base) {
                base = canon_base;
            }
        }
    }

    let mut result = base;

    // Stage 7: append the non-existing suffix components (purely lexical)
    for component in components.iter().skip(existing_count) {
        result.push(component);
    }

    // Stage 8 (Windows): ensure extended-length prefix for absolute paths when we didn't canonicalize
    #[cfg(windows)]
    {
        use std::path::Component;
        if matches!(result.components().next(), Some(Component::Prefix(_))) {
            result = ensure_windows_extended_prefix(&result);
        }
    }

    Ok(result)
}

#[cfg(windows)]
fn ensure_windows_extended_prefix(p: &Path) -> PathBuf {
    use std::path::{Component, Prefix};

    let mut comps = p.components();
    let first = match comps.next() {
        Some(Component::Prefix(pr)) => pr,
        _ => return p.to_path_buf(),
    };

    match first.kind() {
        Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => {
            // Already extended-length
            p.to_path_buf()
        }
        Prefix::Disk(_drive) => {
            // \\\?\\C:\...
            use std::ffi::OsString;
            let mut s = OsString::from(r"\\?\");
            s.push(p.as_os_str());
            PathBuf::from(s)
        }
        Prefix::UNC(server, share) => {
            // \\?\UNC\server\share\...
            let mut out = PathBuf::from(r"\\?\UNC\");
            out.push(server);
            out.push(share);
            for c in comps {
                out.push(c.as_os_str());
            }
            out
        }
        _ => p.to_path_buf(),
    }
}

//

#[cfg(windows)]
fn has_windows_short_component(p: &Path) -> bool {
    use std::path::Component;
    for comp in p.components() {
        if let Component::Normal(name) = comp {
            // Heuristic: 8.3 short names contain a tilde '~' in the component
            if name.to_string_lossy().contains('~') {
                return true;
            }
        }
    }
    false
}

/// Combined single-pass existing-prefix computation and inline symlink handling.
/// Contract:
/// - Input: root/prefix (e.g., "/" or "C:\\" or "\\\\?\\UNC\\server\\share\\") and a list of
///   normalized non-root components
/// - Output: (deepest_existing_path, number_of_existing_components, symlink_seen)
///
/// Behavior:
/// - Walk left-to-right, probing each component with symlink_metadata
/// - If a component is a symlink, attempt to resolve its chain; adopt the resolved path only if
///   the resolved target or its parent exists (preserves attachment semantics for non-existing suffixes)
/// - Early-exit when the next component doesn't exist
fn compute_existing_prefix(
    root_prefix: &Path,
    components: &[std::ffi::OsString],
) -> io::Result<(PathBuf, usize, bool)> {
    let mut path = root_prefix.to_path_buf();
    let mut count = 0usize;
    let mut symlink_seen = false;

    // Early fast-path: check first component only, common case when first doesn't exist
    if let Some(first) = components.first() {
        path.push(first);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    symlink_seen = true;
                    path = resolve_simple_symlink_chain(&path)?;
                }
                count = 1;
            }
            Err(_) => {
                // First component missing; return root as deepest existing
                let _ = path.pop();
                return Ok((root_prefix.to_path_buf(), 0, false));
            }
        }
    }

    for c in components.iter().skip(count) {
        path.push(c);

        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    symlink_seen = true;
                    // Resolve the chain; adopt only if target or its parent exists
                    let resolved = resolve_simple_symlink_chain(&path)?;
                    let adopt =
                        resolved.exists() || resolved.parent().map(|p| p.exists()).unwrap_or(false);
                    if adopt {
                        path = resolved;
                    } else {
                        // Keep the symlink path as part of the existing prefix
                        // so non-existing suffixes remain attached to the symlink component
                    }
                }
                count += 1;
            }
            Err(_) => {
                // Remove the non-existing component; base must remain the deepest existing
                let _ = path.pop();
                break;
            }
        }
    }

    Ok((path, count, symlink_seen))
}

/// Resolve a symlink chain using read_link only (no extra metadata calls).
/// Notes:
/// - Uses a visited set on textual paths to detect cycles without extra IO
/// - Caps depth at MAX_SYMLINK_DEPTH (or a smaller heuristic for common system symlinks)
/// - Re-resolves relative symlink targets against the parent of the current link
fn resolve_simple_symlink_chain(symlink_path: &Path) -> io::Result<PathBuf> {
    use std::collections::HashSet;

    let mut current = symlink_path.to_path_buf();
    let mut depth = 0usize;
    let mut visited: HashSet<std::ffi::OsString> = HashSet::with_capacity(8);

    // Heuristic: system symlinks are unlikely to be malicious chains; keep their budget small
    let effective_max_depth = if is_likely_system_symlink(&current) {
        5
    } else {
        MAX_SYMLINK_DEPTH
    };

    loop {
        // Detect cycles using the textual path (no extra IO)
        if !visited.insert(current.as_os_str().to_os_string()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Too many levels of symbolic links",
            ));
        }

        match fs::read_link(&current) {
            Ok(target) => {
                depth += 1;
                if depth > effective_max_depth {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Too many levels of symbolic links",
                    ));
                }

                if target.is_absolute() {
                    current = target;
                } else if let Some(parent) = current.parent() {
                    current = simple_normalize_path(&parent.join(target));
                } else {
                    current = target;
                }
            }
            Err(_) => break, // not a symlink or cannot read; stop here
        }
    }

    Ok(current)
}

/// Checks if a symlink is likely a system symlink that shouldn't consume depth budget
#[cfg(target_os = "macos")]
fn is_likely_system_symlink(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/var") || s.starts_with("/tmp") || s.starts_with("/etc")
}

#[cfg(target_os = "linux")]
fn is_likely_system_symlink(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/lib")
        || s.starts_with("/usr/lib")
        || s.starts_with("/bin")
        || s.starts_with("/sbin")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn is_likely_system_symlink(_path: &Path) -> bool {
    false
}

/// Streaming path normalization with push/pop operations.
/// This replaces intermediate Vec allocation with direct PathBuf manipulation.
/// Contract:
/// - Input: any Path (absolute/relative)
/// - Output: a PathBuf where `.` is removed and `..` pops one component when possible
/// - Root semantics are preserved (never pops past root)
fn simple_normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                result.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                result.push(name);
            }
            std::path::Component::ParentDir => {
                // Pop only if there is a parent (stay at root otherwise)
                let _ = result.pop();
            }
            std::path::Component::CurDir => {
                // Skip
            }
        }
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
    mod security_audit;
    mod std_behavior;
    mod symlink_depth;
    mod symlink_dotdot_resolution_order;
}
