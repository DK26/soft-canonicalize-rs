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
//! **🔬 Comprehensive test suite with 260 tests including std::fs::canonicalize compatibility tests,
//! robustness validation, edge case handling, and cross-platform validation.**
//!
//! ## Why Use This?
//!
//! - **🚀 Works with non-existing paths** - Plan file locations before creating them  
//! - **⚡ Fast** - Mixed workload median performance observed in recent runs: Windows ~1.9x, Linux ~3.0x faster than Python's pathlib  
//! - **✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths  
//! - **🔒 Robust** - 260 tests including symlink cycle protection, malicious stream validation, and edge case handling  
//! - **🛡️ Robust path handling** - Proper `..` and symlink resolution with cycle detection and boundary enforcement
//! - **🌍 Cross-platform** - Windows, macOS, Linux with proper UNC/symlink handling and Unicode preservation
//! - **🔧 Zero dependencies** - Only uses std library with comprehensive edge case validation
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
//! soft-canonicalize = "0.2"
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
//! **260 comprehensive tests** including:
//!
//! - **11 std::fs::canonicalize compatibility tests** ensuring 100% behavioral compatibility
//! - **80+ robustness tests** covering consistent canonicalization behavior and edge cases  
//! - **Python pathlib test suite adaptations** for cross-language validation
//! - **Platform-specific tests** for Windows, macOS, and Linux edge cases
//! - **Performance and stress tests** validating behavior under various conditions
//!
//! ### 🔍 Tested Against Path Handling Edge Cases
//!
//! Our comprehensive test suite validates consistent canonicalization behavior across various challenging scenarios:
//!
//! - **Race Condition Robustness**: Tests against filesystem changes during canonicalization (symlinks replaced, directories modified) to ensure consistent behavior
//! - **Symlink Cycle Protection**: Detects and rejects circular symlink references using visited set tracking to prevent infinite loops
//! - **Malicious Stream Detection**: Validates Windows NTFS Alternate Data Stream syntax, rejecting malformed patterns like `file:../../../evil.exe`
//! - **Unicode Normalization Handling**: Consistent behavior with Unicode normalization forms and edge cases
//! - **Encoding Consistency**: Validates that percent-encoded sequences are handled consistently across platforms
//! - **Case Sensitivity Handling**: Consistent behavior on case-insensitive filesystems
//! - **Path Boundary Validation**: Comprehensive testing of path resolution boundaries and component limits
//! - **Filesystem Boundary Testing**: Edge cases around filename length limits and component count boundaries
//! - **Explicit Null Byte Handling**: Consistent error handling across platforms (unlike OS-dependent behavior)
//!
//! These tests ensure that `soft_canonicalize` provides consistent, predictable behavior while protecting against common path-related attack vectors during the canonicalization process itself.
//!
//! ## Performance & Benchmarks
//!
//! Recent benchmark snapshot (2025-08-18):
//! - Windows (5 runs): Rust mixed-workload median ~10.4k paths/s vs Python baseline median ~5.3k paths/s (~1.9x)
//! - Linux (WSL, 5 runs): Rust mixed-workload median ~297k paths/s vs Python baseline median ~91k paths/s (~3.0x)
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
///
/// **Benchmark snapshot** (mixed workloads): Windows ~9.0k–12.3k vs Python ~5.8k–6.3k; Linux ~238k–448k vs Python ~95k.
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

    // Windows-only: explicit guard — reject incomplete UNC roots (\\server without a share)
    #[cfg(windows)]
    {
        if is_incomplete_unc(path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid UNC path: missing share",
            ));
        }
    }

    // Stage 1: convert to absolute path (preserves drive/root semantics)
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    // Windows-only EARLY ADS validation (before lexical normalization) so that patterns like
    //   decoy.txt:..\\..\\evil.exe are rejected before `..` components collapse and hide intent.
    #[cfg(windows)]
    validate_windows_ads_layout(&absolute_path)?;

    // Stage 1.5: fast-path — attempt std canonicalize on the ORIGINAL absolute path first.
    // Rationale: For fully-existing paths, we must match the platform's symlink semantics
    // exactly. Performing lexical normalization (collapsing "..") before this step would
    // change behavior in cases like "symlink/../x" where the OS resolves the symlink first.
    match fs::canonicalize(&absolute_path) {
        Ok(p) => return Ok(p),
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => { /* continue to boundary detection */ }
            io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied => return Err(e),
            _ => { /* continue to optimized boundary detection */ }
        },
    }

    // Stage 2: pre-normalize lexically (resolve . and .. without touching the filesystem)
    let normalized_path = simple_normalize_path(&absolute_path);

    // Windows-only LATE ADS validation (defense in depth after normalization) in case normalization
    // produces a new final colon component scenario.
    #[cfg(windows)]
    validate_windows_ads_layout(&normalized_path)?;

    // Stage 3: fast-path — try fs::canonicalize on the lexically-normalized path as well,
    // but only if normalization actually changed the path. This avoids an extra syscall in
    // the common case where the absolute path was already normalized.
    if normalized_path != absolute_path {
        match fs::canonicalize(&normalized_path) {
            Ok(p) => return Ok(p),
            Err(e) => match e.kind() {
                io::ErrorKind::NotFound => { /* fall through to optimized boundary detection */ }
                io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied => return Err(e),
                _ => { /* fall through to optimized boundary detection */ }
            },
        }
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

    for component in absolute_path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                root_prefix.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => {
                components.push(name.to_os_string());
            }
            std::path::Component::CurDir => components.push(std::ffi::OsString::from(".")),
            std::path::Component::ParentDir => components.push(std::ffi::OsString::from("..")),
        }
    }

    // Stage 5: discover the deepest existing prefix and resolve symlinks inline as encountered
    let (existing_prefix, existing_count, symlink_seen) =
        compute_existing_prefix(&root_prefix, &components)?;

    // Stage 6: Build the base result; optionally canonicalize the anchor once if any symlink was seen.
    let mut base = existing_prefix;

    // Rationale: If we didn't resolve any symlink, the existing prefix already reflects the
    // filesystem's view (case, UNC, etc.). If we did, canonicalize the existing prefix once
    // to normalize casing/UNC details. The existing prefix should exist by construction.
    if symlink_seen {
        if let Ok(canon) = fs::canonicalize(&base) {
            base = canon;
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

    // After we have a fully-resolved base, normalize lexically to clean up any
    // remaining './' or '../' occurrences in the appended tail.
    result = simple_normalize_path(&result);

    // Stage 8 (Windows): ensure extended-length prefix for absolute paths when we didn't canonicalize
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        if let Some(Component::Prefix(pr)) = result.components().next() {
            match pr.kind() {
                Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => { /* already extended */
                }
                Prefix::Disk(_) | Prefix::UNC(_, _) => {
                    result = ensure_windows_extended_prefix(&result);
                }
                Prefix::DeviceNS(_) => { /* leave as-is */ }
            }
        }
    }

    Ok(result)
}

#[cfg(windows)]
fn is_incomplete_unc(p: &Path) -> bool {
    // Detect \\server or \\server\\ (no share). Exclude verbatim and device namespaces.
    let raw = p.as_os_str().to_string_lossy();
    if raw.starts_with("\\\\") && !raw.starts_with("\\\\?\\") && !raw.starts_with("\\\\.\\") {
        let mut parts = raw
            .trim_start_matches(['\\', '/'])
            .split(['\\', '/'])
            .filter(|s| !s.is_empty());
        let server = parts.next();
        let share = parts.next();
        return server.is_some() && share.is_none();
    }
    false
}

#[cfg(windows)]
fn validate_windows_ads_layout(p: &Path) -> io::Result<()> {
    use std::path::Component;
    // Collect normal components (exclude prefix/root for positional analysis)
    let comps: Vec<_> = p
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .collect();
    if comps.len() <= 1 {
        return Ok(()); // Nothing to validate in single-component cases
    }
    for (i, comp) in comps.iter().enumerate() {
        if let Component::Normal(name) = comp {
            let s = name.to_string_lossy();
            if s.contains(':') {
                if i < comps.len() - 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NTFS ADS placement: colon-containing component '{s}' must be final"),
                    ));
                }
                // Split into base + stream [+ type]
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() < 2 {
                    continue; // shouldn't happen; contains(':') implies >=2 parts
                }
                if parts.len() > 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "invalid NTFS ADS stream: too many colons in final component '{s}'"
                        ),
                    ));
                }
                let stream_part = parts[1];
                if stream_part.is_empty()
                    || stream_part == "."
                    || stream_part == ".."
                    || stream_part.trim().is_empty()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NTFS ADS stream name in '{s}'"),
                    ));
                }
                // Reject whitespace manipulation (leading/trailing whitespace in stream names)
                if stream_part != stream_part.trim() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NTFS ADS stream name contains leading/trailing whitespace in '{s}'"),
                    ));
                }
                // Reject control characters and null bytes in stream names
                if stream_part.chars().any(|c| c.is_control() || c == '\0') {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "invalid NTFS ADS stream name contains control characters in '{s}'"
                        ),
                    ));
                }
                // SECURITY: Reject Unicode manipulation attacks (zero-width chars, BOM, etc.)
                if stream_part.chars().any(|c| {
                    matches!(
                        c,
                        '\u{200B}' |   // Zero-width space
                        '\u{200C}' |   // Zero-width non-joiner  
                        '\u{200D}' |   // Zero-width joiner
                        '\u{FEFF}' |   // Byte order mark
                        '\u{200E}' |   // Left-to-right mark
                        '\u{200F}' |   // Right-to-left mark
                        '\u{202A}' |   // Left-to-right embedding
                        '\u{202B}' |   // Right-to-left embedding
                        '\u{202C}' |   // Pop directional formatting
                        '\u{202D}' |   // Left-to-right override
                        '\u{202E}' // Right-to-left override
                    )
                }) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NTFS ADS stream name contains Unicode manipulation characters in '{s}'"),
                    ));
                }
                // Reject overly long stream names (NTFS limit ~255 chars for stream name)
                if stream_part.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NTFS ADS stream name too long in '{s}'"),
                    ));
                }
                // Disallow separators or traversal markers anywhere after first colon
                let after_first_colon = &s[s.find(':').unwrap() + 1..];
                if after_first_colon.contains(['\\', '/'])
                    || after_first_colon.contains("..\\")
                    || after_first_colon.contains("../")
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid NTFS ADS stream name contains path separator or traversal in '{s}'"),
                    ));
                }
                // Additional security: reject Windows device names as stream names to prevent confusion
                let stream_upper = stream_part.to_ascii_uppercase();
                if matches!(
                    stream_upper.as_str(),
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                ) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "invalid NTFS ADS stream name uses reserved device name '{stream_part}'"
                        ),
                    ));
                }
                if parts.len() == 3 {
                    let ty = parts[2];
                    // Allow NTFS stream type tokens: $ + alphanumeric/underscore (case-insensitive for real types like $DATA, $BITMAP)
                    let valid_type = ty.starts_with('$')
                        && ty.len() > 1
                        && ty
                            .chars()
                            .skip(1)
                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        && !ty.chars().any(|c| c.is_control() || c.is_whitespace());
                    if !valid_type {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid NTFS ADS stream type '{ty}' in component '{s}'"),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
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
#[inline]
fn has_windows_short_component(p: &Path) -> bool {
    use std::path::Component;
    for comp in p.components() {
        if let Component::Normal(name) = comp {
            // Fast path: check for '~' in UTF-16 code units without allocating a String
            use std::os::windows::ffi::OsStrExt;
            let mut saw_tilde = false;
            for u in name.encode_wide() {
                if u == b'~' as u16 {
                    saw_tilde = true;
                    break;
                }
            }
            if !saw_tilde {
                continue;
            }
            if is_likely_8_3_short_name_wide(name) {
                return true;
            }
        }
    }
    false
}

#[cfg(windows)]
fn is_likely_8_3_short_name_wide(name: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    // Stream over UTF-16 code units without heap allocation using a small state machine.
    // States:
    //   0 = before '~' (must see at least one ASCII char)
    //   1 = reading one-or-more digits after '~'
    let mut it = name.encode_wide();
    let mut seen_pre_char = false; // at least one ASCII char before '~'
    let mut state = 0u8;
    let mut saw_digit = false;

    // Iterate through all code units once.
    while let Some(u) = it.next() {
        // Enforce ASCII-only for 8.3 short names
        if u > 0x7F {
            return false;
        }
        let b = u as u8;
        match state {
            0 => {
                if b == b'~' {
                    // Require at least one char before '~'
                    if !seen_pre_char {
                        return false;
                    }
                    state = 1;
                } else {
                    // Any ASCII char counts as pre-tilde content
                    seen_pre_char = true;
                }
            }
            1 => {
                if b.is_ascii_digit() {
                    saw_digit = true;
                } else {
                    // Digit run ended; accept only "." followed by at least one more char
                    if !saw_digit {
                        return false;
                    }
                    if b == b'.' {
                        // Must have at least one ASCII unit after '.'
                        match it.next() {
                            Some(u2) if u2 <= 0x7F => return true,
                            _ => return false,
                        }
                    } else {
                        return false;
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    // End of stream: valid only if we were parsing digits and saw at least one.
    state == 1 && saw_digit
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

    for c in components.iter() {
        // Apply '.' and '..' lexically during traversal, so that if a prior
        // component was a symlink and got resolved, '..' climbs from the
        // symlink target (symlink-first semantics).
        if c == std::ffi::OsStr::new(".") {
            count += 1;
            continue;
        }
        if c == std::ffi::OsStr::new("..") {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    path = parent.to_path_buf();
                }
            }
            count += 1;
            continue;
        }

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
    let mut current = symlink_path.to_path_buf();
    let mut depth = 0usize;
    // Small Vec cycle detection avoids hashing overhead; chains are typically short.
    let mut visited: Vec<std::ffi::OsString> = Vec::with_capacity(8);

    // Heuristic: system symlinks are unlikely to be malicious chains; keep their budget small
    let effective_max_depth = if is_likely_system_symlink(&current) {
        5
    } else {
        MAX_SYMLINK_DEPTH
    };

    loop {
        // Detect cycles using the textual path (no extra IO)
        if visited.iter().any(|s| s == current.as_os_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Too many levels of symbolic links",
            ));
        }
        visited.push(current.as_os_str().to_os_string());

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
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::path::{Component, Prefix};

        // Capture prefix and root semantics, and normalize components lexically with clamping
        enum Anchor {
            None,
            Drive(OsString),         // e.g., "C:"
            Unc(OsString, OsString), // (server, share)
            DeviceNS(OsString),      // raw device prefix (e.g., \\.\, \\?\GLOBALROOT\...)
        }

        let mut anchor = Anchor::None;
        let mut prefix_os: Option<OsString> = None; // original prefix text
        let mut has_root_dir = false;
        let mut stack: Vec<OsString> = Vec::new();

        for comp in path.components() {
            match comp {
                Component::Prefix(p) => {
                    // Identify and preserve prefix verbatim, but capture parsed parts for UNC/Drive
                    prefix_os = Some(p.as_os_str().to_os_string());
                    match p.kind() {
                        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                            anchor = Anchor::Unc(server.to_os_string(), share.to_os_string());
                        }
                        Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                            // Store like "C:"
                            let mut s = OsString::with_capacity(2);
                            s.push(format!("{}:", (d as char)));
                            anchor = Anchor::Drive(s);
                            // For drive-absolute, RootDir will activate floor
                        }
                        Prefix::DeviceNS(ns) | Prefix::Verbatim(ns) => {
                            anchor = Anchor::DeviceNS(ns.to_os_string());
                        }
                    }
                }
                Component::RootDir => {
                    has_root_dir = true;
                }
                Component::CurDir => {
                    // skip
                }
                Component::Normal(name) => {
                    stack.push(name.to_os_string());
                }
                Component::ParentDir => {
                    if !stack.is_empty() {
                        stack.pop();
                    } else {
                        // Either no floor or at floor: ignore/clamp, do nothing
                    }
                }
            }
        }

        // Fallback: if no anchor detected but the raw path starts with two slashes (UNC-like),
        // treat the first two components as server/share and clamp at that share root.
        if matches!(anchor, Anchor::None) {
            // Detect raw leading UNC (\\server\share) and override anchor,
            // excluding verbatim (\\?\) and device (\\.\) namespaces.
            let raw = path.as_os_str().to_string_lossy();
            if raw.starts_with("\\\\") && !raw.starts_with("\\\\?\\") && !raw.starts_with("\\\\.\\")
            {
                // Tokenize by both separators
                let mut parts = raw
                    .trim_start_matches(['\\', '/'])
                    .split(['\\', '/'])
                    .filter(|s| !s.is_empty());
                if let (Some(server_s), Some(share_s)) = (parts.next(), parts.next()) {
                    let server = std::ffi::OsString::from(server_s);
                    let share = std::ffi::OsString::from(share_s);
                    anchor = Anchor::Unc(server, share);
                    has_root_dir = true;

                    // Lexically normalize the remainder
                    let mut new_stack: Vec<std::ffi::OsString> = Vec::new();
                    for seg in parts {
                        match seg {
                            "." => {}
                            ".." => {
                                let _ = new_stack.pop();
                            }
                            _ => new_stack.push(std::ffi::OsString::from(seg)),
                        }
                    }
                    stack = new_stack;
                }
            }
        }

        // Rebuild path using Anchor where possible (UNC/Drive), falling back to original prefix for DeviceNS
        let mut out = PathBuf::new();
        match &anchor {
            Anchor::Unc(server, share) => {
                // Build non-verbatim UNC: \\server\share
                let base = PathBuf::from(format!(
                    r"\\{}\{}",
                    server.to_string_lossy(),
                    share.to_string_lossy()
                ));
                out.push(base);
                if has_root_dir {
                    out.push(Component::RootDir.as_os_str());
                }
            }
            Anchor::Drive(drive) => {
                out.push(drive);
                if has_root_dir {
                    out.push(Component::RootDir.as_os_str());
                }
            }
            Anchor::DeviceNS(ns) => {
                let _ = ns; // read to avoid dead_code warning
                if let Some(p) = &prefix_os {
                    out.push(p);
                }
                // No RootDir for DeviceNS
            }
            Anchor::None => {
                if let Some(p) = &prefix_os {
                    out.push(p);
                }
                if has_root_dir {
                    out.push(Component::RootDir.as_os_str());
                }
            }
        }
        // If we have a Drive or UNC anchor, return an extended-length path now
        match anchor {
            Anchor::Unc(ref server, ref share) => {
                let mut ext = PathBuf::from(r"\\?\UNC");
                ext.push(server);
                ext.push(share);
                for seg in stack {
                    ext.push(seg);
                }
                return ext;
            }
            Anchor::Drive(ref drive) => {
                let mut ext = PathBuf::from(r"\\?\");
                ext.push(drive);
                if has_root_dir {
                    ext.push(Component::RootDir.as_os_str());
                }
                for seg in stack {
                    ext.push(seg);
                }
                return ext;
            }
            _ => {}
        }

        for seg in stack {
            out.push(seg);
        }
        out
    }

    #[cfg(not(windows))]
    {
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
    mod short_filename_detection;
    mod std_behavior;
    mod symlink_depth;
    mod symlink_dotdot_resolution_order;
    mod symlink_dotdot_symlink_first;
}
