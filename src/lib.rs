//! # soft-canonicalize
//!
//! Path canonicalization that works with non-existing paths.
//!
//! Inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`, this crate:
//! - Matches `std::fs::canonicalize` exactly for fully-existing paths
//! - Extends canonicalization to non-existing suffixes
//! - Preserves robust behavior across Windows, macOS, and Linux
//! - Provides zero-dependency, security-focused implementation
//!
//! ## Quick Start
//!
//! ```toml
//! [dependencies]
//! soft-canonicalize = "0.3"
//! ```
//!
//! ### Cross-Platform Example
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//!
//! // Existing path behaves like std::fs::canonicalize
//! let existing = soft_canonicalize(&std::env::temp_dir())?;
//! # let _ = existing;
//!
//! // Also works when suffixes don't exist yet
//! let non_existing = soft_canonicalize(
//!     std::env::temp_dir().join("some/deep/non/existing/path.txt")
//! )?;
//! # let _ = non_existing;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! ### Windows Example (UNC/extended-length)
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//! # fn example() -> Result<(), std::io::Error> {
//! # #[cfg(windows)]
//! # {
//! let p = r"C:\\Users\\user\\documents\\..\\non\\existing\\config.json";
//! let result = soft_canonicalize(p)?;
//! assert!(result.to_string_lossy().starts_with(r"\\\\?\\C:"));
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! ## How It Works
//!
//! 1. Input validation (empty path, platform pre-checks)
//! 2. Convert to absolute path (preserving drive/root semantics)
//! 3. Fast-path: try `fs::canonicalize` on the original absolute path
//! 4. Lexically normalize `.` and `..` (streaming, no extra allocations)
//! 5. Fast-path: try `fs::canonicalize` on the normalized path when different
//! 6. Validate null bytes (platform-specific)
//! 7. Discover deepest existing prefix; resolve symlinks inline with cycle detection
//! 8. Optionally canonicalize the anchor (if symlinks seen) and rebuild
//! 9. Append non-existing suffix lexically, then normalize if needed
//! 10. Windows: ensure extended-length prefix for absolute paths
//!
//! ## Security Considerations
//!
//! - Directory traversal (`..`) resolved lexically before filesystem access
//! - Symlink chains resolved with cycle detection and depth limits
//! - Windows NTFS ADS validation performed early and after normalization
//! - Embedded NUL byte checks on all platforms
//!
//! ## Cross-Platform Notes
//!
//! - Windows: returns extended-length verbatim paths for absolute results (`\\?\C:\…`, `\\?\UNC\…`)
//! - Unix-like systems: standard absolute and relative path semantics
//! - UNC floors and device namespaces are preserved and respected
//!
//! ## Test Coverage
//!
//! 264+ tests including:
//! - std::fs::canonicalize compatibility tests (existing paths)
//! - Path traversal and robustness tests
//! - Python pathlib-inspired behavior checks
//! - Platform-specific cases (Windows/macOS/Linux)
//! - Symlink semantics and cycle detection
//! - Windows-specific UNC, 8.3, and ADS validation
//!
//! ## Known Limitation (Windows 8.3)
//!
//! On Windows, for non-existing paths we cannot determine equivalence between a short (8.3)
//! name and its long form. Existing paths are canonicalized to the same result.
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//! # fn example() -> Result<(), std::io::Error> {
//! # #[cfg(windows)]
//! # {
//! let short_form = soft_canonicalize("C:/PROGRA~1/MyApp/config.json")?;
//! let long_form  = soft_canonicalize("C:/Program Files/MyApp/config.json")?;
//! assert_ne!(short_form, long_form); // for non-existing suffixes
//! # }
//! # Ok(())
//! # }
//! ```

mod error;
mod normalize;
mod prefix;
mod symlink;
#[cfg(windows)]
mod windows;

pub use error::{IoErrorPathExt, SoftCanonicalizeError};
pub use symlink::MAX_SYMLINK_DEPTH;

use crate::error::error_with_path;
use crate::normalize::simple_normalize_path;
use crate::prefix::compute_existing_prefix;
#[cfg(windows)]
use crate::windows::{
    ensure_windows_extended_prefix, has_windows_short_component, is_incomplete_unc,
    validate_windows_ads_layout,
};

use std::path::{Path, PathBuf};
use std::{fs, io};

/// Performs "soft" canonicalization on a path.
///
/// Unlike `std::fs::canonicalize()`, this function works with non-existent paths by:
/// 1. Finding the deepest existing ancestor directory
/// 2. Canonicalizing that existing part (resolving symlinks, normalizing case, etc.)
/// 3. Appending the non-existing path components to the canonicalized base
///
/// This provides canonicalization benefits (symlink resolution, path normalization)
/// without requiring the entire path to exist.
pub fn soft_canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();

    // Stage 0: guard-rail — handle empty path early (aligns with std::fs::canonicalize)
    if path.as_os_str().is_empty() {
        return Err(error_with_path(
            io::ErrorKind::NotFound,
            path,
            "The system cannot find the path specified.",
        ));
    }

    // Windows-only: explicit guard — reject incomplete UNC roots (\\server without a share)
    #[cfg(windows)]
    {
        if is_incomplete_unc(path) {
            return Err(error_with_path(
                io::ErrorKind::InvalidInput,
                path,
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

    // Windows-only EARLY ADS validation (before lexical normalization)
    #[cfg(windows)]
    validate_windows_ads_layout(&absolute_path)?;

    // Stage 1.5: fast-path — attempt std canonicalize on the ORIGINAL absolute path first.
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

    // Windows-only LATE ADS validation (defense in depth after normalization)
    #[cfg(windows)]
    validate_windows_ads_layout(&normalized_path)?;

    // Stage 3: fast-path — try fs::canonicalize on the lexically-normalized path as well
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
            return Err(error_with_path(
                io::ErrorKind::InvalidInput,
                path,
                "path contains null byte",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        if path.as_os_str().encode_wide().any(|c| c == 0) {
            return Err(error_with_path(
                io::ErrorKind::InvalidInput,
                path,
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

    // Stage 6: Build the base result. Only canonicalize the deepest existing ancestor
    // when needed (e.g., symlink encountered).
    let mut base = existing_prefix;
    if existing_count > 0 && symlink_seen {
        // Identify deepest existing anchor (defensive in case base points at a symlink whose target doesn't exist)
        let mut anchor = base.as_path();
        while !anchor.exists() {
            if let Some(p) = anchor.parent() {
                anchor = p;
            } else {
                break;
            }
        }
        if anchor.exists() {
            if let Ok(canon_anchor) = fs::canonicalize(anchor) {
                // Rebuild base as: canonicalized anchor + relative suffix
                let suffix = base.strip_prefix(anchor).ok();
                let mut rebuilt = canon_anchor;
                if let Some(suf) = suffix {
                    rebuilt.push(suf);
                }
                base = rebuilt;
            }
        }
    }

    // Windows-only: Expand short-name component if no symlink encountered but base has 8.3 component
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
    let mut suffix_has_dot_or_dotdot = false;
    for component in components.iter().skip(existing_count) {
        if !suffix_has_dot_or_dotdot
            && (component == std::ffi::OsStr::new(".") || component == std::ffi::OsStr::new(".."))
        {
            suffix_has_dot_or_dotdot = true;
        }
        result.push(component);
    }

    // After we have a fully-resolved base, normalize lexically.
    #[cfg(windows)]
    {
        result = simple_normalize_path(&result);
    }
    #[cfg(not(windows))]
    {
        if suffix_has_dot_or_dotdot {
            result = simple_normalize_path(&result);
        }
    }

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
