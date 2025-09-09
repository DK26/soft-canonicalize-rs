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
//! ### Anchored Canonicalization (Security-Focused)
//!
//! For secure path handling within a known root directory:
//!
//! ```rust
//! # #[cfg(feature = "anchored")]
//! use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
//! # #[cfg(not(feature = "anchored"))]
//! # use soft_canonicalize::soft_canonicalize;
//! use std::fs;
//!
//! # fn example() -> Result<(), std::io::Error> {
//! // Set up an anchor directory
//! let root = std::env::temp_dir().join("workspace_root");
//! fs::create_dir_all(&root)?;
//! // No need to pre-canonicalize: anchored_canonicalize soft-canonicalizes the anchor internally
//! let anchor = &root;
//!
//! // Canonicalize user input relative to anchor
//! let user_input = "../../../etc/passwd";
//! # #[cfg(feature = "anchored")]
//! let resolved_path = anchored_canonicalize(anchor, user_input)?;
//! # #[cfg(not(feature = "anchored"))]
//! # { let _ = user_input; }
//! # #[cfg(feature = "anchored")]
//! # let _ = resolved_path;
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
//! ## Testing
//!
//! 301 tests including:
//! - std::fs::canonicalize compatibility tests (existing paths)
//! - Path traversal and robustness tests
//! - Python pathlib-inspired behavior checks
//! - Platform-specific cases (Windows/macOS/Linux)
//! - Symlink semantics and cycle detection
//! - Windows-specific UNC, 8.3, and ADS validation
//! - Anchored canonicalization tests (with `anchored` feature)
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

#[inline]
fn path_contains_nul(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        p.as_os_str().as_bytes().contains(&0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        p.as_os_str().encode_wide().any(|c| c == 0)
    }
}

#[inline]
fn reject_nul_bytes(p: &Path) -> io::Result<()> {
    if path_contains_nul(p) {
        return Err(error_with_path(
            io::ErrorKind::InvalidInput,
            p,
            "path contains null byte",
        ));
    }
    Ok(())
}

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
    reject_nul_bytes(path)?;

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

/// Canonicalize a user-provided path relative to an anchor directory, with symlink-aware semantics.
///
/// This function resolves paths **as if rooted under a given anchor**, performing canonical path
/// resolution relative to the anchor instead of the current working directory.
///
/// ## Behavior Overview
/// - Treats `input` as if rooted under `anchor` (strips root/prefix markers from `input`)
/// - Expands symlinks as encountered (component-by-component), applying `..` after expansion
/// - Clamps lexical `..` to the `anchor` boundary — unless an absolute symlink target
///   is followed, in which case the symlink is followed to its actual target
/// - Bounded symlink following with cycle-defense, consistent with `MAX_SYMLINK_DEPTH`
/// - Mirrors input validations from `soft_canonicalize` (null-byte checks, Windows ADS layout)
///
/// ## Features
/// - **Anchored resolution**: Interprets paths relative to a specific anchor directory
/// - **Symlink canonicalization**: Follows symlinks to their actual targets (including absolute ones)
/// - **Input validation**: Rejects null bytes, malformed UNC paths, and empty paths
/// - **Cycle detection**: Prevents infinite symlink loops with configurable depth limits
///
/// ## Use Cases
/// - **Virtual filesystem implementations**: Provides correct symlink resolution behavior
///   when operating within virtual/constrained directory spaces
/// - **Containerized environments**: Ensures symlinks resolve properly relative to a virtual root
/// - **Chroot-like scenarios**: Maintains correct path semantics within bounded directory trees
/// - **Build systems**: Resolving paths relative to project roots with proper symlink handling
/// - **Applications needing anchor-relative interpretation**: Consistent path resolution
///   relative to a base directory while preserving symlink semantics
/// - **Path sandboxing**: Building higher-level path processing APIs with controlled resolution scope
///
/// ## Notes
/// - The `anchor` is canonicalized (soft) first; the result is absolute
/// - For fully-existing final paths, this typically matches `std::fs::canonicalize` of the
///   resolved path; however, semantics differ because `input` is interpreted relative to `anchor`
/// - Enable with `--features anchored` (optional feature to keep core library lightweight)
///
/// ## Example
/// ```
/// use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
/// use std::fs;
///
/// # fn demo() -> Result<(), std::io::Error> {
/// let anchor = std::env::temp_dir().join("sc_anchor_demo").join("root");
/// fs::create_dir_all(&anchor)?;
///
/// let base = soft_canonicalize(&anchor)?;
/// let out = anchored_canonicalize(&base, "/etc/passwd")?;
/// assert_eq!(out, base.join("etc").join("passwd"));
/// # Ok(())
/// # }
/// # demo().unwrap();
/// ```
#[cfg(feature = "anchored")]
#[cfg_attr(docsrs, doc(cfg(feature = "anchored")))]
pub fn anchored_canonicalize(
    anchor: impl AsRef<Path>,
    input: impl AsRef<Path>,
) -> io::Result<PathBuf> {
    let anchor = anchor.as_ref();
    let input = input.as_ref();

    // Basic input validation (empty paths)
    if anchor.as_os_str().is_empty() {
        return Err(error_with_path(
            io::ErrorKind::NotFound,
            anchor,
            "anchor path is empty",
        ));
    }

    // Reject NULs (platform-specific)
    reject_nul_bytes(anchor)?;
    reject_nul_bytes(input)?;

    // Windows-only: reject incomplete UNC anchors early
    #[cfg(windows)]
    {
        if is_incomplete_unc(anchor) {
            return Err(error_with_path(
                io::ErrorKind::InvalidInput,
                anchor,
                "invalid UNC path: missing share",
            ));
        }
    }

    // Canonicalize anchor (soft) to get absolute, platform-correct base even if parts don't exist.
    let mut base = soft_canonicalize(anchor)?;

    // Early ADS validation on the combined textual intent (defense-in-depth)
    #[cfg(windows)]
    validate_windows_ads_layout(&base.join(input))?;

    // Strip root/prefix markers from `input`: iterate only Normal/CurDir/ParentDir components.
    // Feed components through a work queue so we can push symlink targets back in if needed.
    let mut queue: std::collections::VecDeque<std::ffi::OsString> =
        std::collections::VecDeque::new();
    for comp in input.components() {
        use std::path::Component;
        match comp {
            Component::Normal(s) => queue.push_back(s.to_os_string()),
            Component::CurDir => queue.push_back(std::ffi::OsString::from(".")),
            Component::ParentDir => queue.push_back(std::ffi::OsString::from("..")),
            Component::RootDir | Component::Prefix(_) => {
                // Strip root/prefix per spec; do not push
            }
        }
    }

    // Clamp floor: never pop below the canonicalized anchor unless an absolute symlink target is followed.
    let anchor_floor = base.clone();
    let mut clamp_enabled = true;

    // Symlink cycles and hop limits are enforced via shared helper used below.

    while let Some(seg) = queue.pop_front() {
        if seg == std::ffi::OsStr::new(".") {
            continue;
        }
        if seg == std::ffi::OsStr::new("..") {
            if clamp_enabled {
                if base != anchor_floor && base.starts_with(&anchor_floor) {
                    let _ = base.pop();
                }
            } else {
                let _ = base.pop();
            }
            continue;
        }

        // Normal segment: append and then resolve symlinks at this point, chain-aware.
        base.push(&seg);

        // Resolve symlink chain at `base` via shared helper; enforce clamp semantics
        if let Ok(meta) = fs::symlink_metadata(&base) {
            if meta.file_type().is_symlink() {
                // Inspect the first hop to decide escape behavior
                let first_target = fs::read_link(&base)?;
                let absolute_first = first_target.is_absolute();

                // Use common symlink resolver to inherit security policies
                let resolved = crate::symlink::resolve_simple_symlink_chain(&base)?;
                base = resolved;

                if absolute_first {
                    // Absolute symlink escape: drop clamp per spec
                    clamp_enabled = false;
                } else if clamp_enabled {
                    // Relative symlink: do not allow escape beyond anchor floor
                    if !base.starts_with(&anchor_floor) {
                        base = anchor_floor.clone();
                    }
                }
            }
        }
    }

    // LATE Windows ADS validation
    #[cfg(windows)]
    validate_windows_ads_layout(&base)?;

    // Ensure Windows extended-length normalization for absolute results
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        if let Some(Component::Prefix(pr)) = base.components().next() {
            match pr.kind() {
                Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => {}
                Prefix::Disk(_) | Prefix::UNC(_, _) => {
                    base = ensure_windows_extended_prefix(&base);
                }
                Prefix::DeviceNS(_) => {}
            }
        }
    }

    Ok(base)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "anchored")]
    mod anchored_canonicalize;
    #[cfg(feature = "anchored")]
    mod anchored_security;
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
