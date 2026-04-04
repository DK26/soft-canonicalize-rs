//! # soft-canonicalize
//!
//! **Path canonicalization that works with non-existing paths.**
//!
//! Rust implementation inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`, providing
//! the same functionality as `std::fs::canonicalize` (Rust's equivalent to Unix `realpath()`)
//! but extended to handle non-existing paths, with optional features for simplified Windows
//! output (`dunce`) and virtual filesystem semantics (`anchored`).
//!
//! ## Why Use This?
//!
//! - **🚀 Works with non-existing paths** - Plan file locations before creating them
//! - **⚡ Fast** - Optimized performance with minimal allocations and syscalls
//! - **✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths, with optional UNC simplification via `dunce` feature (Windows)
//! - **🎯 Virtual filesystem support** - Optional `anchored` feature for bounded canonicalization within directory boundaries
//! - **🔒 Robust** - 530+ comprehensive tests covering edge cases and security scenarios
//! - **🛡️ Safe traversal** - Proper `..` and symlink resolution with cycle detection
//! - **🌍 Cross-platform** - Windows, macOS, Linux with comprehensive UNC/symlink handling
//! - **💾 Exotic filesystem support** - Works on RAM disks, network drives, Docker volumes, and other non-standard filesystems
//! - **🔧 Zero dependencies** - Optional features may add minimal dependencies
//!
//! ## Lexical vs. Filesystem-Based Resolution
//!
//! Path resolution libraries fall into two categories:
//!
//! **Lexical Resolution** (no I/O):
//! - **Performance**: Fast - no filesystem access
//! - **Accuracy**: Incorrect if symlinks are present (doesn't resolve them)
//! - **Use when**: You're 100% certain no symlinks exist and need maximum performance
//! - **Examples**: `std::path::absolute`, `normpath::normalize`
//!
//! **Filesystem-Based Resolution** (performs I/O):
//! - **Performance**: Slower - requires filesystem syscalls to resolve symlinks
//! - **Accuracy**: Correct - follows symlinks to their targets
//! - **Use when**: Safety is priority over performance, or symlinks may be present
//! - **Examples**: `std::fs::canonicalize`, `soft_canonicalize`, `dunce::canonicalize`
//!
//! **Rule of thumb**: If you cannot guarantee symlinks won't be introduced, or if correctness is critical, use filesystem-based resolution.
//!
//! ## Use Cases
//!
//! ### Path Comparison
//!
//! - **Equality**: Determine if two different path strings point to the same location
//! - **Containment**: Check if one path is inside another directory
//!
//! ### Common Applications
//!
//! - **Build Systems**: Resolve output paths during build planning before directories exist
//! - **Configuration Validation**: Ensure user-provided paths stay within allowed boundaries
//! - **Deduplication**: Detect when different path strings refer to the same planned location
//! - **Cross-Platform Normalization**: Handle Windows UNC paths and symlinks consistently
//!
//! ## Quick Start
//!
//! ```toml
//! [dependencies]
//! soft-canonicalize = "0.5"
//! ```
//!
//! ### Basic Example
//!
//! ```rust
//! # #[cfg(windows)]
//! # {
//! use soft_canonicalize::soft_canonicalize;
//!
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
//! # #[cfg(not(feature = "dunce"))]
//! assert_eq!(
//!     result.unwrap().to_string_lossy(),
//!     r"\\?\C:\Users\user\non\existing\config.json"
//! );
//!
//! // With `dunce` feature enabled, paths are simplified when safe
//! # #[cfg(feature = "dunce")]
//! assert_eq!(
//!     result.unwrap().to_string_lossy(),
//!     r"C:\Users\user\non\existing\config.json"
//! );
//! # }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! ## Optional Features
//!
//! ### Anchored Canonicalization (`anchored` feature)
//!
//! For **correct symlink resolution within virtual/constrained directory spaces**, use
//! `anchored_canonicalize`. This function implements true virtual filesystem semantics by
//! clamping ALL paths (including absolute symlink targets) to the anchor directory:
//!
//! ```toml
//! [dependencies]
//! soft-canonicalize = { version = "0.5", features = ["anchored"] }
//! ```
//!
//! ```rust
//! # #[cfg(feature = "anchored")]
//! use soft_canonicalize::anchored_canonicalize;
//! # #[cfg(not(feature = "anchored"))]
//! # use soft_canonicalize::soft_canonicalize;
//! use std::fs;
//!
//! # fn example() -> Result<(), std::io::Error> {
//! // Set up an anchor/root directory (no need to pre-canonicalize)
//! let anchor = std::env::temp_dir().join("workspace_root");
//! fs::create_dir_all(&anchor)?;
//!
//! // Canonicalize paths relative to the anchor (anchor is soft-canonicalized internally)
//! # #[cfg(feature = "anchored")]
//! let resolved_path = anchored_canonicalize(&anchor, "../../../etc/passwd")?;
//! # #[cfg(not(feature = "anchored"))]
//! # { let _ = (&anchor, "../../../etc/passwd"); }
//! // Result: /tmp/workspace_root/etc/passwd (lexical .. clamped to anchor)
//!
//! // Absolute symlinks are also clamped to the anchor
//! // If there's a symlink: workspace_root/config -> /etc/config
//! // It resolves to: workspace_root/etc/config (clamped to anchor)
//! # #[cfg(feature = "anchored")]
//! let symlink_path = anchored_canonicalize(&anchor, "config")?;
//! # #[cfg(not(feature = "anchored"))]
//! # { let _ = "config"; }
//! // Safe: always stays within workspace_root, even if symlink points to /etc/config
//! # Ok(())
//! # }
//! ```
//!
//! **Key features:**
//! - Virtual filesystem semantics: All absolute paths (including symlink targets) are clamped to anchor
//! - Anchor-relative canonicalization: Resolves paths relative to a specific anchor directory
//! - Complete symlink clamping: Follows symlink chains with clamping at each step
//! - Component-by-component: Processes path components in proper order
//! - Absolute results: Always returns absolute canonical paths within the anchor boundary
//!
//! **For a complete multi-tenant security example**, run:
//! ```bash
//! cargo run --example virtual_filesystem_demo --features anchored
//! ```
//!
//! ### Simplified Path Output (`dunce` feature, Windows-only)
//!
//! By default, `soft_canonicalize` returns Windows paths in extended-length UNC format
//! (`\\?\C:\foo`) for maximum robustness and compatibility with long paths, reserved names,
//! and other Windows filesystem edge cases.
//!
//! If you need simplified paths (`C:\foo`) for compatibility with legacy applications or
//! user-facing output, enable the **`dunce` feature**:
//!
//! ```toml
//! [dependencies]
//! soft-canonicalize = { version = "0.5", features = ["dunce"] }
//! ```
//!
//! **Example:**
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//! # fn example() -> Result<(), std::io::Error> {
//! # #[cfg(windows)]
//! # {
//! let path = soft_canonicalize(r"C:\Users\user\documents\..\config.json")?;
//!
//! // Without dunce feature (default):
//! // Returns: \\?\C:\Users\user\config.json (extended-length UNC)
//!
//! // With dunce feature enabled:
//! // Returns: C:\Users\user\config.json (simplified when safe)
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! **When to use:**
//! - ✅ Legacy applications that don't support UNC paths
//! - ✅ User-facing output requiring familiar path format
//! - ✅ Tools expecting traditional Windows path format
//!
//! **How it works:**
//!
//! The [dunce](https://crates.io/crates/dunce) crate intelligently simplifies Windows UNC paths
//! (`\\?\C:\foo` → `C:\foo`) **only when safe**:
//! - Automatically keeps UNC for paths >260 chars
//! - Automatically keeps UNC for reserved names (CON, PRN, NUL, COM1-9, LPT1-9)
//! - Automatically keeps UNC for paths with trailing spaces/dots
//! - Automatically keeps UNC for paths containing `..` (literal interpretation)
//!
//! ## When Paths Must Exist: `proc-canonicalize`
//!
//! Since v0.5.0, `soft_canonicalize` uses [`proc-canonicalize`](https://crates.io/crates/proc-canonicalize)
//! by default for existing-path canonicalization instead of `std::fs::canonicalize`. This fixes a
//! critical issue with Linux namespace boundaries.
//!
//! **The Problem**: On Linux, `std::fs::canonicalize` resolves "magic symlinks" like `/proc/PID/root`
//! to their targets, losing the namespace boundary:
//!
//! ```rust
//! # #[cfg(all(target_os = "linux", feature = "proc-canonicalize"))]
//! # fn main() -> std::io::Result<()> {
//! // /proc/self/root is a "magic symlink" pointing to the current process's root filesystem
//! // std::fs::canonicalize incorrectly resolves it to "/"
//! let std_result = std::fs::canonicalize("/proc/self/root")?;
//! assert_eq!(std_result.to_string_lossy(), "/"); // Wrong! Namespace boundary lost
//!
//! // proc_canonicalize preserves the namespace boundary
//! let proc_result = proc_canonicalize::canonicalize("/proc/self/root")?;
//! assert_eq!(proc_result.to_string_lossy(), "/proc/self/root"); // Correct!
//! # Ok(())
//! # }
//! # #[cfg(not(all(target_os = "linux", feature = "proc-canonicalize")))]
//! # fn main() {}
//! ```
//!
//! **Recommendation**: If you need to canonicalize paths that **must exist** (and would previously
//! use `std::fs::canonicalize`), use `proc_canonicalize::canonicalize` for correct Linux namespace
//! handling:
//!
//! ```toml
//! [dependencies]
//! proc-canonicalize = "0.0"
//! ```
//!
//! ## Security & CVE Coverage
//!
//! Security does not depend on enabling features. The core API is secure-by-default; the optional
//! `anchored` feature is a convenience for virtual roots. We test all modes (no features;
//! `--features anchored`; `--features anchored,dunce`).
//!
//! **Built-in protections include:**
//! - **NTFS Alternate Data Stream (ADS) validation** - Blocks malicious stream placements and traversal attempts
//! - **Symlink cycle detection** - Bounded depth tracking prevents infinite loops
//! - **Path traversal clamping** - Never ascends past root/share/device boundaries
//! - **Null byte rejection** - Early validation prevents injection attacks
//! - **UNC/device semantics** - Preserves Windows extended-length and device namespace integrity
//! - **TOCTOU race resistance** - Tested against time-of-check-time-of-use attacks
//!
//! See [`docs/SECURITY.md`](https://github.com/DK26/soft-canonicalize-rs/blob/dev/docs/SECURITY.md)
//! for detailed analysis, attack scenarios, and test references.
//!
//! ## Cross-Platform Notes
//!
//! - Windows: returns extended-length verbatim paths for absolute results (`\\?\C:\…`, `\\?\UNC\…`)
//!   - With `dunce` feature: returns simplified paths (`C:\…`) when safe
//! - Unix-like systems: standard absolute and relative path semantics
//! - UNC floors and device namespaces are preserved and respected
//!
//! ### Exotic Filesystem Support
//!
//! Unlike pure `std::fs::canonicalize`, this crate gracefully handles paths on filesystems where
//! canonicalization may fail unexpectedly ([rust-lang/rust#45067], [rust-lang/rust#48249], etc.):
//!
//! - **RAM disks** (ImDisk, etc.): Common issue where `std::fs::canonicalize` returns `os error 1`
//! - **Network drives**: May return `os error 1` (Incorrect function)
//! - **Docker volumes**: Container paths that fail standard canonicalization
//! - **Non-native filesystems**: Ext4 via Ext2Fsd on Windows, etc.
//!
//! When `std::fs::canonicalize` fails on these filesystems, we fall back to our prefix-discovery
//! logic, still resolving symlinks where possible while handling the non-existing suffix correctly.
//!
//! [rust-lang/rust#45067]: https://github.com/rust-lang/rust/issues/45067
//! [rust-lang/rust#48249]: https://github.com/rust-lang/rust/issues/48249
//!
//! ## Testing
//!
//! 530+ tests including:
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
//!
//! ## How It Works
//!
//! For those interested in the implementation details, here's how `soft_canonicalize` processes paths:
//!
//! 1. Input validation (empty path, platform pre-checks)
//! 2. Convert to absolute path (preserving drive/root semantics)
//! 3. Fast-path: try `fs::canonicalize` on the original absolute path
//! 4. Lexically normalize `.` and `..` (fast-path optimization for whole-path existence check)
//! 5. Fast-path: try `fs::canonicalize` on the normalized path when different
//! 6. Validate null bytes (platform-specific)
//! 7. Discover deepest existing prefix with **symlink-first** semantics: resolve symlinks incrementally, then process `.` and `..` relative to resolved targets
//! 8. Optionally canonicalize the anchor (if symlinks seen) and rebuild
//! 9. Append non-existing suffix lexically, then normalize if needed
//! 10. Windows: ensure extended-length prefix for absolute paths
//! 11. Optional: simplify Windows paths when `dunce` feature enabled

#[cfg(feature = "anchored")]
mod anchored;
mod error;
mod normalize;
mod prefix;
mod symlink;
#[cfg(windows)]
mod windows;

#[cfg(feature = "anchored")]
pub use anchored::anchored_canonicalize;
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

use std::io;
use std::path::{Path, PathBuf};

// Canonicalization backend selection (priority order):
// 1. proc-canonicalize feature (default): fixes Linux /proc/PID/root magic symlinks,
//    and delegates to dunce when both features are enabled
// 2. dunce feature on Windows (without proc-canonicalize): uses dunce::canonicalize
// 3. fallback: uses std::fs::canonicalize
#[cfg(feature = "proc-canonicalize")]
use proc_canonicalize::canonicalize as fs_canonicalize;

#[cfg(all(not(feature = "proc-canonicalize"), feature = "dunce", windows))]
use dunce::canonicalize as fs_canonicalize;

#[cfg(all(
    not(feature = "proc-canonicalize"),
    not(all(feature = "dunce", windows))
))]
use std::fs::canonicalize as fs_canonicalize;

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
        p.as_os_str().encode_wide().any(|u| u == 0)
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Fallback for other platforms
        return false;
    }
}

#[inline]
pub(crate) fn reject_nul_bytes(p: &Path) -> io::Result<()> {
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
///
/// # Output Format
///
/// **Without `dunce` feature (default):**
/// - Windows: Returns extended-length UNC paths (`\\?\C:\foo`) for maximum robustness
/// - Unix: Returns standard absolute paths (`/foo`)
///
/// **With `dunce` feature enabled:**
/// - Windows: Returns simplified paths (`C:\foo`) when safe to do so
/// - Unix: Returns standard absolute paths (`/foo`) - no change
///
/// See the [module documentation](crate#optional-features) for details on the `dunce` feature.
#[must_use = "this function returns a new PathBuf without modifying the input"]
#[doc(alias = "realpath")]
#[doc(alias = "canonicalize")]
#[doc(alias = "resolve")]
#[doc(alias = "absolute")]
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
    match fs_canonicalize(&absolute_path) {
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

    // Stage 3: fast-path — try fs::canonicalize on the lexically-normalized path as well.
    // SAFETY: Skip when the original path contains ".." components. Lexical normalization
    // collapses "symlink/.." without following the symlink, which can resolve to a completely
    // different (wrong) existing path. The slow path (Stages 4-7) handles ".." correctly by
    // resolving symlinks before climbing. See: https://github.com/DK26/soft-canonicalize-rs/issues/53
    let has_parent_dir = absolute_path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));
    if normalized_path != absolute_path && !has_parent_dir {
        match fs_canonicalize(&normalized_path) {
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
            // Don't allocate new OsStrings for . and .. - we'll handle them specially
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
            if let Ok(canon_anchor) = fs_canonicalize(anchor) {
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
            if let Ok(canon_base) = fs_canonicalize(&base) {
                base = canon_base;
            }
        }
    }

    let mut result = base;

    // Stage 7: append the non-existing suffix components (purely lexical)
    let mut suffix_has_dot_or_dotdot = false;
    for component in components.iter().skip(existing_count) {
        // Use OsStr comparison instead of creating new OsStr instances
        if !suffix_has_dot_or_dotdot {
            let comp_str = component.as_os_str();
            if comp_str == "." || comp_str == ".." {
                suffix_has_dot_or_dotdot = true;
            }
        }
        result.push(component);
    }

    // After we have a fully-resolved base, normalize lexically.
    // Note: When dunce feature is enabled AND path is verbatim, skip normalization
    // so dunce can see the raw structure and make correct safety decisions
    #[cfg(windows)]
    {
        #[cfg(feature = "dunce")]
        {
            use std::path::{Component, Prefix};
            let should_normalize = !matches!(
                result.components().next(),
                Some(Component::Prefix(p)) if matches!(
                    p.kind(),
                    Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _)
                )
            );
            if should_normalize {
                result = simple_normalize_path(&result);
            }
        }
        #[cfg(not(feature = "dunce"))]
        {
            result = simple_normalize_path(&result);
        }
    }
    #[cfg(not(windows))]
    {
        if suffix_has_dot_or_dotdot {
            result = simple_normalize_path(&result);
        }
    }

    // Stage 8 (Windows): ensure extended-length prefix for absolute paths
    // We always add \\?\ for robustness, then let dunce decide whether to strip it (if enabled)
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

    // Stage 9 (Optional): dunce feature - simplify paths to legacy format when safe
    // dunce::simplified() intelligently strips \\?\ only when safe (no reserved names,
    // path length ok, no .., etc.). It performs no I/O and handles non-existing paths correctly.
    #[cfg(all(feature = "dunce", windows))]
    {
        result = dunce::simplified(&result).to_path_buf();
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    // Test utilities for feature-conditional assertions
    mod test_utils;

    #[cfg(feature = "anchored")]
    mod anchored_canonicalize;
    #[cfg(feature = "anchored")]
    mod anchored_relative_symlink_clamping;
    #[cfg(feature = "anchored")]
    mod anchored_security;
    #[cfg(feature = "anchored")]
    mod anchored_symlink_clamping;
    mod api_compatibility;
    mod basic_functionality;
    mod cve_tests;
    mod cve_traversal_attacks;
    mod cve_windows_attacks;
    mod edge_case_robustness;
    mod edge_cases;
    mod exotic_cross_platform;
    mod exotic_windows;
    mod format_verification;
    mod optimization;
    mod path_traversal;
    mod platform_linux_and_anchored;
    mod platform_windows;
    mod python_inspired_tests;
    mod python_lessons;
    mod security_audit;
    mod short_filename_detection;
    mod std_behavior;
    mod symlink_depth;
    mod symlink_dotdot_resolution_order;
    mod symlink_dotdot_symlink_first;
    #[cfg(windows)]
    mod windows_path_stripping;

    // dunce feature test suite (Windows-only)
    #[cfg(all(feature = "dunce", windows))]
    mod dunce_feature;
}
