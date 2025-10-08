//! # soft-canonicalize
//!
//! **Path canonicalization that works with non-existing paths.**
//!
//! Rust implementation inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`, providing
//! the same functionality as Unix `realpath()` and `std::fs::canonicalize` but extended to handle
//! non-existing paths, with optional features for simplified Windows output (`dunce`) and virtual
//! filesystem semantics (`anchored`).
//!
//! ## Why Use This?
//!
//! - **🚀 Works with non-existing paths** - Plan file locations before creating them
//! - **⚡ Fast** - Optimized performance with minimal allocations and syscalls
//! - **✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths
//! - **🔒 Robust** - 436 comprehensive tests covering edge cases and security scenarios
//! - **🛡️ Safe traversal** - Proper `..` and symlink resolution with cycle detection
//! - **🌍 Cross-platform** - Windows, macOS, Linux with comprehensive UNC/symlink handling
//! - **🔧 Zero dependencies** - Optional features may add dependencies
//!
//! ## Quick Start
//!
//! ```toml
//! [dependencies]
//! soft-canonicalize = "0.4"
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
//! soft-canonicalize = { version = "0.4", features = ["anchored"] }
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
//! > **Windows-specific feature**: The `dunce` feature only affects Windows platforms. On
//! > Unix/Linux/macOS, it has no effect and adds no runtime dependencies (configured as a
//! > target-conditional dependency in `Cargo.toml`).
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
//! soft-canonicalize = { version = "0.4", features = ["dunce"] }
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
//! All security validations remain unchanged - only the final output format is simplified when
//! possible.
//!
//! ## Cross-Platform Notes
//!
//! - Windows: returns extended-length verbatim paths for absolute results (`\\?\C:\…`, `\\?\UNC\…`)
//!   - With `dunce` feature: returns simplified paths (`C:\…`) when safe
//! - Unix-like systems: standard absolute and relative path semantics
//! - UNC floors and device namespaces are preserved and respected
//!
//! ## Testing
//!
//! 436 tests including:
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

use std::io;
use std::path::{Path, PathBuf};

// When dunce feature is enabled AND on Windows, use dunce::canonicalize which simplifies paths
// Otherwise use std::fs::canonicalize
#[cfg(all(feature = "dunce", windows))]
use dunce::canonicalize as fs_canonicalize;
#[cfg(not(all(feature = "dunce", windows)))]
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

    // Stage 3: fast-path — try fs::canonicalize on the lexically-normalized path as well
    if normalized_path != absolute_path {
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

/// Canonicalize a user-provided path relative to an anchor directory, with virtual filesystem semantics.
///
/// This function resolves paths **as if rooted under a given anchor**, performing canonical path
/// resolution relative to the anchor instead of the current working directory. All paths, including
/// absolute symlink targets, are clamped to the anchor, implementing true virtual filesystem behavior.
///
/// ## Behavior Overview
/// - Treats `input` as if rooted under `anchor` (strips root/prefix markers from `input`)
/// - Expands symlinks as encountered (component-by-component), applying `..` after expansion
/// - **Clamps ALL paths to the `anchor` boundary**, including:
///   - Lexical `..` traversal in user input
///   - **All absolute symlink targets** (both within and outside anchor - see below)
///   - Chained symlinks with mixed absolute and relative targets
/// - Bounded symlink following with cycle-defense, consistent with `MAX_SYMLINK_DEPTH`
/// - Mirrors input validations from `soft_canonicalize` (null-byte checks, Windows ADS layout)
///
/// ## Absolute Symlink Clamping (Critical Behavior)
///
/// When a symlink points to an absolute path, it is **always clamped to the anchor**,
/// implementing true virtual filesystem semantics. This happens in two cases:
///
/// **Case 1: Symlink within anchor** (host-style path)
/// - Example: Symlink `/tmp/anchor/link` → `/tmp/anchor/docs/file`
/// - The target already expresses the full host path including the anchor
/// - Process: Strip anchor prefix, then rejoin to anchor
/// - Result: `/tmp/anchor/docs/file` (stays within anchor)
///
/// **Case 2: Symlink outside anchor** (virtual-style path)
/// - Example: Symlink `/tmp/anchor/link` → `/etc/passwd`
/// - The target is an absolute path outside the anchor
/// - Process: Strip root prefix (`/`), then join to anchor
/// - Result: `/tmp/anchor/etc/passwd` (clamped to anchor)
///
/// In both cases, the anchor acts as a **virtual root** (`/`), similar to chroot behavior.
/// This ensures symlinks cannot escape the anchor boundary, regardless of where they point.
///
/// ## Features
/// - **Anchored resolution**: Interprets paths relative to a specific anchor directory
/// - **Virtual filesystem semantics**: Clamps all absolute paths (including symlink targets) to anchor
/// - **Symlink canonicalization**: Follows symlink chains with clamping at each step
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
/// ## Output Format
///
/// The output format follows the same rules as [`soft_canonicalize`]:
/// - **Without `dunce` feature (default)**: Windows returns extended-length UNC paths (`\\?\C:\foo`)
/// - **With `dunce` feature enabled**: Windows returns simplified paths (`C:\foo`) when safe
/// - Unix systems always return standard absolute paths
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
///
/// // Absolute input paths are clamped to anchor
/// let out = anchored_canonicalize(&base, "/etc/passwd")?;
/// assert_eq!(out, base.join("etc").join("passwd"));
///
/// // Lexical .. traversal is also clamped
/// let out2 = anchored_canonicalize(&base, "../../../etc/passwd")?;
/// assert_eq!(out2, base.join("etc").join("passwd"));
/// # Ok(())
/// # }
/// # demo().unwrap();
/// ```
///
/// ## Symlink Clamping Example
/// ```
/// # #[cfg(unix)]
/// # fn demo() -> Result<(), std::io::Error> {
/// use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
/// use std::os::unix::fs::symlink;
/// use std::fs;
///
/// let anchor = std::env::temp_dir().join("sc_symlink_demo2").join("root");
/// fs::create_dir_all(&anchor)?;
/// let base = soft_canonicalize(&anchor)?;
///
/// // Create a symlink pointing to absolute path outside anchor
/// let external_path = std::env::temp_dir().join("external_data2");
/// fs::create_dir_all(&external_path)?;
/// let link_path = base.join("mylink");
/// let _ = fs::remove_file(&link_path); // Clean up if exists
/// symlink(&external_path, &link_path)?;
///
/// // The absolute symlink target is CLAMPED to the anchor
/// let result = anchored_canonicalize(&base, "mylink")?;
/// // Result stays within anchor (virtual filesystem semantics)
/// assert!(result.starts_with(&base));
/// # Ok(())
/// # }
/// # #[cfg(unix)]
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

    // Clamp floor: all paths (including symlink targets) stay within the anchor.
    let anchor_floor = base.clone();

    // Process components directly without a queue - simpler and more efficient
    for comp in input.components() {
        use std::path::Component;
        match comp {
            Component::Normal(seg) => {
                base.push(seg);

                // Resolve symlink chain at `base` using anchor-aware resolver
                if let Ok(meta) = std::fs::symlink_metadata(&base) {
                    if meta.file_type().is_symlink() {
                        // Use anchored symlink resolver that implements virtual filesystem semantics
                        let resolved =
                            crate::symlink::resolve_anchored_symlink_chain(&base, &anchor_floor)?;

                        // Final safety check: ensure resolved path is within anchor
                        if !resolved.starts_with(&anchor_floor) {
                            // Virtual filesystem semantics: reinterpret escaped path as relative to anchor
                            // Find common ancestor and preserve relative path structure
                            // Example: resolved = /tmp/xyz/opt/file, anchor = /tmp/xyz/home/jail
                            // Common ancestor: /tmp/xyz
                            // Resolved relative to common: opt/file
                            // Result: /tmp/xyz/home/jail/opt/file

                            // Find longest common prefix by comparing components
                            let mut common_depth = 0;
                            let anchor_comps: Vec<_> = anchor_floor.components().collect();
                            let resolved_comps: Vec<_> = resolved.components().collect();
                            for (a, r) in anchor_comps.iter().zip(resolved_comps.iter()) {
                                if a == r {
                                    common_depth += 1;
                                } else {
                                    break;
                                }
                            }

                            // Build clamped path: anchor + (resolved components after common prefix)
                            base = anchor_floor.clone();
                            for comp in resolved_comps.iter().skip(common_depth) {
                                base.push(comp);
                            }
                        } else {
                            base = resolved;
                        }
                    }
                }
            }
            Component::ParentDir => {
                // Clamp ".." to anchor boundary
                if base != anchor_floor && base.starts_with(&anchor_floor) {
                    let _ = base.pop();
                }
            }
            Component::CurDir => {
                // Skip "." - no-op
            }
            Component::RootDir | Component::Prefix(_) => {
                // Strip root/prefix per spec; do not process
            }
        }
    }

    // LATE Windows ADS validation
    #[cfg(windows)]
    validate_windows_ads_layout(&base)?;

    // Ensure Windows extended-length normalization for absolute results
    // We always add \\?\ for robustness, then let dunce decide whether to strip it (if enabled)
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

    // Optional: dunce feature - simplify UNC paths to legacy format when safe
    // dunce::simplified() intelligently strips \\?\ only when safe (no reserved names,
    // path length ok, no .., etc.). It performs no I/O and handles non-existing paths correctly.
    #[cfg(all(feature = "dunce", windows))]
    {
        base = dunce::simplified(&base).to_path_buf();
    }

    Ok(base)
}

#[cfg(test)]
mod tests {
    // Test utilities for feature-conditional assertions
    mod test_utils;

    #[cfg(feature = "anchored")]
    mod anchored_canonicalize;
    #[cfg(feature = "anchored")]
    mod anchored_security;
    #[cfg(feature = "anchored")]
    mod anchored_symlink_clamping;
    mod api_compatibility;
    mod basic_functionality;
    mod cve_2024_2025_security;
    mod cve_tests;
    mod edge_case_robustness;
    mod edge_cases;
    mod exotic_edge_cases;
    mod format_verification;
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
    #[cfg(windows)]
    mod windows_path_stripping;

    // dunce feature test suite (Windows-only)
    #[cfg(all(feature = "dunce", windows))]
    mod dunce_feature;
}
