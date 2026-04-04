use std::io;
use std::path::{Path, PathBuf};

use crate::error::error_with_path;
#[cfg(windows)]
use crate::windows::{
    ensure_windows_extended_prefix, is_incomplete_unc, validate_windows_ads_layout,
};

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
/// The output format follows the same rules as [`soft_canonicalize`](crate::soft_canonicalize):
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
/// // Create a symlink pointing to an absolute path outside the anchor
/// let link_path = base.join("mylink");
/// let _ = fs::remove_file(&link_path); // Clean up if exists
/// symlink("/etc/passwd", &link_path)?;
///
/// // The absolute symlink target is CLAMPED to the anchor:
/// // /etc/passwd → strip root → etc/passwd → join anchor → base/etc/passwd
/// let result = anchored_canonicalize(&base, "mylink")?;
/// assert_eq!(result, base.join("etc").join("passwd"));
/// # Ok(())
/// # }
/// # #[cfg(unix)]
/// # demo().unwrap();
/// ```
#[must_use = "this function returns a new PathBuf without modifying the input"]
#[doc(alias = "chroot")]
#[doc(alias = "jail")]
#[doc(alias = "sandbox")]
#[doc(alias = "virtual_root")]
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
    crate::reject_nul_bytes(anchor)?;
    crate::reject_nul_bytes(input)?;

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

    // On Windows, treat drive-relative anchors (e.g., "C:dir") as absolute anchors ("C:\\dir").
    // Anchors act as virtual roots and should not depend on the process's per-drive cwd.
    #[cfg(windows)]
    let anchor = {
        use std::path::{Component, Prefix};
        let mut comps = anchor.components();
        match comps.next() {
            Some(Component::Prefix(pr)) => match pr.kind() {
                Prefix::Disk(drive) => {
                    let mut rest = comps.clone();
                    let is_absolute = matches!(rest.next(), Some(Component::RootDir));
                    if is_absolute {
                        anchor.to_path_buf()
                    } else {
                        // Synthesize absolute from drive-relative: "C:\\" + remaining components
                        let mut out = PathBuf::from(format!("{}:\\", drive as char));
                        for c in comps {
                            out.push(c.as_os_str());
                        }
                        out
                    }
                }
                _ => anchor.to_path_buf(),
            },
            _ => anchor.to_path_buf(),
        }
    };

    // Canonicalize anchor (soft) to get absolute, platform-correct base even if parts don't exist.
    let mut base = crate::soft_canonicalize(anchor)?;

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
