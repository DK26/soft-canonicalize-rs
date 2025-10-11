use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::error::error_with_path;
use crate::normalize::simple_normalize_path;

/// Maximum number of symlinks to follow before giving up.
/// This matches the behavior of std::fs::canonicalize and OS limits:
/// - Linux: ELOOP limit is typically 40
/// - Windows: Similar limit around 63
/// - Other Unix systems: Usually 32-40
#[doc(alias = "ELOOP")]
#[doc(alias = "symlink_limit")]
pub const MAX_SYMLINK_DEPTH: usize = if cfg!(target_os = "windows") { 63 } else { 40 };

/// Strip root prefix from an absolute path to make it relative.
///
/// This is used in anchored canonicalization to clamp absolute symlink targets
/// to the anchor directory, implementing virtual filesystem semantics.
///
/// # Examples
/// - Unix: `/etc/passwd` → `etc/passwd`
/// - Windows: `C:\Windows\System32` → `Windows\System32`
/// - Windows UNC: `\\server\share\path` → `path`
#[cfg(feature = "anchored")]
pub(crate) fn strip_root_prefix(path: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        path.strip_prefix("/").unwrap_or(path).to_path_buf()
    }

    #[cfg(windows)]
    {
        use std::path::Component;
        let mut result = PathBuf::new();

        for comp in path.components() {
            match comp {
                // Skip all prefix and root components
                Component::Prefix(_) | Component::RootDir => continue,
                // Keep all normal components
                _ => result.push(comp),
            }
        }

        // If result is empty, return current directory marker
        if result.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            result
        }
    }
}

/// Resolve a symlink chain with anchor clamping for absolute targets.
///
/// This resolver implements virtual filesystem semantics by clamping absolute symlink
/// targets to the anchor directory. When an absolute symlink is encountered, it's
/// reinterpreted as relative to the anchor, ensuring all paths stay within the
/// virtual filesystem boundary.
///
/// # Arguments
/// * `symlink_path` - The starting symlink path to resolve
/// * `anchor` - The anchor directory that serves as the virtual root
///
/// # Virtual Filesystem Semantics
/// - **All absolute symlink targets are clamped to the anchor** (virtual filesystem root)
/// - Relative symlink targets are resolved normally from the symlink's parent
/// - Symlink chains are followed recursively with the same clamping rules
/// - Cycle detection and depth limits prevent infinite loops
///
/// # Dual-Case Clamping Logic
///
/// When an absolute symlink target is encountered, it's handled in one of two ways:
///
/// **Case 1: Target already within anchor** (host-style absolute path)
/// ```text
/// // Symlink: /tmp/anchor/mylink -> /tmp/anchor/docs/file
/// // Anchor: /tmp/anchor
/// // Process: Strip anchor prefix → "docs/file" → Rejoin to anchor
/// // Result: /tmp/anchor/docs/file ✅ (stays within anchor)
/// ```
///
/// **Case 2: Target outside anchor** (virtual-style absolute path)
/// ```text
/// // Symlink: /tmp/anchor/mylink -> /etc/passwd
/// // Anchor: /tmp/anchor
/// // Process: Strip root prefix → "etc/passwd" → Join to anchor
/// // Result: /tmp/anchor/etc/passwd ✅ (clamped to anchor)
/// ```
///
/// Both cases ensure the final path stays within the anchor, implementing true
/// chroot-like behavior where the anchor is treated as the virtual root (`/`).
///
/// # Example
/// ```text
/// // Symlink: /anchor/mylink -> /etc/config
/// // Result: /anchor/etc/config (clamped to anchor)
/// let result = resolve_anchored_symlink_chain(&Path::new("/anchor/mylink"), &Path::new("/anchor"))?;
/// ```
#[cfg(feature = "anchored")]
pub(crate) fn resolve_anchored_symlink_chain(
    symlink_path: &Path,
    anchor: &Path,
) -> io::Result<PathBuf> {
    let mut current = symlink_path.to_path_buf();
    let mut depth = 0usize;
    let mut visited: Vec<std::ffi::OsString> = Vec::with_capacity(8);

    let effective_max_depth = if is_likely_system_symlink(&current) {
        5
    } else {
        MAX_SYMLINK_DEPTH
    };

    loop {
        // Detect cycles using the textual path (no extra IO)
        if visited.iter().any(|s| s == current.as_os_str()) {
            return Err(error_with_path(
                io::ErrorKind::InvalidInput,
                symlink_path,
                "Too many levels of symbolic links",
            ));
        }
        visited.push(current.as_os_str().to_os_string());

        match fs::read_link(&current) {
            Ok(target) => {
                depth += 1;
                if depth > effective_max_depth {
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        symlink_path,
                        "Too many levels of symbolic links",
                    ));
                }

                if target.is_absolute() {
                    // CLAMP: Convert absolute symlink target to be relative to anchor
                    // This implements virtual filesystem semantics

                    // On Windows, we DON'T canonicalize absolute symlink targets at all
                    // because canonicalization expands their full path, breaking the clamping logic.
                    // The target will be stripped and clamped as-is, which is correct for
                    // virtual filesystem semantics where we treat the symlink as if it were
                    // absolute within the virtual root (anchor).
                    //
                    // Note: This means symlink targets may contain 8.3 short names in the
                    // clamped result, but this is acceptable because:
                    // 1. The paths are still valid and accessible
                    // 2. Trying to expand them would require knowing the "virtual root" context
                    // 3. For relative symlinks, we handle 8.3 expansion separately
                    #[cfg(not(windows))]
                    let target = target.clone();

                    #[cfg(windows)]
                    let target = target.clone();

                    // Now strip the anchor prefix (for targets within anchor)
                    if let Ok(rel) = target.strip_prefix(anchor) {
                        // Target is already within anchor: /anchor/foo -> foo
                        // Rejoin to anchor to normalize: anchor/foo
                        current = anchor.join(rel);
                    } else {
                        // Target is outside anchor: strip root and clamp to anchor
                        // /etc/passwd -> anchor/etc/passwd
                        let stripped = strip_root_prefix(&target);
                        current = anchor.join(stripped);
                    }
                } else {
                    // Relative symlink: resolve from parent as normal
                    let parent = current.parent();
                    if let Some(p) = parent {
                        current = simple_normalize_path(&p.join(target));

                        // FIX: Re-canonicalize on Windows to ensure:
                        // 1. Prefix format consistency (\\?\ vs regular paths)
                        // 2. 8.3 short names are expanded to full names
                        // This is critical because simple_normalize_path only handles . and ..,
                        // but doesn't expand short names like RUNNER~1 -> runneradmin
                        #[cfg(windows)]
                        if current.exists() {
                            use std::path::Prefix;

                            // Check if anchor has extended-length prefix (\\?\)
                            let anchor_has_prefix = anchor.components().next().is_some_and(|c| {
                                matches!(c, std::path::Component::Prefix(p) if matches!(
                                    p.kind(),
                                    Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) | Prefix::Verbatim(_)
                                ))
                            });

                            // Check if current has extended-length prefix
                            let current_has_prefix = current.components().next().is_some_and(|c| {
                                matches!(c, std::path::Component::Prefix(p) if matches!(
                                    p.kind(),
                                    Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) | Prefix::Verbatim(_)
                                ))
                            });

                            // Only re-canonicalize if there's a prefix mismatch
                            // (anchor has \\?\ but current doesn't)
                            if anchor_has_prefix && !current_has_prefix {
                                // Re-canonicalize to ensure matching prefix format and expand 8.3 names
                                if let Ok(canonicalized) = std::fs::canonicalize(&current) {
                                    current = canonicalized;
                                }
                                // If canonicalization fails, continue with current path;
                                // starts_with may still work
                            }
                        }
                    } else {
                        current = target.clone();
                    }
                }
            }
            Err(_e) => {
                break; // not a symlink or cannot read; stop here
            }
        }
    }

    Ok(current)
}

/// Resolve a symlink chain using read_link only (no extra metadata calls).
/// Notes:
/// - Uses a visited set on textual paths to detect cycles without extra IO
/// - Caps depth at MAX_SYMLINK_DEPTH (or a smaller heuristic for common system symlinks)
/// - Re-resolves relative symlink targets against the parent of the current link
#[inline]
pub(crate) fn resolve_simple_symlink_chain(symlink_path: &Path) -> io::Result<PathBuf> {
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
            return Err(error_with_path(
                io::ErrorKind::InvalidInput,
                symlink_path,
                "Too many levels of symbolic links",
            ));
        }
        visited.push(current.as_os_str().to_os_string());

        match fs::read_link(&current) {
            Ok(target) => {
                depth += 1;
                if depth > effective_max_depth {
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        symlink_path,
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
#[inline]
fn is_likely_system_symlink(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/var") || s.starts_with("/tmp") || s.starts_with("/etc")
}

#[cfg(target_os = "linux")]
#[inline]
fn is_likely_system_symlink(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/lib")
        || s.starts_with("/usr/lib")
        || s.starts_with("/bin")
        || s.starts_with("/sbin")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[inline]
fn is_likely_system_symlink(_path: &Path) -> bool {
    false
}
