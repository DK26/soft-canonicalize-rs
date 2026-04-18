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

/// Component-wise equality that treats Windows `VerbatimDisk(X)` and `Disk(X)` as
/// equivalent (same for `VerbatimUNC` vs `UNC`, case-insensitive for drive letters
/// and UNC server/share). On non-Windows this is a plain `==`.
#[cfg(feature = "anchored")]
#[inline]
pub(crate) fn component_eq(a: &std::path::Component, b: &std::path::Component) -> bool {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        match (a, b) {
            (Component::Prefix(ap), Component::Prefix(bp)) => match (ap.kind(), bp.kind()) {
                (Prefix::VerbatimDisk(ad), Prefix::Disk(bd))
                | (Prefix::Disk(ad), Prefix::VerbatimDisk(bd))
                | (Prefix::VerbatimDisk(ad), Prefix::VerbatimDisk(bd))
                | (Prefix::Disk(ad), Prefix::Disk(bd)) => ad.eq_ignore_ascii_case(&bd),
                (Prefix::VerbatimUNC(as1, as2), Prefix::UNC(bs1, bs2))
                | (Prefix::UNC(as1, as2), Prefix::VerbatimUNC(bs1, bs2))
                | (Prefix::VerbatimUNC(as1, as2), Prefix::VerbatimUNC(bs1, bs2))
                | (Prefix::UNC(as1, as2), Prefix::UNC(bs1, bs2)) => {
                    as1.eq_ignore_ascii_case(bs1) && as2.eq_ignore_ascii_case(bs2)
                }
                _ => ap == bp,
            },
            _ => a == b,
        }
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// Normalize `current` and clamp it inside `anchor`.
///
/// - Collapses `.` and `..` segments lexically (so literal `..` from a raw symlink
///   target cannot escape when the OS later resolves the returned path).
/// - If the normalized path is not within `anchor`, rebuilds it as
///   `anchor + (current components after longest common prefix)`.
///
/// Returns `(clamped_path, was_clamped)`.
#[cfg(feature = "anchored")]
pub(crate) fn normalize_and_clamp_to_anchor(current: &Path, anchor: &Path) -> (PathBuf, bool) {
    let normalized = simple_normalize_path(current);

    let anchor_comps: Vec<_> = anchor.components().collect();
    let current_comps: Vec<_> = normalized.components().collect();

    let is_within_anchor = current_comps.len() >= anchor_comps.len()
        && current_comps
            .iter()
            .zip(anchor_comps.iter())
            .all(|(c, a)| component_eq(c, a));

    if is_within_anchor {
        (normalized, false)
    } else {
        let mut common_depth = 0;
        for (a, c) in anchor_comps.iter().zip(current_comps.iter()) {
            if component_eq(a, c) {
                common_depth += 1;
            } else {
                break;
            }
        }
        let mut clamped = anchor.to_path_buf();
        for comp in current_comps.iter().skip(common_depth) {
            clamped.push(comp);
        }
        (clamped, true)
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
/// **Case 1: Target already within anchor** (host-style absolute path).
/// A symlink `/tmp/anchor/mylink` pointing to `/tmp/anchor/docs/file` with
/// anchor `/tmp/anchor`: the anchor prefix is stripped to `docs/file` and
/// rejoined to the anchor, yielding `/tmp/anchor/docs/file` — stays within anchor.
///
/// **Case 2: Target outside anchor** (virtual-style absolute path).
/// A symlink `/tmp/anchor/mylink` pointing to `/etc/passwd` with anchor
/// `/tmp/anchor`: the root prefix is stripped to `etc/passwd` and joined to
/// the anchor, yielding `/tmp/anchor/etc/passwd` — clamped to anchor.
///
/// Both cases ensure the final path stays within the anchor, implementing true
/// chroot-like behavior where the anchor is treated as the virtual root (`/`).
///
/// # Example
///
/// A symlink at `/anchor/mylink` pointing to `/etc/config`, with anchor
/// `/anchor`, resolves to `/anchor/etc/config` (clamped to anchor).
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
        // Detect cycles using the textual path (no extra IO).
        // Why textual (not case-normalized): on Windows's case-insensitive FS,
        // a cycle expressed in mixed case (`/Anchor/x` ↔ `/anchor/x`) won't
        // match here and falls through to the `effective_max_depth` cap below —
        // same outcome (InvalidInput, "Too many levels of symbolic links"),
        // just reached via depth exhaustion instead of early detection.
        // Case-normalizing would require per-component FS queries; the depth
        // cap is cheap and sufficient.
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

                    // We don't canonicalize absolute symlink targets because canonicalization
                    // expands the full path, breaking the clamping logic. The target is
                    // stripped and clamped as-is (virtual filesystem semantics — anchor is root).
                    // On Windows this means junction targets may retain 8.3 short names in the
                    // clamped result; that is acceptable since the paths remain valid.
                    let target = target.clone();

                    // Try to strip anchor prefix from target using component-aware comparison
                    // This handles Windows prefix format differences (\\?\C: vs C:)
                    // AND 8.3 short name vs long name mismatches (e.g., RUNNER~1 vs runneradmin)
                    #[cfg(windows)]
                    let rel_path = {
                        // Expand 8.3 short names in the target so it can be compared with the
                        // anchor (which uses long names on Windows).  Junction targets often
                        // carry 8.3 names inherited from the caller's working directory.
                        let target_for_comparison =
                            if let Ok(canonical_target) = std::fs::canonicalize(&target) {
                                canonical_target
                            } else {
                                // Target doesn't fully exist: canonicalize the deepest existing
                                // prefix and re-attach the non-existing suffix verbatim.
                                let mut check = target.clone();
                                let mut suffix_parts = Vec::new();
                                while !check.as_os_str().is_empty() {
                                    if check.exists() {
                                        break;
                                    }
                                    if let Some(file_name) = check.file_name() {
                                        suffix_parts.push(file_name.to_os_string());
                                    }
                                    if !check.pop() {
                                        break;
                                    }
                                }
                                if let Ok(canonical_prefix) = std::fs::canonicalize(&check) {
                                    let mut result = canonical_prefix;
                                    for part in suffix_parts.into_iter().rev() {
                                        result.push(part);
                                    }
                                    result
                                } else {
                                    target.clone()
                                }
                            };

                        let anchor_comps: Vec<_> = anchor.components().collect();
                        let target_comps: Vec<_> = target_for_comparison.components().collect();

                        // Component-aware prefix match handles `\\?\C:` vs `C:` and UNC
                        // verbatim-vs-legacy equivalence (see `component_eq`).
                        let is_within_anchor = target_comps.len() >= anchor_comps.len()
                            && target_comps
                                .iter()
                                .zip(anchor_comps.iter())
                                .all(|(t, a)| component_eq(t, a));

                        if is_within_anchor {
                            let mut rel = std::path::PathBuf::new();
                            for comp in target_comps.iter().skip(anchor_comps.len()) {
                                rel.push(comp);
                            }
                            Some(rel)
                        } else {
                            None
                        }
                    };

                    #[cfg(not(windows))]
                    let rel_path = target.strip_prefix(anchor).ok().map(|p| p.to_path_buf());

                    let tentative = if let Some(rel) = rel_path {
                        // Target is already within anchor: rejoin to anchor to normalize
                        anchor.join(rel)
                    } else {
                        // Target is outside anchor: strip root and clamp to anchor
                        // /etc/passwd -> anchor/etc/passwd
                        let stripped = strip_root_prefix(&target);
                        anchor.join(stripped)
                    };
                    // SECURITY: Normalize + clamp. The raw symlink target (and, in some
                    // Windows fallback paths, the computed `rel`) may contain literal `..`
                    // segments. Without this step, the returned path would still textually
                    // start with the anchor but escape when the OS resolves it.
                    let (clamped, _was_clamped) = normalize_and_clamp_to_anchor(&tentative, anchor);
                    current = clamped;
                } else {
                    // Relative symlink: resolve from parent, then clamp to anchor
                    // Virtual filesystem semantics: relative symlinks are resolved as if
                    // the anchor is the root - they cannot escape the anchor boundary
                    let parent = current.parent();
                    if let Some(p) = parent {
                        let joined = p.join(target);
                        let (clamped, _was_clamped) =
                            normalize_and_clamp_to_anchor(&joined, anchor);
                        current = clamped;

                        // FIX: Re-canonicalize on Windows to ensure:
                        // 1. Prefix format consistency (\\?\ vs regular paths)
                        // 2. 8.3 short names are expanded to full names
                        // This is critical because simple_normalize_path only handles . and ..,
                        // but doesn't expand short names like RUNNER~1 -> runneradmin
                        //
                        // IMPORTANT: Only re-canonicalize if we didn't clamp. If we clamped,
                        // the path is a virtual path within the anchor and should NOT be
                        // resolved to a real system path.
                        #[cfg(windows)]
                        if !_was_clamped && current.exists() {
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
        // Detect cycles using the textual path (no extra IO).
        // See `resolve_anchored_symlink_chain` for the rationale behind using
        // textual (not case-normalized) comparison here.
        if visited.iter().any(|s| s == current.as_os_str()) {
            return Err(error_with_path(
                io::ErrorKind::InvalidInput,
                symlink_path,
                "Too many levels of symbolic links",
            ));
        }
        visited.push(current.as_os_str().to_os_string());

        // On Linux with proc-canonicalize, check for magic paths BEFORE reading the link.
        // If we are at /proc/PID/root or /proc/PID/cwd, we must NOT resolve it to its target
        // (which is usually / or the cwd), but preserve it as a boundary.
        #[cfg(all(target_os = "linux", feature = "proc-canonicalize"))]
        if is_proc_magic_link(&current) {
            break;
        }

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

/// Checks if a path is a Linux magic link.
///
/// Supported patterns:
/// - `/proc/PID/root` and `/proc/PID/cwd` (4 components)
/// - `/proc/PID/task/TID/root` and `/proc/PID/task/TID/cwd` (6 components)
///
/// Where PID/TID can be numeric, "self", or "thread-self".
#[cfg(all(target_os = "linux", feature = "proc-canonicalize"))]
pub(crate) fn is_proc_magic_link(path: &Path) -> bool {
    use std::path::Component;

    let comps: Vec<_> = path.components().collect();

    // Pattern 1: /proc/PID/root or /proc/PID/cwd (4 components)
    if let [Component::RootDir, Component::Normal(proc), Component::Normal(pid), Component::Normal(magic)] =
        comps.as_slice()
    {
        if *proc != "proc" {
            return false;
        }
        if !is_valid_pid_component(pid) {
            return false;
        }
        let magic_str = magic.to_string_lossy();
        return matches!(magic_str.as_ref(), "root" | "cwd");
    }

    // Pattern 2: /proc/PID/task/TID/root or /proc/PID/task/TID/cwd (6 components)
    if let [Component::RootDir, Component::Normal(proc), Component::Normal(pid), Component::Normal(task), Component::Normal(tid), Component::Normal(magic)] =
        comps.as_slice()
    {
        if *proc != "proc" {
            return false;
        }
        if !is_valid_pid_component(pid) {
            return false;
        }
        if *task != "task" {
            return false;
        }
        if !is_valid_pid_component(tid) {
            return false;
        }
        let magic_str = magic.to_string_lossy();
        return matches!(magic_str.as_ref(), "root" | "cwd");
    }

    false
}

/// Checks if a component is a valid PID/TID identifier.
#[cfg(all(target_os = "linux", feature = "proc-canonicalize"))]
#[inline]
fn is_valid_pid_component(s: &std::ffi::OsStr) -> bool {
    let s_str = s.to_string_lossy();
    s_str == "self" || s_str == "thread-self" || s_str.chars().all(|c| c.is_ascii_digit())
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

#[cfg(all(test, windows, feature = "anchored"))]
mod clamp_verbatim_regression {
    //! Regression: `normalize_and_clamp_to_anchor` must return a path whose
    //! prefix form matches the anchor's, so that downstream callers using
    //! stdlib `Path::starts_with` (which treats `Disk` != `VerbatimDisk`) get
    //! the match they expect.
    //!
    //! The CI-only failure in
    //! `anchored_security::windows_symlink::anchored_relative_symlink_keeps_clamp_windows`
    //! traced to this: when `is_within_anchor` was true, the function returned
    //! the `simple_normalize_path` output directly, which used to come back
    //! with `Disk` prefix even for a `VerbatimDisk` input. The caller's
    //! `base.starts_with(&anchor_floor)` then returned false, the `..` clamp
    //! was skipped, and the stale component leaked into the final path.
    //!
    //! This test exercises the clamp helper directly with a hand-built
    //! verbatim path, so it triggers the exact failure path without needing
    //! symlink creation privileges (which Windows denies in non-admin sessions,
    //! silently skipping the integration test above).
    use super::normalize_and_clamp_to_anchor;
    use std::path::{Component, Path, Prefix};

    fn first_prefix_kind(p: &Path) -> Option<Prefix<'_>> {
        p.components().next().and_then(|c| match c {
            Component::Prefix(pc) => Some(pc.kind()),
            _ => None,
        })
    }

    #[test]
    fn verbatim_anchor_and_within_input_yields_verbatim_output() {
        let anchor = Path::new(r"\\?\C:\Users\runneradmin\AppData\Local\Temp\.tmpAAAA\home\jail");
        // `current` is anchor + opt/subdir/special — already within the anchor,
        // which takes the `is_within_anchor = true` branch (the buggy one).
        let current = Path::new(
            r"\\?\C:\Users\runneradmin\AppData\Local\Temp\.tmpAAAA\home\jail\opt\subdir\special",
        );

        let (clamped, was_clamped) = normalize_and_clamp_to_anchor(current, anchor);

        assert!(
            !was_clamped,
            "input lies within anchor; clamp helper should signal no reclamp"
        );
        assert!(
            matches!(first_prefix_kind(&clamped), Some(Prefix::VerbatimDisk(b'C'))),
            "clamped output must preserve VerbatimDisk so stdlib starts_with works; got {:?} for {:?}",
            first_prefix_kind(&clamped),
            &clamped
        );
        assert!(
            clamped.starts_with(anchor),
            "stdlib Path::starts_with must match the anchor; got clamped={:?}, anchor={:?}",
            &clamped,
            anchor
        );
    }
}
