use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::symlink::resolve_simple_symlink_chain;

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
#[inline]
pub(crate) fn compute_existing_prefix(
    root_prefix: &Path,
    components: &[std::ffi::OsString],
) -> io::Result<(PathBuf, usize, bool)> {
    let mut path = root_prefix.to_path_buf();
    let mut count = 0usize;
    let mut symlink_seen = false;

    // Early fast-path: check first component only, common case when first doesn't exist
    if let Some(first) = components.first() {
        // Handle . and .. even in fast path
        if first == std::ffi::OsStr::new(".") {
            return Ok((root_prefix.to_path_buf(), 1, false));
        }
        if first == std::ffi::OsStr::new("..") {
            let parent_path = if let Some(parent) = root_prefix.parent() {
                if !parent.as_os_str().is_empty() {
                    parent.to_path_buf()
                } else {
                    root_prefix.to_path_buf()
                }
            } else {
                root_prefix.to_path_buf()
            };
            return Ok((parent_path, 1, false));
        }

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
                return Ok((root_prefix.to_path_buf(), 0, false));
            }
        }
    }

    for c in components.iter().skip(count) {
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
