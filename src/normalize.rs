use std::path::PathBuf;

/// Streaming path normalization with push/pop operations.
/// This replaces intermediate Vec allocation with direct PathBuf manipulation.
/// Contract:
/// - Input: any Path (absolute/relative)
/// - Output: a PathBuf where `.` is removed and `..` pops one component when possible
/// - Root semantics are preserved (never pops past root)
#[inline]
pub(crate) fn simple_normalize_path(path: &std::path::Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::path::{Component, Prefix};

        // Capture prefix and root semantics, and normalize components lexically with clamping
        enum Anchor {
            None,
            Drive(OsString),         // e.g., "C:"
            Unc(OsString, OsString), // (server, share)
            DeviceNS(OsString),      // raw device prefix (e.g., \\., \\?\GLOBALROOT\...)
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
