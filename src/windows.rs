use std::io;
use std::path::{Path, PathBuf};

use crate::error::error_with_path;

#[inline]
pub(crate) fn is_incomplete_unc(p: &Path) -> bool {
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

pub(crate) fn validate_windows_ads_layout(p: &Path) -> io::Result<()> {
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
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
                        format!(
                            "invalid NTFS ADS placement: colon-containing component '{s}' must be final"
                        ),
                    ));
                }
                // Split into base + stream [+ type]
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() < 2 {
                    continue; // shouldn't happen; contains(':') implies >=2 parts
                }
                if parts.len() > 3 {
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
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
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
                        format!("invalid NTFS ADS stream name in '{s}'"),
                    ));
                }
                // Reject whitespace manipulation (leading/trailing whitespace in stream names)
                if stream_part != stream_part.trim() {
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
                        format!("invalid NTFS ADS stream name contains leading/trailing whitespace in '{s}'"),
                    ));
                }
                // Reject control characters and null bytes in stream names
                if stream_part.chars().any(|c| c.is_control() || c == '\0') {
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
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
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
                        format!("invalid NTFS ADS stream name contains Unicode manipulation characters in '{s}'"),
                    ));
                }
                // Reject overly long stream names (NTFS limit ~255 chars for stream name)
                if stream_part.len() > 255 {
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
                        format!("invalid NTFS ADS stream name too long in '{s}'"),
                    ));
                }
                // Disallow separators or traversal markers anywhere after first colon
                let after_first_colon = &s[s.find(':').unwrap() + 1..];
                if after_first_colon.contains(['\\', '/'])
                    || after_first_colon.contains("..\\")
                    || after_first_colon.contains("../")
                {
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
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
                    return Err(error_with_path(
                        io::ErrorKind::InvalidInput,
                        p,
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
                        return Err(error_with_path(
                            io::ErrorKind::InvalidInput,
                            p,
                            format!("invalid NTFS ADS stream type '{ty}' in component '{s}'"),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[inline]
pub(crate) fn ensure_windows_extended_prefix(p: &Path) -> PathBuf {
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
        Prefix::Disk(drive) => {
            // Build an extended-length disk path. If the input was drive-relative (e.g., "C:dir"),
            // resolve relative to the process's current directory on that drive (Windows semantics).
            // Otherwise (already absolute like "C:\\..."), just add the verbatim prefix.
            use std::ffi::OsString;

            // Peek the next component to detect drive-relative vs absolute
            let mut rest = comps.clone();
            let is_absolute = matches!(rest.next(), Some(Component::RootDir));

            if is_absolute {
                // Fast path: already absolute -> just prefix with \\?\
                let mut s = OsString::from(r"\\?\");
                s.push(p.as_os_str());
                PathBuf::from(s)
            } else {
                // Drive-relative: base is the current directory on that drive if available
                // Fallback to the drive root if no per-drive current directory is found.
                #[inline]
                fn current_dir_on_drive(drive: u8) -> Option<PathBuf> {
                    // First, if the process current_dir is on this drive, use it directly
                    if let Ok(cwd) = std::env::current_dir() {
                        if let Some(std::path::Component::Prefix(pr)) = cwd.components().next() {
                            if let std::path::Prefix::Disk(d) = pr.kind() {
                                if d == drive {
                                    return Some(cwd);
                                }
                            }
                        }
                    }
                    // Next, try Windows per-drive current directory env var: "=<DRIVE>:"
                    // e.g., "=C:" -> "C:\\path\\to\\cwd"
                    let mut name = String::with_capacity(3);
                    name.push('=');
                    name.push((drive as char).to_ascii_uppercase());
                    name.push(':');
                    if let Some(val) = std::env::var_os(&name) {
                        let base = PathBuf::from(val);
                        // Ensure it looks like an absolute path (has RootDir)
                        if matches!(
                            base.components().nth(1),
                            Some(std::path::Component::RootDir)
                        ) {
                            return Some(base);
                        }
                    }
                    None
                }

                let base = current_dir_on_drive(drive)
                    .unwrap_or_else(|| PathBuf::from(format!("{}:\\", drive as char)));

                // Ensure verbatim prefix on the base
                let mut out = ensure_windows_extended_prefix(&base);
                // Append remaining components (after the drive prefix) lexically
                for c in comps {
                    out.push(c.as_os_str());
                }
                out
            }
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

#[inline]
pub(crate) fn has_windows_short_component(p: &Path) -> bool {
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

#[inline]
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
