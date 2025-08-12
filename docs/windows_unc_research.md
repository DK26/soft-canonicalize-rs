# Windows UNC paths: behavior, std::fs::canonicalize alignment, and test matrix

This document summarizes Windows path prefixes, what Rust's `std::fs::canonicalize` does, and the coverage we need in this crate to stay aligned, including ambiguous cases for non-existing paths.

## Windows path prefixes and forms

Windows path parsing recognizes these key forms (see `std::path::Prefix`):

- Drive-relative and absolute:
  - `C:\` (absolute on drive C)
  - `C:relative\path` (relative to current directory on drive C)
- UNC (server/share):
  - `\\server\share\path` (Win32 UNC)
  - Verbatim UNC: `\\?\UNC\server\share\path` (extended-length)  
    Skips Win32 normalization like trimming trailing dots/spaces.
- Verbatim disk: `\\?\C:\path` (extended-length for local drive)
- Device namespace: `\\.\COM1`, `\\?\GLOBALROOT\Device\HarddiskVolume1` (lexical-only: supported as opaque prefixes; no IO)

Notes:
- Extended-length (verbatim) prefixes remove `MAX_PATH` (260) limits and disable certain Win32 normalizations (e.g., trailing dot/space trimming, `\\.\` device paths, path parsing quirks).
- `std::fs::canonicalize` returns extended-length paths (`\\?\C:\...` or `\\?\UNC\server\share\...`) for existing paths.

## `std::fs::canonicalize` behavior (Windows)

- For existing paths:
  - Converts to extended-length verbatim form.
  - Normalizes case to the filesystem's canonical casing.
  - Resolves symlinks and junctions.
  - Expands 8.3 (short) names to long names.
- For non-existing paths:
  - Returns `NotFound`.

Implications for this crate:
- We must match `std::fs::canonicalize` when the full path exists.
- For non-existing suffixes, we keep the extended-length prefix and preserve textual components (no short-name expansion) while resolving the deepest existing prefix.
- For device namespace paths (e.g., `\\.\`, `\\?\GLOBALROOT\...`), we support lexical normalization without IO: preserve the device prefix verbatim and normalize `.`/`..` within the path.

## Edge cases to cover

- Mixed separators `\\` and `/` inside UNC forms.
- `..` traversal cannot climb above `\\server\share` root; it clamps at the share root.
- Trailing dots/spaces in names are preserved under verbatim prefix.
- 8.3-like components (e.g., `PROGRA~1`) are preserved when non-existing; expanded only when that component exists and is probed/canonicalized.
- Idempotency when input already uses verbatim `\\?\` or verbatim UNC.
- Drive-letter absolute across multiple letters yields `\\?\X:\...`.
- UNC server/share roots canonicalize to verbatim UNC; server/share availability cannot be verified without network, so tests must assert prefix/shape rather than existence.
- Device namespace paths: assert prefix preservation and purely lexical normalization; never convert to another prefix or probe the filesystem.

## Proposed test matrix (Windows)

- Drive absolute:
  - `C:\nonexistent\child.txt` -> starts with `\\?\C:\`; endswith `nonexistent\child.txt`.
  - Repeat for `D, E, Z`.
- Verbatim disk idempotency:
  - Input `\\?\C:\NonExistent\...` -> unchanged.
- UNC server/share non-existing:
  - `\\server\share` -> verbatim UNC prefix `\\?\UNC\server` (cannot assert share due to envs where `share` isn't included in output without probing).
  - `\\server\share\mixed/sep\\dir/file.txt` -> starts `\\?\UNC\`, endswith suffix.
  - `\\server\share\folder\..\..\sibling\file.txt` -> still under `\\?\UNC\server`; endswith suffix.
  - Idempotent for `\\?\UNC\server\share\...`.
  - Preserve `PROGRA~1` component for non-existing.
  - Preserve trailing `.` and ` ` in components.

  - Device namespace (lexical-only):
    - `\\.\PIPE\name\..\other` -> `\\.\PIPE\other`
    - `\\?\GLOBALROOT\Device\HarddiskVolume1\foo\.\bar\..\baz` -> `\\?\GLOBALROOT\Device\HarddiskVolume1\foo\baz`
    - Idempotent for already-normalized device paths like `\\.\PhysicalDrive0`
  - Parent traversal clamps at the DeviceNS prefix including the device class (e.g., `\\.\PIPE` or `\\?\GLOBALROOT`); it won’t pop the device class name. Example: `\\.\PIPE\a\..\..\b` -> `\\.\PIPE\b`

## Known limitations

- Device namespace paths are handled lexically only; we do not perform IO or guarantee device availability/resolution. Parent traversal never crosses the DeviceNS prefix and does not remove the device class name.
- We cannot verify network share existence in CI; tests use structural assertions instead of IO checks.

## Alignment checklist

- Existing local paths: exact equality with `std::fs::canonicalize` (covered by `std_compat`).
- Existing UNC paths: equality when available; otherwise avoid tests that require a real share.
- Non-existing suffixes: extended-length prefix present; suffix preserved lexically; `..` stops at root or share.

