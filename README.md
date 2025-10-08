# soft-canonicalize

[![Crates.io](https://img.shields.io/crates/v/soft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![CI](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)
[![Security audit](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml)

**Path canonicalization that works with non-existing paths.**

**Inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`** - this library brings the same functionality to Rust with enhanced performance and comprehensive testing.

### Rust equivalent of Unix `realpath()` / `std::fs::canonicalize`

This crate extends standard path canonicalization to support non-existing paths. See the [comparison table](#comparison-with-alternatives) for detailed feature comparisons.

## Why Use This?

**🚀 Works with non-existing paths** - Plan file locations before creating them  
**⚡ Fast** - Mixed workload median performance (5-run protocol): Windows ~1.3x (9,907 paths/s), Linux ~1.9x (238,038 paths/s) faster than Python's pathlib  
**✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths  
**🔒 Robust** - 436 comprehensive tests including symlink cycle protection, malicious stream validation, and edge case handling  
**🛡️ Robust path handling** - Proper `..` and symlink resolution with cycle detection  
**🌍 Cross-platform** - Windows, macOS, Linux with comprehensive UNC/symlink handling  
**🔧 Zero dependencies** - Optional features may add dependencies

For detailed benchmarks, analysis, and testing procedures, see the [`benches/`](benches/) directory. Bench numbers vary by hardware, OS, and filesystem; see the bench outputs for per-scenario numbers.

## Quick Start

### Cargo.toml
```toml
[dependencies]
soft-canonicalize = "0.4"
```

### Code Example

```rust
use soft_canonicalize::soft_canonicalize;
use std::path::PathBuf;

let non_existing_path = r"C:\Users\user\documents\..\non\existing\config.json";

// Using Rust's own std canonicalize function:
let result = std::fs::canonicalize(non_existing_path);
assert!(result.is_err());

// Using our crate's function:
let result = soft_canonicalize(non_existing_path);
assert!(result.is_ok());

// Shows the UNC path conversion and path normalization
assert_eq!(
    result.unwrap().to_string_lossy(),
    r"\\?\C:\Users\user\non\existing\config.json"
);
```


## Comparison with Alternatives

Each crate serves different use cases. Choose based on your primary need:

| Tool/Crate                       | **Primary Purpose**                               | **Use Cases**                                                                     |
| -------------------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------- |
| `soft_canonicalize`              | **Path canonicalization + non-existing paths**    | When you need `std::fs::canonicalize` behavior but for paths that don't exist yet |
| `soft_canonicalize` (w/ `dunce`) | **Non-existing paths + simplified output**        | Like `dunce::canonicalize`, but works with non-existing paths                     |
| `realpath()` (libc)              | **Path canonicalization (existing paths only)**   | Unix/POSIX system call for path canonicalization                                  |
| `std::fs::canonicalize`          | **Path canonicalization (existing paths only)**   | Standard path canonicalization when all paths exist on filesystem                 |
| `std::path::absolute`            | **Make paths absolute (no canonicalization)**     | Converting to absolute paths without resolving symlinks or normalizing            |
| `dunce::canonicalize`            | **Windows compatibility layer**                   | Fixing Windows UNC issues for legacy app compatibility                            |
| `normpath::normalize`            | **Safe normalization alternative**                | Avoiding Windows UNC bugs while normalizing paths                                 |
| `path_absolutize`                | **CWD-relative path resolution**                  | Converting relative paths to absolute with performance optimization               |
| `strict-path`                    | **Type-safe path restriction with safe symlinks** | Preventing directory traversal with type-safe path restriction and safe symlinks  |

### Feature Comparison

| Feature                          | `soft_canonicalize`           | `realpath()` (libc) | `std::fs::canonicalize` | `std::path::absolute` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize` | `strict-path`       |
| -------------------------------- | ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | --------------------- | ----------------- | ------------------- |
| Works with non-existing paths    | ✅                             | ❌                   | ❌                       | ✅                     | ❌                     | ✅                     | ✅                 | ✅ (via this crate)  |
| Resolves symlinks                | ✅                             | ✅                   | ✅                       | ❌                     | ✅                     | ❌                     | ❌                 | ✅ (via this crate)  |
| Simplified Windows paths         | ✅ (opt-in `dunce` feature)    | N/A (Unix/POSIX)    | ❌ (UNC)                 | ❌ (varies)            | ✅                     | ✅                     | ❌                 | ❌ (UNC)             |
| Windows UNC path support         | ✅                             | N/A (Unix/POSIX)    | ✅                       | ✅                     | ✅                     | ✅                     | ❌                 | ✅ (via this crate)  |
| Zero dependencies                | ✅ (default)                   | N/A (system call)   | ✅                       | ✅                     | ✅                     | ❌                     | ❌                 | ❌ (uses this crate) |
| Virtual/bounded canonicalization | ✅ (opt-in `anchored` feature) | ❌                   | ❌                       | ❌                     | ❌                     | ❌                     | ❌                 | ✅ (`VirtualRoot`)   |

## Known Limitations

### Windows Short Filename Equivalence

On Windows, the filesystem may generate short filenames (8.3 format) for long directory names. For **non-existing paths**, this library cannot determine if a short filename form (e.g., `PROGRA~1`) and its corresponding long form (e.g., `Program Files`) refer to the same future location:

```rust
use soft_canonicalize::soft_canonicalize;

// These non-existing paths are treated as different (correctly)
let short_form = soft_canonicalize("C:/PROGRA~1/MyApp/config.json")?;
let long_form = soft_canonicalize("C:/Program Files/MyApp/config.json")?;

// They will NOT be equal because we cannot determine equivalence
// without filesystem existence
assert_ne!(short_form, long_form);
```

**This is a fundamental limitation** shared by Python's `pathlib.Path.resolve(strict=False)` and other path canonicalization libraries across languages. Short filename mapping only exists when files/directories are actually created by the filesystem.

**For existing paths**, this library correctly resolves short and long forms to the same canonical result, maintaining 100% compatibility with `std::fs::canonicalize`.

### Test Coverage

**436 comprehensive tests** including:

- **11 std::fs::canonicalize compatibility tests** ensuring 100% behavioral compatibility
- **80+ robustness tests** covering consistent canonicalization behavior and edge cases  
- **42 Python pathlib test suite adaptations** for cross-language validation
- **45+ Windows UNC path tests** including unicode preservation, long paths, and mixed separators
- **50+ platform-specific tests** for Windows, macOS, and Linux edge cases
- **22+ performance and stress tests** validating behavior under various conditions
- **5 documentation tests** demonstrating API usage

### 🔍 Tested Against Path Handling Edge Cases

Our comprehensive test suite validates consistent canonicalization behavior across various challenging scenarios:

- **Race Condition Robustness**: Consistent canonicalization behavior even when filesystem changes during processing
- **Symlink Cycle Protection**: Detects and rejects circular symlink references to prevent infinite loops
- **Malicious Stream Detection**: Validates Windows NTFS Alternate Data Stream syntax to reject malformed or suspicious patterns
- **Path Equivalence Handling**: Consistent behavior with various path representations and edge cases
- **Short Name Handling**: Proper canonicalization behavior with Windows 8.3 short names
- **Long Path Support**: Correct handling of Windows extended-length paths and NTFS features
- **Unicode Normalization**: Consistent handling of Unicode characters, zero-width characters, and normalization forms
- **Path Resolution**: Comprehensive `..` resolution with cycle detection and boundary enforcement
- **Cross-Platform Consistency**: Comprehensive testing across Windows, macOS, and Linux filesystem behaviors

## What is Path Canonicalization?

Path canonicalization converts paths to their canonical (standard) form, enabling accurate comparison and ensuring two different path representations that point to the same location are recognized as equivalent. 

Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths even when components don't exist on the filesystem. This enables accurate path comparison, resolution of future file locations, and preprocessing paths before file creation.

This is essential for:

- **Path Comparison**: Determining if two paths refer to the same file or directory
- **Deduplication**: Avoiding duplicate operations on the same file accessed via different paths  
- **Build Systems**: Resolving output paths and dependencies accurately
- **Future Path Planning**: Computing paths for files that will be created later
- **Path Validation**: Providing consistent, normalized paths for validation and boundary checking in applications

The "soft" aspect means we can canonicalize paths even when the target doesn't exist yet - extending traditional canonicalization to work with planned or future file locations.

## Optional Features

This crate provides two optional features:
- **`anchored`** - Virtual filesystem/bounded canonicalization (cross-platform)
- **`dunce`** - Simplified Windows path output (Windows-only, no effect on Unix/Linux/macOS)

### Anchored Canonicalization (`anchored` feature)

For **correct symlink resolution within virtual/constrained directory spaces**, use `anchored_canonicalize`. This function implements true virtual filesystem semantics by clamping ALL paths (including absolute symlink targets) to the anchor directory:

```toml
[dependencies]
soft-canonicalize = { version = "0.4", features = ["anchored"] }
```

```rust
use soft_canonicalize::anchored_canonicalize;
use std::fs;

// Set up an anchor/root directory (no need to pre-canonicalize)
let anchor = std::env::temp_dir().join("workspace_root");
fs::create_dir_all(&anchor)?;

// Canonicalize paths relative to the anchor (anchor is soft-canonicalized internally)
let resolved_path = anchored_canonicalize(&anchor, "../../../etc/passwd")?;
// Result: /tmp/workspace_root/etc/passwd (lexical .. clamped to anchor)

// Absolute symlinks are also clamped to the anchor
// If there's a symlink: workspace_root/config -> /etc/config
// It resolves to: workspace_root/etc/config (clamped to anchor)
let symlink_path = anchored_canonicalize(&anchor, "config")?;
// Safe: always stays within workspace_root, even if symlink points to /etc/config
```

Key features of `anchored_canonicalize`:
- **Virtual filesystem semantics**: All absolute paths (including symlink targets) are clamped to anchor
- **Anchor-relative canonicalization**: Resolves paths relative to a specific anchor directory
- **Complete symlink clamping**: Follows symlink chains with clamping at each step
- **Component-by-component**: Processes path components in proper order
- **Absolute results**: Always returns absolute canonical paths within the anchor boundary

### Simplified Path Output (`dunce` feature, Windows-only)

**Windows-specific feature**: The `dunce` feature only affects Windows platforms. On Unix/Linux/macOS, it has no effect and adds no dependencies.

By default on Windows, `soft_canonicalize` returns paths in extended-length UNC format (`\\?\C:\foo`) for maximum robustness and compatibility with long paths, reserved names, and other Windows filesystem edge cases.

If you need simplified paths (`C:\foo`) for compatibility with legacy Windows applications or user-facing output, enable the **`dunce` feature**:

```toml
[dependencies]
soft-canonicalize = { version = "0.4", features = ["dunce"] }
```

**Example:**

```rust
use soft_canonicalize::soft_canonicalize;

let path = soft_canonicalize(r"C:\Users\user\documents\..\config.json")?;

// Without dunce feature (default):
// Returns: \\?\C:\Users\user\config.json (extended-length UNC)

// With dunce feature enabled:
// Returns: C:\Users\user\config.json (simplified when safe)
```

**When to use:**
- ✅ Legacy applications that don't support UNC paths
- ✅ User-facing output requiring familiar path format
- ✅ Tools expecting traditional Windows path format

**How it works:**
The [dunce](https://crates.io/crates/dunce) crate intelligently simplifies Windows UNC paths (`\\?\C:\foo` → `C:\foo`) **only when safe**:
- Automatically keeps UNC for paths >260 chars
- Automatically keeps UNC for reserved names (CON, PRN, NUL, COM1-9, LPT1-9)
- Automatically keeps UNC for paths with trailing spaces/dots
- Automatically keeps UNC for paths containing `..` (literal interpretation)

All security validations remain unchanged - only the final output format is simplified when possible. On Unix systems, the feature has no effect.


## Security & CVE Coverage

Security does not depend on enabling features. The core API is secure-by-default; the optional `anchored` feature is a convenience for virtual roots. We test all modes (no features; `--features anchored`; `--features anchored,dunce`).

See `docs/SECURITY.md` for details, usage patterns, and test references.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
