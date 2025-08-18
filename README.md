# soft-canonicalize

[![Crates.io](https://img.shields.io/crates/v/soft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![CI](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)
[![Security audit](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml)

**Path canonicalization that works with non-existing paths.**

**Inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`** - this library brings the same functionality to Rust with enhanced performance and comprehensive testing.

## Why Use This?

**🚀 Works with non-existing paths** - Plan file locations before creating them  
**⚡ Fast** - Mixed workload median performance observed in recent runs: Windows ~1.9x, Linux ~3.0x faster than Python's pathlib  
**✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths  
**🔒 Robust** - 260 comprehensive tests including symlink cycle protection, malicious stream validation, and edge case handling  
**🛡️ Robust path handling** - Proper `..` and symlink resolution with cycle detection  
**🌍 Cross-platform** - Windows, macOS, Linux with comprehensive UNC/symlink handling  
**🔧 Zero dependencies** - Only uses std library

For detailed benchmarks, analysis, and testing procedures, see the [`benches/`](benches/) directory. Bench numbers vary by hardware, OS, and filesystem; see the bench outputs for per-scenario numbers.

## Quick Start

### Cargo.toml
```toml
[dependencies]
soft-canonicalize = "0.2"
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

### Test Coverage

**260 comprehensive tests** including:

- **11 std::fs::canonicalize compatibility tests** ensuring 100% behavioral compatibility
- **80+ robustness tests** covering consistent canonicalization behavior and edge cases  
- **42 Python pathlib test suite adaptations** for cross-language validation
- **45+ Windows UNC path tests** including unicode preservation, long paths, and mixed separators
- **50+ platform-specific tests** for Windows, macOS, and Linux edge cases
- **22+ performance and stress tests** validating behavior under various conditions

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


## Comparison with Alternatives

Each crate serves different use cases. Choose based on your primary need:

| Crate                   | **Primary Purpose**                             | **Use Cases**                                                                     |
| ----------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------- |
| `soft_canonicalize`     | **Path canonicalization + non-existing paths**  | When you need `std::fs::canonicalize` behavior but for paths that don't exist yet |
| `std::fs::canonicalize` | **Path canonicalization (existing paths only)** | Standard path canonicalization when all paths exist on filesystem                 |
| `dunce::canonicalize`   | **Windows compatibility layer**                 | Fixing Windows UNC issues for legacy app compatibility                            |
| `normpath::normalize`   | **Safe normalization alternative**              | Avoiding Windows UNC bugs while normalizing paths                                 |
| `path_absolutize`       | **CWD-relative path resolution**                | Converting relative paths to absolute with performance optimization               |
| `jailed-path`           | **Security-first path containment**             | Preventing directory traversal attacks in web servers/sandboxes                   |

### Feature Comparison

| Feature                       | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize` | `jailed-path`       |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | ----------------- | ------------------- |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                     | ✅                 | ✅ (via this crate)  |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                 | ✅ (via this crate)  |
| Windows UNC path support      | ✅                   | ✅                       | ✅                     | ✅                     | ❌                 | ✅ (via this crate)  |
| Zero dependencies             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                 | ❌ (uses this crate) |
| Built-in path jailing         | ❌                   | ❌                       | ❌                     | ❌                     | ❌                 | ✅                   |

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
