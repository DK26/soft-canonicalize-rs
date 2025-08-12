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
**⚡ Fast** - Windows: ~1.5–2.1x faster; Linux: ~2.5–4.7x faster than Python's pathlib (mixed workloads)  
**✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths  
**🔒 Security Hardened** - 182 comprehensive tests including CVE protections and path traversal prevention  
**🛡️ Robust path handling** - Proper `..` and symlink resolution with cycle detection and jail escape prevention  
**🌍 Cross-platform** - Windows, macOS, Linux with comprehensive UNC/symlink handling and Unicode preservation  
**🔧 Zero dependencies** - Only uses std library with extensive security validation

For detailed benchmarks, analysis, and testing procedures, see the [`benches/`](benches/) directory.

> Performance varies by hardware and OS/filesystem. 
> See the bench outputs for per-scenario numbers.

## Quick Start

### Cargo.toml
```toml
[dependencies]
soft-canonicalize = "0.2.3"
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

## Features

- **Directory Traversal Prevention**: `..` components resolved before filesystem access with jail escape protection
- **Symlink Resolution**: Existing symlinks properly resolved with cycle detection and attack prevention  
- **Cross-platform Path Normalization**: Handles Windows drive letters, UNC paths, device namespaces, and Unix absolute paths
- **Extended-Length Path Support**: Automatic conversion to `\\?\` prefixes on Windows for >260 character paths
- **Unicode Preservation**: Maintains exact Unicode representation without normalization for security
- **Security Hardening**: Protection against TOCTOU attacks, Unicode bypasses, and filesystem boundary exploits
 
### Test Coverage

**182 comprehensive tests** including:

- **11 std::fs::canonicalize compatibility tests** ensuring 100% behavioral compatibility
- **107 core functionality tests** covering path resolution, symlinks, and edge cases
- **51 security penetration tests** covering CVE protections and path traversal attacks  
- **25 Windows UNC path tests** including unicode preservation, long paths, and mixed separators
- **42 Python pathlib test suite adaptations** for cross-language validation
- **25 platform-specific tests** for Windows, macOS, and Linux edge cases
- **20 performance and stress tests** validating behavior under various conditions
- **7 CVE-specific security tests** protecting against known vulnerabilities including filename handling flaws

### 🔒 Comprehensive CVE Protection

Our security test suite provides **verified protection** against real-world vulnerabilities:

#### Comprehensive CVE Protection
- **CVE-2022-21658** (TOCTOU): Race condition prevention through atomic path processing
- **CVE-2019-9855** (LibreOffice): Protection against path equivalence handling flaws
- **CVE-2017-17793** (BlogoText): Prevention of backup file access through predictable short names
- **CVE-2020-12279** (Git): Protection against NTFS short name equivalence confusion
- **CVE-2005-0471** (Java): Mitigation of predictable temporary file names
- **CVE-2002-2413** (WebSite Pro): Prevention of script source code disclosure via filename equivalence
- **CVE-2001-0795** (LiteServe): Protection against script source disclosure through name variation

#### Additional Security Protections
- **Unicode Security**: Homoglyph detection, zero-width character preservation, and normalization bypass prevention
- **Path Traversal**: Comprehensive `..` resolution with jail escape detection and UNC share boundary enforcement
- **Symlink Attacks**: Cycle detection, visited set manipulation prevention, and nested directory attack mitigation

### 🛡️ Battle-Tested Security Validation

Our comprehensive security test suite specifically validates protection against real-world vulnerabilities found in other path handling libraries:

#### Filesystem Security
- **UNC Path Traversal Prevention**: Comprehensive testing of Windows UNC paths to prevent escape from share roots using `..` traversal
- **Device Namespace Security**: Tests for `\\.\` and `\\?\GLOBALROOT\` path handling to prevent device namespace exploitation
- **NTFS Alternate Data Streams**: Windows-specific tests for ADS attack vectors that can hide malicious content
- **Filesystem Boundary Testing**: Edge cases around filename length limits and component count boundaries

#### Unicode & Encoding Security  
- **Unicode Normalization Bypasses**: Protection against attacks using Unicode normalization to disguise malicious paths, including homoglyph and zero-width character preservation
- **Double-Encoding Attacks**: Validates that percent-encoded sequences aren't automatically decoded (preventing bypass attempts)
- **Case Sensitivity Bypasses**: Tests on case-insensitive filesystems to prevent case-based security bypasses
- **Explicit Null Byte Detection**: Consistent error handling across platforms (unlike OS-dependent behavior)

#### Symlink & Race Condition Security
- **Symlink Jail Escapes**: Comprehensive testing of symlinked directory attacks and nested symlink chains
- **TOCTOU Race Conditions**: Tests against Time-of-Check-Time-of-Use attacks where symlinks are replaced between canonicalization and file access
- **Symlink Cycle Detection**: Prevention of infinite loops and resource exhaustion through malicious symlink chains

These tests ensure that `soft_canonicalize` doesn't inherit the security vulnerabilities that have affected other path canonicalization libraries, giving you confidence in production security-critical applications.


## What is Path Canonicalization?

Path canonicalization converts paths to their canonical (standard) form, enabling accurate comparison and ensuring two different path representations that point to the same location are recognized as equivalent. 

Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths even when components don't exist on the filesystem. This enables accurate path comparison, resolution of future file locations, and preprocessing paths before file creation.

This is essential for:

- **Path Comparison**: Determining if two paths refer to the same file or directory
- **Deduplication**: Avoiding duplicate operations on the same file accessed via different paths  
- **Build Systems**: Resolving output paths and dependencies accurately
- **Future Path Planning**: Computing paths for files that will be created later
- **Security Applications**: Preventing path traversal attacks and ensuring paths stay within intended boundaries

The "soft" aspect means we can canonicalize paths even when the target doesn't exist yet - extending traditional canonicalization to work with planned or future file locations.


## Comparison with Alternatives

Each crate serves different use cases. Choose based on your primary need:

| Crate                    | **Primary Purpose**               | **Use Cases**                                                        |
| ------------------------ | --------------------------------- | -------------------------------------------------------------------- |
| `soft_canonicalize`      | **Path canonicalization + non-existing paths** | When you need `std::fs::canonicalize` behavior but for paths that don't exist yet |
| `std::fs::canonicalize`  | **Path canonicalization (existing paths only)** | Standard path canonicalization when all paths exist on filesystem   |
| `dunce::canonicalize`    | **Windows compatibility layer**   | Fixing Windows UNC issues for legacy app compatibility              |
| `normpath::normalize`    | **Safe normalization alternative**| Avoiding Windows UNC bugs while normalizing paths                   |
| `path_absolutize`        | **CWD-relative path resolution**  | Converting relative paths to absolute with performance optimization  |
| `jailed-path`            | **Security-first path containment**| Preventing directory traversal attacks in web servers/sandboxes    |

### Feature Comparison

| Feature                       | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize`     | `jailed-path`       |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | --------------------- | ------------------- |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                     | ✅                     | ✅ (via this crate) |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                     | ✅ (via this crate) |
| Windows UNC path support      | ✅                   | ✅                       | ✅                     | ✅                     | ❌                     | ✅ (via this crate) |
| Zero dependencies             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                     | ❌ (uses this crate)|
| Built-in path jailing         | ❌                   | ❌                       | ❌                     | ❌                     | ❌                     | ✅                   |

### When to Choose `soft_canonicalize`

- **Path comparison**: Need to check if two paths refer to the same location
- **Non-existing paths**: Working with planned files, build outputs, or future locations  
- **Cross-platform**: Want consistent behavior across Windows, macOS, and Linux
- **Zero dependencies**: Prefer minimal dependency footprint

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
