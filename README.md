# soft-canonicalize

[![Crates.io](https://img.shields.io/crates/v/soft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![CI](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)
[![Security audit](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml)

A high-performance, pure Rust library for path canonicalization that works with non-existing paths.

**Inspired by Python's `pathlib.Path.resolve(strict=False)`** - this library brings the same functionality to Rust, but with significant performance improvements and additional safety features.

Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths even when components don't exist on the filesystem. This enables accurate path comparison, resolution of future file locations, and preprocessing paths before file creation.

**🔬 Comprehensive test suite with 100+ tests ensuring 100% behavioral compatibility with std::fs::canonicalize for existing paths.**

## Features

- **🚀 Works with non-existing paths**: Canonicalizes paths that don't exist yet
- **🌍 Cross-platform**: Windows, macOS, and Linux support  
- **🔧 Zero dependencies**: Only uses std library
- **🔒 Robust path handling**: Proper `..` and symlink resolution with cycle detection
- **🛡️ Security tested**: Protection against CVE-2022-21658 and common path traversal attacks
- **🔍 Security monitoring**: Automated daily security audits via cargo-audit in CI/CD
- **⚡ High Performance**: Optimized algorithm significantly outperforms naive implementations

## What is Path Canonicalization?

Path canonicalization converts paths to their canonical (standard) form, enabling accurate comparison and ensuring two different path representations that point to the same location are recognized as equivalent. This is essential for:

- **Path Comparison**: Determining if two paths refer to the same file or directory
- **Deduplication**: Avoiding duplicate operations on the same file accessed via different paths  
- **Build Systems**: Resolving output paths and dependencies accurately
- **Future Path Planning**: Computing paths for files that will be created later
- **Security Applications**: Preventing path traversal attacks and ensuring paths stay within intended boundaries

The "soft" aspect means we can canonicalize paths even when the target doesn't exist yet - extending traditional canonicalization to work with planned or future file locations.

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
soft-canonicalize = "0.1.4"
```

### Basic Usage

```rust
use soft_canonicalize::soft_canonicalize;
use std::path::PathBuf;

// Starting from working directory: /home/user/myproject

// Input: "data/config.json" (relative path to non-existing file)
// Output: absolute canonical path (file doesn't need to exist!)
let result = soft_canonicalize("data/config.json")?;
assert_eq!(result, PathBuf::from("/home/user/myproject/data/config.json"));

// Input: "src/../data/settings.toml" (path with .. traversal to non-existing file)  
// Output: .. resolved logically, no filesystem needed
let result = soft_canonicalize("src/../data/settings.toml")?;
assert_eq!(result, PathBuf::from("/home/user/myproject/data/settings.toml"));

// Input: "src/../README.md" (existing file with .. traversal)
// Output: same as std::fs::canonicalize (resolves symlinks too)
let result = soft_canonicalize("src/../README.md")?;
assert_eq!(result, PathBuf::from("/home/user/myproject/README.md"));
```

## Use Cases

- **Path Comparison & Deduplication**: Ensure different path representations are recognized as equivalent
- **Build Tools**: Resolving non-existing output paths and dependency tracking
- **File System Planning**: Computing canonical paths for files that will be created
- **Web Applications**: Normalizing user-provided paths for consistent handling
- **Security Applications**: Safe path validation with proper symlink resolution

## How It Works

This library implements an optimized **PathResolver algorithm** that:

1. **Fast-path optimization**: Uses `std::fs::canonicalize()` directly for existing absolute paths without dot components
2. **Boundary detection**: Efficiently finds the split between existing and non-existing path components
3. **Lexical resolution**: Resolves `..` and `.` components without filesystem calls where possible
4. **Symlink handling**: Properly resolves existing symlinks with cycle detection and depth limits
5. **Platform optimization**: Maintains Windows UNC path canonicalization (`\\?\C:\...` format)

This approach ensures you get the same results as the standard library for existing paths, with extended support for non-existing paths and significantly better performance than naive implementations.

## Performance & Compatibility

- **Time Complexity**: O(k) existing components (best: O(1), worst: O(n))
- **Space Complexity**: O(n) component storage with optimized memory usage
- **Cross-platform**: Windows (drive letters, UNC), Unix (symlinks)
- **Comprehensive Testing**: 100+ tests including security audits, Python-inspired edge cases, and cross-platform validation
- **100% Behavioral Compatibility**: Passes all std::fs::canonicalize tests for existing paths

For detailed performance benchmarks and comparisons with Python's pathlib, see the [`benches/`](benches/) directory.

## Security

- **Directory Traversal Prevention**: `..` components resolved before filesystem access
- **Symlink Resolution**: Existing symlinks properly resolved with cycle detection
- **Cross-platform Path Normalization**: Handles Windows drive letters, UNC paths, and Unix absolute paths

**Note on Symlink Handling**: Unlike some path normalization libraries, this crate resolves symlinks when they exist, providing stronger guarantees about the final path destination. This behavior matches `std::fs::canonicalize` and can help prevent certain types of path-based security issues in applications that require it.

### Critical Safety Mechanisms

**🔒 Symlink Cycle Detection**: Tracks visited symlinks to prevent infinite recursion and stack overflow attacks. Tested with comprehensive cycle detection tests ensuring robust protection against malicious symlink chains.

**🛡️ Symlinked Directory Jail Break Prevention**: Properly resolves symlinked directories that point outside security boundaries, enabling detection of sophisticated jail escape attempts. Our test suite includes specific scenarios where attackers use symlinked directories (e.g., `jail/uploads/user123 -> /outside/secrets/`) to escape containment when accessing non-existing files through the symlink.

### 🔍 Tested Against Known Vulnerabilities

Our comprehensive security test suite specifically validates protection against real-world vulnerabilities found in other path handling libraries:

- **CVE-2022-21658 Race Conditions**: Tests against Time-of-Check-Time-of-Use (TOCTOU) attacks where symlinks are replaced between canonicalization and file access
- **Unicode Normalization Bypasses**: Protection against attacks using Unicode normalization to disguise malicious paths
- **Double-Encoding Attacks**: Validates that percent-encoded sequences aren't automatically decoded (preventing bypass attempts)
- **Case Sensitivity Bypasses**: Tests on case-insensitive filesystems to prevent case-based security bypasses
- **Symlink Jail Escapes**: Comprehensive testing of symlinked directory attacks and nested symlink chains
- **NTFS Alternate Data Streams**: Windows-specific tests for ADS attack vectors that can hide malicious content
- **Filesystem Boundary Testing**: Edge cases around filename length limits and component count boundaries

These tests ensure that `soft_canonicalize` doesn't inherit the security vulnerabilities that have affected other path canonicalization libraries, giving you confidence in production security-critical applications.

## Comparison with Alternatives

| Feature                       | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize` | `jailed-path`       |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | ----------------- | ------------------- |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                     | ✅                 | ✅ (via this crate) |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                 | ✅ (via this crate) |
| Zero dependencies             | ✅                   | ✅                       | ❌                     | ❌                     | ❌                 | ❌ (uses this crate)|
| Prevents symlink jail breaks  | ✅                   | ✅                       | ✅                     | N/A                   | ⚠️ (no symlink resolution) | ✅ (via this crate) |
| Security tested               | ✅ (CVEs & bypasses) | ❌                       | ❌                     | ❌                     | ❌                 | ✅ (via this crate) |
| Built-in path jailing         | ❌                   | ❌                       | ❌                     | ❌                     | ❌                 | ✅ (enforcement)    |

**Choose `soft_canonicalize` when you need**: Core path canonicalization for non-existing files with full symlink resolution.  
**Choose `jailed-path` when you need**: Path jailing with type-safe boundaries (builds on `soft_canonicalize`).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
