# soft-canonicalize

[![Crates.io](https://img.shields.io**That's it!** Zero dependencies, pure Rust stdlib.

## Examplesoft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![CI](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)
[![Security audit](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml)

**Path canonicalization that works with non-existing paths.**

**Inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`** - this library brings the same functionality to Rust, with additional safety features.

## Why Use This?

**🚀 Works with non-existing paths** - Plan file locations before creating them  
**✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths  
**🔧 Zero dependencies** - Only uses std library  
**⚡ Fast** - 1.3x-1.5x faster than Python's pathlib in mixed workloads  
**🔒 Secure** - 108 tests including CVE protections and path traversal prevention  
**🌍 Cross-platform** - Windows, macOS, Linux with proper UNC/symlink handling  
**🛡️ Robust path handling** - Proper `..` and symlink resolution with cycle detection

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

```rust
use soft_canonicalize::soft_canonicalize;

// Works with non-existing paths (unlike std::fs::canonicalize)
let result = soft_canonicalize("../future/config.json")?;
// Returns: "/home/user/project/future/config.json"

// Resolves complex traversals logically
let result = soft_canonicalize("src/../data/../config.json")?;  
// Returns: "/home/user/project/config.json"

// Same as std::fs::canonicalize for existing paths
let result = soft_canonicalize("src/lib.rs")?;
// Returns: "/home/user/project/src/lib.rs" (with symlinks resolved)
```

## Quick Start

```toml
[dependencies]
soft-canonicalize = "0.1.4"
```

**That's it!** Zero dependencies, pure Rust stdlib.

## Examples

```rust
use soft_canonicalize::soft_canonicalize;
use std::path::PathBuf;

// Starting from working directory: /home/user/myproject

// Non-existing file planning
let result = soft_canonicalize("data/config.json")?;
assert_eq!(result, PathBuf::from("/home/user/myproject/data/config.json"));

// Complex path traversal resolution  
let result = soft_canonicalize("src/../data/settings.toml")?;
assert_eq!(result, PathBuf::from("/home/user/myproject/data/settings.toml"));

// Existing files (same as std::fs::canonicalize)
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

1. **Optimization for existing paths**: Uses `std::fs::canonicalize()` directly for existing absolute paths without dot components
2. **Boundary detection**: Efficiently finds the split between existing and non-existing path components
3. **Lexical resolution**: Resolves `..` and `.` components without filesystem calls where possible
4. **Symlink handling**: Properly resolves existing symlinks with cycle detection and depth limits
5. **Platform optimization**: Maintains Windows UNC path canonicalization (`\\?\C:\...` format)

This approach ensures you get the same results as the standard library for existing paths, with extended support for non-existing paths.

## Performance & Benchmarks

**1.3x - 1.5x faster than Python 3.12.4** in mixed workloads on typical hardware.

### Algorithm Optimizations

- **Fast-path for simple cases**: Direct `std::fs::canonicalize()` for existing absolute paths without dot components  
- **Binary search boundary detection**: O(log n) time complexity to find existing/non-existing split
- **Single-pass normalization**: Resolves `..` and `.` components without filesystem calls where possible
- **Intelligent caching**: Reuses filesystem queries within the same path resolution
- **Platform-specific optimizations**: Windows UNC path handling, Unix symlink resolution

### Detailed Results

**Verified against Python 3.12.4's `pathlib.Path.resolve(strict=False)`:**

| Scenario              | Python 3.12.4         | Rust (this crate)           | Performance Comparison        |
| --------------------- | --------------------- | --------------------------- | ----------------------------- |
| **Mixed workload**    | 4,627 paths/s         | **6,089 - 6,769 paths/s**   | **1.3x - 1.5x faster**        |
| Simple existing paths | ~6,600 paths/s        | **10,057 - 12,851 paths/s** | **1.5x - 1.9x faster**        |
| Path traversal (../)  | ~6,500 paths/s        | **11,551 - 13,529 paths/s** | **1.8x - 2.1x faster**        |
| Non-existing paths    | 2,516 - 4,441 paths/s | **1,950 - 2,072 paths/s**   | **0.4x - 0.8x (competitive)** |

*Performance varies by hardware. Benchmarks run on Windows 11 with comprehensive test suites.*

For detailed benchmarks, analysis, and testing procedures, see the [`benches/`](benches/) directory.

## Security

- **Directory Traversal Prevention**: `..` components resolved before filesystem access
- **Symlink Resolution**: Existing symlinks properly resolved with cycle detection  
- **Cross-platform Path Normalization**: Handles Windows drive letters, UNC paths, and Unix absolute paths

**Note on Symlink Handling**: Unlike some path normalization libraries, this crate resolves symlinks when they exist, providing stronger guarantees about the final path destination. This behavior matches `std::fs::canonicalize` and can help prevent certain types of path-based security issues in applications that require it.

### Test Coverage

**108 comprehensive tests** including:

- **10 std::fs::canonicalize compatibility tests** ensuring 100% behavioral compatibility
- **32 security penetration tests** covering CVE-2022-21658 and path traversal attacks  
- **Python pathlib test suite adaptations** for cross-language validation
- **Platform-specific tests** for Windows, macOS, and Linux edge cases
- **Performance and stress tests** validating behavior under various conditions

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

| Feature                       | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize`         | `jailed-path`       |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | ------------------------- | ------------------- |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                     | ✅                         | ✅ (via this crate)  |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                         | ✅ (via this crate)  |
| Zero dependencies             | ✅                   | ✅                       | ❌                     | ❌                     | ❌                         | ❌ (uses this crate) |
| Prevents symlink jail breaks  | ✅                   | ✅                       | ✅                     | N/A                   | ⚠️ (no symlink resolution) | ✅ (via this crate)  |
| Security tested               | ✅ (CVEs & bypasses) | ❌                       | ❌                     | ❌                     | ❌                         | ✅ (via this crate)  |
| Built-in path jailing         | ❌                   | ❌                       | ❌                     | ❌                     | ❌                         | ✅ (enforcement)     |

**Choose `soft-canonicalize` when you need**: Core path canonicalization for non-existing files with full symlink resolution.  
**Choose `jailed-path` when you need**: Path jailing with type-safe boundaries (builds on `soft-canonicalize`).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
