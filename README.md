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
**⚡ Fast** - Windows: ~1.4–2.0x faster; Linux: ~2.5–4.7x faster than Python's pathlib (mixed workloads)  
**✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths  
**🔒 Secure** - 111 comprehensive tests including security scenarios and path traversal prevention  
**🛡️ Robust path handling** - Proper `..` and symlink resolution with cycle detection  
**🌍 Cross-platform** - Windows, macOS, Linux with proper UNC/symlink handling  
**🔧 Zero dependencies** - Only uses std library

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

**📝 Note:** Symlinks are also automatically resolved with cycle detection.

## Quick Start

```toml
[dependencies]
soft-canonicalize = "0.2.0"
```

## How It Works

This library implements an optimized, single-pass path resolution algorithm with the following stages:

1. **Input validation**: Handle empty paths early (matches `std::fs::canonicalize` behavior)
2. **Absolute path conversion**: Convert relative paths to absolute using the current working directory
3. **Lexical normalization**: Resolve `.` and `..` components without filesystem calls
4. **Fast-path attempt**: Try `std::fs::canonicalize` once; if it succeeds (path fully exists), return early
5. **Null byte validation**: Check for embedded null bytes (platform-specific error handling)
6. **Existing-prefix discovery**: Walk components left-to-right to find the deepest existing ancestor; resolve symlinks inline with cycle detection
7. **Conditional anchor canonicalization**: If any symlink was encountered, canonicalize the deepest existing ancestor once to normalize casing/UNC details
8. **Result reconstruction**: Append non-existing components to the canonicalized base
9. **Windows normalization**: Ensure extended-length prefix (\\?\) for absolute Windows paths when needed

This approach matches `std::fs::canonicalize` behavior for existing paths, while extending support to non-existing paths with minimal overhead.

## Performance & Benchmarks

Cross-platform results against Python pathlib (mixed workloads):

- Windows (Python baseline ~5.9–6.9k paths/s): Rust ~9.5–11.9k paths/s → ~1.4–2.0x faster
- Linux (Python baseline ~95k paths/s): Rust ~238k–448k paths/s → ~2.5–4.7x faster

### Key Optimizations

- **Fast-path for existing paths**: Direct `std::fs::canonicalize()` when the entire normalized path exists
- **Single-pass existing-prefix discovery**: Finds the deepest existing ancestor and handles symlinks inline
- **Streaming lexical normalization**: Resolves `..` and `.` without extra allocations using direct push/pop operations
- **Minimal syscalls**: Early-exit when first component is missing; avoid redundant filesystem probes
- **Platform-specific optimizations**: Windows extended-length (\\?\) handling; robust Unix symlink behavior

### Detailed Results

Measured with the benches in this repo (see `benches/`) against Python 3.10/3.12 pathlib:

- Windows mixed workload: Rust ~9.5k–11.9k vs Python ~5.9k–6.9k paths/s (≈1.4–2.0x)
- Linux mixed workload: Rust ~238k–448k vs Python ~95k paths/s (≈2.5–4.7x)

Performance varies by hardware and OS/filesystem. See the bench outputs for per-scenario numbers.

For detailed benchmarks, analysis, and testing procedures, see the [`benches/`](benches/) directory.

## Security

- **Directory Traversal Prevention**: `..` components resolved before filesystem access
- **Symlink Resolution**: Existing symlinks properly resolved with cycle detection  
- **Cross-platform Path Normalization**: Handles Windows drive letters, UNC paths, and Unix absolute paths
- **Explicit Null Byte Detection**: Consistent error handling across platforms (unlike OS-dependent behavior)

**Note on Symlink Handling**: Unlike some path normalization libraries, this crate resolves symlinks when they exist, providing stronger guarantees about the final path destination. This behavior matches `std::fs::canonicalize` and can help prevent certain types of path-based security issues in applications that require it.

### Test Coverage

**111 comprehensive tests** including:

- **10 std::fs::canonicalize compatibility tests** ensuring 100% behavioral compatibility
- **32 security penetration tests** covering CVE-2022-21658 and path traversal attacks  
- **Python pathlib test suite adaptations** for cross-language validation
- **Platform-specific tests** for Windows, macOS, and Linux edge cases
- **Performance and stress tests** validating behavior under various conditions

### Path Resolution Features

**🔒 Symlink Cycle Detection**: Tracks visited symlinks to prevent infinite recursion and stack overflow attacks. Tested with comprehensive cycle detection tests ensuring robust protection against malicious symlink chains.

**🛡️ Symlink Resolution for Security Testing**: Properly resolves symlinked directories to their actual targets, enabling security applications to detect when paths escape intended boundaries. Our test suite includes scenarios where symlinked directories (e.g., `jail/uploads/user123 -> /outside/secrets/`) point outside security boundaries, allowing applications to test for jail break vulnerabilities.

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
