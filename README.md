# soft-canonicalize

[![Crates.io](https://img.shields.io/crates/v/soft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Build Status](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)

A pure Rust library for path canonicalization that works with non-existing paths.

Unlike `std::fs::canonicalize()`, this library can resolve and normalize paths even when some or all of the path components don't exist on the filesystem. This is particularly useful for security validation, path preprocessing, and working with paths before creating files.

Inspired by Python's `pathlib.Path.resolve()` behavior, which can resolve paths that don't fully exist on the filesystem.

## Features

- **🚀 Works with non-existing paths**: Canonicalizes paths even when they don't exist
- **🌍 Cross-platform**: Supports Windows, macOS, and Linux
- **⚡ Zero dependencies**: No external dependencies beyond std
- **🔒 Security focused**: Proper handling of `..` components and symlinks
- **🧮 Pure algorithm**: No filesystem modification during canonicalization
- **📏 Zero-cost abstractions**: Minimal performance overhead

## Use Cases

Common scenarios where `soft_canonicalize` excels:
- **Web servers**: Path validation before file creation
- **Build tools**: Resolving non-existing output paths  
- **Security applications**: Safe path handling with symlink resolution

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
soft-canonicalize = "0.0.3"
```

## Example

```rust
use soft_canonicalize::soft_canonicalize;
use std::path::Path;

// Works with existing and non-existing paths
let path = soft_canonicalize("some/path/../other/file.txt")?;

// Security validation (jail must exist)
fn is_safe_path(user_path: &str, jail: &Path) -> std::io::Result<bool> {
    let canonical_user = soft_canonicalize(user_path)?;
    let canonical_jail = std::fs::canonicalize(jail)?; // Jail must exist
    Ok(canonical_user.starts_with(canonical_jail))
}

// Note: Use std::fs::canonicalize when paths must exist,
// soft_canonicalize when they may not exist yet
```

## Algorithm

Combines Python's `Path.resolve()` approach with robust symlink resolution:

1. **Lexical Resolution**: Process `..` and `.` components without filesystem access
2. **Incremental Symlink Resolution**: Resolve symlinks as path components are encountered
3. **Optimized Access**: Only perform filesystem operations when components actually exist

## Security Considerations

This library is designed with security in mind:

- **Directory Traversal Prevention**: `..` components are resolved logically before any filesystem access
- **Symlink Resolution**: Existing symlinks are properly resolved using standard canonicalization  
- **No Side Effects**: No temporary files or directories are created during the canonicalization process
- **Path Injection Protection**: Proper handling of various path formats and edge cases

**Critical Security Advantage**: Unlike `path_absolutize`, this library resolves symlinks, preventing jail break attacks where malicious symlinks point outside the intended directory boundaries.

## Performance

- **Time**: O(n) where n is the number of path components
- **Space**: O(n) for component storage
- **Filesystem Access**: Optimized - only checks existing components

## Cross-Platform Support

Works correctly on Windows (drive letters, UNC paths), Unix-like systems (symlinks), and handles path separators properly across all platforms.

## Comparison with Alternatives

| Use Case                      | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize::absolutize` | `jailed-path`*      |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | ----------------------------- | ------------------- |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                     | ✅                             | ✅                   |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                             | ✅                   |
| Zero dependencies             | ✅                   | ✅                       | ❌                     | ❌                     | ❌                             | ❌ (uses this crate) |
| Handles `..` components       | ✅ (resolves)        | ✅ (resolves)            | ✅ (resolves)          | ✅ (resolves)          | ✅ (safe with virtual root)    | ❌ (rejects)         |
| Prevents symlink jail breaks  | ✅                   | ✅                       | ✅                     | N/A                   | ❌ (vulnerable)                | ✅                   |
| Built-in path jailing         | ❌                   | ❌                       | ❌                     | ❌                     | ✅ (virtual root)              | ✅                   |

*`jailed-path` uses `soft_canonicalize` as a dependency for path resolution.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
