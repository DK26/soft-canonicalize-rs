# soft-canonicalize

[![Crates.io](https://img.shields.io/crates/v/soft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Build Status](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)

A pure Rust library for path canonicalization that works with non-existing paths.

Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths even when components don't exist on the filesystem. Useful for security validation, path preprocessing, and working with paths before file creation.

**Passes all original std library canonicalize tests plus additional compatibility tests.**

Inspired by Python's `pathlib.Path.resolve()` behavior.

## Features

- **🚀 Works with non-existing paths**: Canonicalizes paths that don't exist yet
- **🌍 Cross-platform**: Windows, macOS, and Linux support
- **⚡ Zero dependencies**: Only uses std library
- **🔒 Security focused**: Proper `..` and symlink handling
- **🧮 Pure algorithm**: No filesystem modification

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
soft-canonicalize = "0.1.0"
```

### Basic Usage

```rust
use soft_canonicalize::soft_canonicalize;

// Works with existing and non-existing paths
let path = soft_canonicalize("some/path/../other/file.txt")?;

// Security validation
fn is_safe_path(user_path: &str, jail: &Path) -> std::io::Result<bool> {
    let canonical_user = soft_canonicalize(user_path)?;
    let canonical_jail = std::fs::canonicalize(jail)?;
    Ok(canonical_user.starts_with(canonical_jail))
}
```

## Use Cases

- **Web servers**: Path validation before file creation
- **Build tools**: Resolving non-existing output paths  
- **Security applications**: Safe path handling with symlink resolution

## How It Works

1. **Lexical Resolution**: Process `..` and `.` components without filesystem access
2. **Incremental Symlink Resolution**: Resolve symlinks as encountered
3. **Optimized Access**: Only check filesystem when components exist

## Performance & Compatibility

- **Time**: O(n) path components
- **Space**: O(n) component storage  
- **Cross-platform**: Windows (drive letters, UNC), Unix (symlinks)
- **Testing**: 100% behavioral compatibility with `std::fs::canonicalize` for existing paths

## Security

- **Directory Traversal Prevention**: `..` components resolved before filesystem access
- **Symlink Resolution**: Existing symlinks properly resolved
- **No Side Effects**: No temporary files created
- **Path Injection Protection**: Handles various path formats safely

**Security Advantage**: Resolves symlinks, preventing jail break attacks where malicious symlinks point outside intended boundaries (unlike `path_absolutize`).

## Comparison with Alternatives

| Use Case                      | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize::absolutize` | `jailed-path`*      |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | ----------------------------- | ------------------- |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                     | ✅                             | ✅                   |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                             | ✅                   |
| Zero dependencies             | ✅                   | ✅                       | ❌                     | ❌                     | ❌                             | ❌ (uses this crate) |
| Handles `..` components       | ✅ (resolves)        | ✅ (resolves)            | ✅ (resolves)          | ✅ (resolves)          | ✅ (safe with virtual root)    | ❌ (rejects)         |
| Prevents symlink jail breaks  | ✅                   | ✅                       | ✅                     | N/A                   | ❌ (vulnerable)                | ✅                   |
| Built-in path jailing         | ❌                   | ❌                       | ❌                     | ❌                     | ✅ (virtual root)              | ✅                   |

*`jailed-path` uses `soft_canonicalize` as a dependency.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
