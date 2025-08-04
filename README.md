# soft-canonicalize

[![Crates.io](https://img.shields.io/crates/v/soft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![CI](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)

A pure Rust library for path canonicalization that works with non-existing paths.

Unlike `std::fs::canonicalize()`, this library resolves and normalizes paths even when components don't exist on the filesystem. Useful for security validation, path preprocessing, and working with paths before file creation.

**Comprehensive test suite with 59 tests ensuring 100% behavioral compatibility with std::fs::canonicalize for existing paths.**

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
soft-canonicalize = "0.1.3"
```

### Basic Usage

```rust
use soft_canonicalize::soft_canonicalize;

// Works even if file doesn't exist!
let user_path = soft_canonicalize("../../../etc/passwd")?;

let jail_path = std::fs::canonicalize("/safe/jail/dir").expect("Jail directory must exist");

let is_safe = user_path.starts_with(&jail_path); // false - attack blocked!
```

## Use Cases

- **Web servers**: Path validation before file creation
- **Build tools**: Resolving non-existing output paths  
- **Security applications**: Safe path handling with symlink resolution

## How It Works

1. **Lexical Resolution**: Process `..` and `.` components without filesystem access
2. **Incremental Symlink Resolution**: Resolve symlinks as encountered using `std::fs::canonicalize`
3. **Hybrid Approach**: Uses `std::fs::canonicalize` for existing path portions, lexical resolution for non-existing parts
4. **Optimized Access**: Only check filesystem when components exist

**Implementation**: Finds the longest existing path prefix, canonicalizes it with `std::fs::canonicalize`, then appends the remaining non-existing components. This ensures you get the same results as the standard library for existing paths, with extended support for non-existing paths.

## Performance & Compatibility

- **Time**: O(k) existing components (best: O(1), worst: O(n))
- **Space**: O(n) component storage  
- **Cross-platform**: Windows (drive letters, UNC), Unix (symlinks)
- **Comprehensive Testing**: 59 tests including Python-inspired edge cases and cross-platform validation
- **100% Behavioral Compatibility**: Passes all std::fs::canonicalize tests for existing paths

## Security

- **Directory Traversal Prevention**: `..` components resolved before filesystem access
- **Symlink Resolution**: Existing symlinks properly resolved
- **No Side Effects**: No temporary files created
- **Path Injection Protection**: Handles various path formats safely

**Security Advantage**: Resolves symlinks, preventing jail break attacks where malicious symlinks point outside intended boundaries (unlike `path_absolutize`).

### Critical Safety Mechanisms

**🔒 Symlink Cycle Detection**: Tracks visited symlinks to prevent infinite recursion and stack overflow attacks. Tested with comprehensive cycle detection tests ensuring robust protection against malicious symlink chains.

**🛡️ Symlinked Directory Jail Break Prevention**: Properly resolves symlinked directories that point outside security boundaries, enabling detection of sophisticated jail escape attempts. Our test suite includes specific scenarios where attackers use symlinked directories (e.g., `jail/uploads/user123 -> /outside/secrets/`) to escape containment when accessing non-existing files through the symlink.

## Comparison with Alternatives

| Use Case                      | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::normalize` | `path_absolutize::absolutize` | `jailed-path`       |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | --------------------- | ----------------------------- | ------------------- |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                     | ✅                             | ✅                   |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                     | ❌                             | ✅                   |
| Zero dependencies             | ✅                   | ✅                       | ❌                     | ❌                     | ❌                             | ❌ (uses this crate) |
| Handles `..` components       | ✅ (resolves)        | ✅ (resolves)            | ✅ (resolves)          | ✅ (resolves)          | ✅ (resolves/validates)        | ✅ (clamps to jail)  |
| Prevents symlink jail breaks  | ✅                   | ✅                       | ✅                     | N/A                   | ❌ (vulnerable)                | ✅                   |
| Built-in path jailing         | ❌                   | ❌                       | ❌                     | ❌                     | ❌ (validation only)           | ✅ (enforcement)     |
| Virtual path display          | ❌                   | ❌                       | ❌                     | ❌                     | ✅                             | ✅                   |
| Type-safe jail markers        | ❌                   | ❌                       | ❌                     | ❌                     | ❌                             | ✅                   |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
