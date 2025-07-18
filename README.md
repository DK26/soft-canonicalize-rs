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

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
soft-canonicalize = "0.0.2"
```

## Examples

### Basic Usage

```rust
use soft_canonicalize::soft_canonicalize;
use std::path::Path;

fn main() -> std::io::Result<()> {
    // Works with existing paths (same as std::fs::canonicalize)
    let existing = soft_canonicalize(&std::env::temp_dir())?;
    println!("Existing path: {:?}", existing);

    // Also works with non-existing paths
    let non_existing = soft_canonicalize(
        &std::env::temp_dir().join("some/deep/non/existing/path.txt")
    )?;
    println!("Non-existing path: {:?}", non_existing);

    Ok(())
}
```

### Directory Traversal Handling

```rust
use soft_canonicalize::soft_canonicalize;
use std::path::Path;

fn main() -> std::io::Result<()> {
    // Resolves .. components logically
    let traversal = soft_canonicalize(
        Path::new("some/path/../other/file.txt")
    )?;
    println!("Resolved: {:?}", traversal);
    // Output: "/current/working/dir/some/other/file.txt"
    
    // Works with complex traversal patterns
    let complex = soft_canonicalize(
        Path::new("deep/nested/path/../../final/file.txt")
    )?;
    println!("Complex: {:?}", complex);
    // Output: "/current/working/dir/deep/final/file.txt"

    Ok(())
}
```

### Security Validation

```rust
use soft_canonicalize::soft_canonicalize;
use std::path::{Path, PathBuf};

fn validate_user_path(user_input: &str, jail_dir: &Path) -> Result<PathBuf, String> {
    // Canonicalize the user input (may not exist yet)
    let canonical_path = soft_canonicalize(Path::new(user_input))
        .map_err(|e| format!("Invalid path: {}", e))?;
    
    // Ensure it's within the jail directory
    if canonical_path.starts_with(jail_dir) {
        Ok(canonical_path)
    } else {
        Err("Path escapes jail boundary".to_string())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jail = std::env::temp_dir().join("user_files");
    let canonical_jail = soft_canonicalize(&jail)?;
    
    // Safe path
    match validate_user_path("documents/file.txt", &canonical_jail) {
        Ok(path) => println!("Safe path: {:?}", path),
        Err(e) => println!("Blocked: {}", e),
    }
    
    // Malicious path with directory traversal
    match validate_user_path("documents/../../../etc/passwd", &canonical_jail) {
        Ok(path) => println!("Safe path: {:?}", path),
        Err(e) => println!("Blocked: {}", e), // This will be blocked
    }
    
    Ok(())
}
```

## Algorithm

The soft canonicalization algorithm works in the following steps:

1. **Absolute Path Conversion**: Convert relative paths to absolute paths using the current working directory
2. **Lexical Resolution**: Process `..` and `.` components mathematically without filesystem access (inspired by Python's `Path.resolve()`)
3. **Incremental Symlink Resolution**: Build the path component by component, resolving symlinks as they are encountered
4. **Efficient Processing**: Only perform filesystem operations when a path component actually exists

This approach combines Python's efficient lexical processing with robust symlink resolution, providing security benefits while supporting non-existing paths.

## Security Considerations

This library is designed with security in mind:

- **Directory Traversal Prevention**: `..` components are resolved logically before any filesystem access
- **Symlink Resolution**: Existing symlinks are properly resolved using standard canonicalization  
- **No Side Effects**: No temporary files or directories are created during the canonicalization process
- **Path Injection Protection**: Proper handling of various path formats and edge cases

## Performance

- **Time Complexity**: O(n) where n is the number of path components
- **Space Complexity**: O(n) for component storage during processing  
- **Filesystem Access**: Optimized - only checks components that actually exist
- **Memory Usage**: Very low overhead, single-pass processing with minimal allocations

## Cross-Platform Support

This library works correctly on:

- **Windows**: Handles drive letters (C:), UNC paths (\\\\server\\share), and case normalization
- **Unix-like systems**: Handles absolute paths starting with `/` and proper symlink resolution
- **All platforms**: Correct handling of path separators (`/` vs `\\`) and component normalization

## Comparison with Alternatives

| Feature                       | `soft_canonicalize` | `std::fs::canonicalize` | `dunce::canonicalize` | `normpath::PathExt::normalize` |
| ----------------------------- | ------------------- | ----------------------- | --------------------- | ------------------------------ |
| Works with non-existing paths | ✅                   | ❌                       | ❌                     | ✅                              |
| Resolves symlinks             | ✅                   | ✅                       | ✅                     | ❌                              |
| Handles `..` components       | ✅                   | ✅                       | ✅                     | ✅                              |
| Cross-platform                | ✅                   | ✅                       | ✅                     | ✅                              |
| Zero dependencies             | ✅                   | ✅                       | ❌                     | ❌                              |
| No filesystem modification    | ✅                   | ✅                       | ✅                     | ✅                              |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
