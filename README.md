# soft-canonicalize

[![Crates.io](https://img.shields.io/crates/v/soft-canonicalize.svg)](https://crates.io/crates/soft-canonicalize)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Documentation](https://docs.rs/soft-canonicalize/badge.svg)](https://docs.rs/soft-canonicalize)
[![CI](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions)
[![Security audit](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml/badge.svg)](https://github.com/DK26/soft-canonicalize-rs/actions/workflows/audit.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.70.0-blue.svg)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html)

**Path canonicalization that works with non-existing paths.**

Rust implementation inspired by Python 3.6+ `pathlib.Path.resolve(strict=False)`, providing the same functionality as `std::fs::canonicalize` (Rust's equivalent to Unix `realpath()`) but extended to handle non-existing paths, with optional features for simplified Windows output (`dunce`) and virtual filesystem semantics (`anchored`).

## Why Use This?

**🚀 Works with non-existing paths** - Plan file locations before creating them  
**⚡ Fast** - Mixed workload median performance: Windows ~1.8x (13,840 paths/s), Linux ~3.0x (379,119 paths/s) faster than Python's pathlib (see [benchmark methodology](benches/README.md) for 5-run protocol and environment details)  
**✅ Compatible** - 100% behavioral match with `std::fs::canonicalize` for existing paths, with optional UNC simplification via `dunce` feature (Windows)  
**🎯 Virtual filesystem support** - Optional `anchored` feature for bounded canonicalization within directory boundaries  
**🔒 Robust** - 445 comprehensive tests including symlink cycle protection, malicious stream validation, and edge case handling  
**🛡️ Safe traversal** - Proper `..` and symlink resolution with cycle detection  
**🌍 Cross-platform** - Windows, macOS, Linux with comprehensive UNC/symlink handling  
**🔧 Zero dependencies** - Optional features may add minimal dependencies

## Lexical vs. Filesystem-Based Resolution

Path resolution libraries fall into two categories:

**Lexical Resolution** (no I/O):
- **Performance**: Fast - no filesystem access
- **Accuracy**: Incorrect if symlinks are present (doesn't resolve them)
- **Use when**: You're 100% certain no symlinks exist and need maximum performance
- **Examples**: `std::path::absolute`, `normpath::normalize`

**Filesystem-Based Resolution** (performs I/O):
- **Performance**: Slower - requires filesystem syscalls to resolve symlinks
- **Accuracy**: Correct - follows symlinks to their targets
- **Use when**: Safety is priority over performance, or symlinks may be present
- **Examples**: `std::fs::canonicalize`, `soft_canonicalize`, `dunce::canonicalize`

**Rule of thumb**: If you cannot guarantee symlinks won't be introduced, or if correctness is critical, use filesystem-based resolution.

## Use Cases

### Path Comparison

- **Equality**: Determine if two different path strings point to the same location
- **Containment**: Check if one path is inside another directory

### Common Applications

- **Build Systems**: Resolve output paths during build planning before directories exist
- **Configuration Validation**: Ensure user-provided paths stay within allowed boundaries
- **Deduplication**: Detect when different path strings refer to the same planned location
- **Cross-Platform Normalization**: Handle Windows UNC paths and symlinks consistently

## Quick Start

### Cargo.toml
```toml
[dependencies]
soft-canonicalize = "0.5"
```

### Code Example

```rust
use soft_canonicalize::soft_canonicalize;

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

// With `dunce` feature enabled, paths are simplified when safe
// assert_eq!(
//     result.unwrap().to_string_lossy(),
//     r"C:\Users\user\non\existing\config.json"
// );
```

## Optional Features

- **`anchored`** - Virtual filesystem/bounded canonicalization (cross-platform)
- **`dunce`** - Simplified Windows path output (Windows-only target-conditional dependency)

### Anchored Canonicalization (`anchored` feature)

For **correct symlink resolution within virtual/constrained directory spaces**, use `anchored_canonicalize`. This function implements true virtual filesystem semantics by clamping ALL paths (including absolute symlink targets) to the anchor directory:

```toml
[dependencies]
soft-canonicalize = { version = "0.5", features = ["anchored"] }
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

**For a complete multi-tenant security example**, see:
```bash
cargo run --example virtual_filesystem_demo --features anchored
```

### Simplified Path Output (`dunce` feature, Windows-only)

By default on Windows, `soft_canonicalize` returns paths in extended-length UNC format (`\\?\C:\foo`) for maximum robustness and compatibility with long paths, reserved names, and other Windows filesystem edge cases.

If you need simplified paths (`C:\foo`) for compatibility with legacy Windows applications or user-facing output, enable the **`dunce` feature**:

```toml
[dependencies]
soft-canonicalize = { version = "0.5", features = ["dunce"] }
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

## Comparison with Alternatives

### Feature Comparison

| Feature                          | `soft_canonicalize`           | `std::fs::canonicalize` | `std::path::absolute` | `dunce::canonicalize` |
| -------------------------------- | ----------------------------- | ----------------------- | --------------------- | --------------------- |
| Resolution type                  | Filesystem-based              | Filesystem-based        | Lexical               | Filesystem-based      |
| Works with non-existing paths    | ✅                             | ❌                       | ✅                     | ❌                     |
| Resolves symlinks                | ✅                             | ✅                       | ❌                     | ✅                     |
| Simplified Windows paths         | ✅ (opt-in `dunce` feature)    | ❌ (UNC)                 | ❌ (varies)            | ✅                     |
| Virtual/bounded canonicalization | ✅ (opt-in `anchored` feature) | ❌                       | ❌                     | ❌                     |
| Zero dependencies                | ✅ (default)                   | ✅                       | ✅                     | ✅                     |

### When to Use Each

**Choose `soft_canonicalize` when:**
- ✅ You need `std::fs::canonicalize` behavior for paths that don't exist yet
- ✅ Planning file locations before creating them (build systems, config generation)
- ✅ You want virtual filesystem/bounded canonicalization (with `anchored` feature)
- ✅ You need simplified Windows paths for legacy apps (with `dunce` feature)

**Choose alternatives when:**
- **`std::fs::canonicalize`** - All paths exist; standard library is sufficient
- **`std::path::absolute`** - You only need absolute paths without symlink resolution (lexical, fast)
- **`dunce::canonicalize`** - Windows-only, all paths exist, just need UNC simplification
- **`normpath::normalize`** - Lexical normalization only, no filesystem I/O (fast but doesn't resolve symlinks)
- **`path_absolutize`** - Absolute path resolution without symlink following, with CWD caching optimizations

## Related Projects

- **[strict-path](https://crates.io/crates/strict-path)** - Type-safe path restriction with compile-time guarantees. Uses `soft-canonicalize` internally for path validation and boundary enforcement.

## Security & CVE Coverage

Security does not depend on enabling features. The core API is secure-by-default; the optional `anchored` feature is a convenience for virtual roots. We test all modes (no features; `--features anchored`; `--features anchored,dunce`).

**Built-in protections include:**
- **NTFS Alternate Data Stream (ADS) validation** - Blocks malicious stream placements and traversal attempts
- **Symlink cycle detection** - Bounded depth tracking prevents infinite loops
- **Path traversal clamping** - Never ascends past root/share/device boundaries
- **Null byte rejection** - Early validation prevents injection attacks
- **UNC/device semantics** - Preserves Windows extended-length and device namespace integrity
- **TOCTOU race resistance** - Tested against time-of-check-time-of-use attacks

See [`docs/SECURITY.md`](docs/SECURITY.md) for detailed analysis, attack scenarios, and test references.

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
