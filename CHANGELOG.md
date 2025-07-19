# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.3] - 2025-07-19

### Documentation
- **Streamlined README**: Reduced verbosity and condensed examples for better readability
- **Added Security Examples**: Added security validation examples with proper jail directory handling
- **Enhanced Comparison Table**: Added "Prevents symlink jail breaks" row highlighting security advantages
- **Added Ecosystem Context**: Added footnote showing `jailed-path` dependency relationship
- **Added Usage Guidance**: Added note clarifying when to use `std::fs::canonicalize` vs `soft_canonicalize`

## [0.0.2] - 2025-07-18

### Changed
- **Improved Algorithm**: Redesigned canonicalization algorithm inspired by Python's `pathlib.Path.resolve(strict=False)`
- **Better Performance**: Switched from "find existing prefix" approach to incremental symlink resolution
- **Reduced I/O**: Now performs lexical resolution first, only checking filesystem when paths actually exist
- **Enhanced Efficiency**: Single-pass processing instead of multiple walks up the directory tree

### Improved
- **Windows Compatibility**: Better handling of Windows path edge cases and root component preservation
- **Root Traversal**: Fixed excessive `..` component handling to properly maintain absolute paths on Windows
- **Symlink Resolution**: More robust incremental symlink resolution strategy
- **Code Quality**: Cleaner, more maintainable implementation with better separation of concerns

### Documentation
- Updated README with Python `pathlib.Path.resolve()` inspiration
- Enhanced algorithm description to reflect new lexical + incremental approach
- Improved performance section with updated characteristics
- Added `normpath::PathExt::normalize` to comparison table for comprehensive ecosystem overview
- Updated Quick Start example to reference version 0.0.2

### Technical Details
- Lexical resolution now processes `..` and `.` components mathematically before filesystem access
- Incremental symlink resolution builds path component-by-component
- Optimized filesystem access patterns for better performance
- Maintained backward compatibility and all existing security guarantees

## [0.0.1] - 2025-07-18

### Added
- Initial release of `soft-canonicalize` crate
- `soft_canonicalize()` function for pure path canonicalization
- Support for non-existing paths through logical path resolution
- Cross-platform compatibility (Windows, macOS, Linux)
- Comprehensive test suite with 7 test cases covering:
  - Existing path canonicalization
  - Non-existing path handling
  - Deep nested non-existing paths
  - Relative path resolution
  - Directory traversal (`..`) component handling
  - Mixed existing/non-existing path resolution
  - Root boundary traversal protection
- Zero-dependency implementation using only std
- Security-focused algorithm with mathematical path resolution
- Comprehensive documentation with examples
- Basic usage example demonstrating all major features
- Security demo example showing directory traversal prevention

### Features
- **Pure Algorithm**: No filesystem modification during canonicalization
- **Directory Traversal Security**: Logical resolution of `..` components before filesystem access
- **Symlink Resolution**: Proper handling of symlinks in existing path portions
- **Performance**: O(n) time complexity with minimal filesystem access
- **Cross-Platform**: Handles Windows drive letters, UNC paths, and Unix absolute paths
- **Zero-Cost**: Minimal memory overhead with efficient path processing

### Documentation
- Comprehensive README with usage examples
- API documentation with detailed algorithm explanation
- Security considerations and best practices
- Performance characteristics and complexity analysis
- Cross-platform compatibility notes
- Comparison with existing canonicalization solutions
