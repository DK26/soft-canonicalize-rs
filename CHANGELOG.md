# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4] - 2025-08-13

### Added
- **Windows 8.3 CVE Protection Suite**: Comprehensive protection against 6 known Windows short filename vulnerabilities:
  - CVE-2019-9855 (LibreOffice): Protection against Windows 8.3 path equivalence handling flaws
  - CVE-2017-17793 (BlogoText): Prevention of backup file access through predictable 8.3 short names  
  - CVE-2020-12279 (Git): Protection against NTFS short name equivalence confusion
  - CVE-2005-0471 (Java): Mitigation of predictable temporary file names from 8.3 truncation
  - CVE-2002-2413 (WebSite Pro): Prevention of script source disclosure via 8.3 equivalent filenames
  - CVE-2001-0795 (LiteServe): Protection against CGI script source disclosure through 8.3 exploitation
- **Security Audit Short Filename Module**: New `src/tests/security_audit/short_filename_bypass.rs` (3 test suites)
- **Windows 8.3 CVE Test Suite**: New `tests/windows_8_3_cve_tests.rs` with 7 comprehensive CVE-specific tests (504 lines)
- **8.3 Detection Validation Tests**: New `tests/test_8_3_detection_validation.rs` (2 security-critical tests, 150 lines)
- **Performance Regression Protection**: New `tests/blackbox_performance_regression.rs` with advanced performance testing:
  - Memory stress testing with very wide paths (1000+ components)
  - Tilde component stress testing (500 iterations)
  - Windows-specific performance attack vectors
  - Concurrent performance stress testing (multi-threaded validation)
  - Algorithmic complexity validation preventing quadratic-time attacks
- **Edge Case Fuzzing Suite**: New `tests/blackbox_edge_case_fuzzing.rs` (4 boundary condition and Unicode tests)

### Security
- **Unicode Filename Security**: Protection against Unicode characters with tildes being misinterpreted as 8.3 short names
- **Cross-Platform Security Validation**: Enhanced test coverage ensuring security properties work across Windows and Unix
- **Performance Attack Prevention**: Comprehensive algorithmic complexity validation with memory exhaustion protection
- **Memory Exhaustion Protection**: Stress testing against memory consumption attacks with 4000+ character components
- **Concurrent Security Testing**: Multi-threaded stress testing (4 threads, 100 iterations each) ensuring security under concurrent load

### Improved
- **Test Module Organization**: Enhanced Windows-only test organization with proper module naming:
  - Renamed `mod tests` to `mod windows_unc_tests` in UNC-related test files for better organization
  - Improved `#[cfg(windows)]` guards for better CI compatibility across platforms
- **Performance Testing**: Advanced memory stress testing with component counts up to 1000 and individual component sizes up to 4000 characters
- **Documentation**: Updated README with comprehensive CVE protection details and security feature documentation
- **Cross-Platform CI**: Improved CI configuration preventing Linux pipeline issues with Windows-only code

## [0.2.3] - 2025-08-12

### Added
- **Windows UNC Path Support**: New Windows-specific implementation with comprehensive UNC path handling
- **Windows Extended-Length Path Support**: Automatic conversion of Drive and UNC paths to `\\?\` extended-length format
- **UNC Path Detection**: Advanced UNC path detection including fallback parsing for raw `\\server\share` patterns
- **Windows Device Namespace Handling**: Lexical-only processing for `\\.\` and `\\?\GLOBALROOT\` device paths
- **Comprehensive UNC Test Suite**: Added 3 new black-box UNC test modules:
  - `tests/blackbox_unc_attacks.rs`: UNC-specific security penetration tests (4 tests)
  - `tests/blackbox_unc_corner_cases.rs`: UNC edge case handling (6 tests)  
  - `tests/blackbox_unc_extras.rs`: Unicode obfuscation and long path tests (8 tests)
- **Enhanced Platform-Specific Tests**: Added 17 new Windows-specific tests in `src/tests/platform_specific.rs`
- **Security Audit UNC Module**: New `src/tests/security_audit/unc.rs` white-box UNC penetration tests (4 tests)

### Improved
- **Windows Path Canonicalization**: Enhanced Windows implementation with proper UNC, Drive, and DeviceNS path handling
- **UNC Server/Share Preservation**: Exact preservation of Unicode sequences in UNC server and share names
- **Mixed Separator Normalization**: Robust handling of mixed `\` and `/` separators in Windows paths
- **Parent Directory Clamping**: Smart `.` and `..` resolution with proper clamping at drive/UNC share roots
- **Unicode Attack Resistance**: Preserves exact Unicode byte sequences to prevent normalization-based security bypasses

### Security Enhancements
- **UNC Jail Break Prevention**: Parent directory traversal cannot escape above UNC share root (`\\server\share`)
- **Drive Root Protection**: Parent traversal properly clamped at drive roots for extended-length paths
- **Long Path Attack Mitigation**: Safe handling of very long paths (>260 chars) using Windows extended-length prefixes
- **Alternate Data Stream Preservation**: Textual preservation of ADS suffixes (`:stream_name`) in path components

## [0.2.2] - 2025-08-12
### Improved
- **Documentation Restructuring**: Major reorganization of README.md and lib.rs documentation for better clarity and user experience
- **Quick Start Section**: Moved installation and basic usage examples to the top of documentation for easier onboarding
- **Algorithm Documentation**: Enhanced technical documentation with detailed time complexity analysis and optimization explanations
- **Performance Information**: Consolidated and improved performance benchmarking information with clearer presentation
- **Security Documentation**: Better organization of security features and vulnerability testing information
- **Code Example Improvements**: Simplified and streamlined code examples for better readability

### Changed
- **Documentation Structure**: Reorganized content flow to prioritize practical usage over technical details
- **Technical Details**: Moved detailed algorithm explanations to more appropriate sections in the documentation

## [0.2.1] - 2025-08-11
### Added
- **Enhanced Security Test Suite**: Comprehensive security audit module reorganization with platform-specific tests
- **Blackbox TOCTOU Attack Testing**: New `blackbox_toctou_attacks.rs` with Time-of-Check-to-Time-of-Use race condition testing
- **Platform-Specific Security Tests**: Dedicated Unix and Windows security test modules for platform-specific edge cases
- **Unicode Security Testing**: Enhanced Unicode path edge case testing including emoji, zero-width characters, and mixed scripts
- **Unix-Specific Testing**: Non-UTF8 filename handling tests with macOS UTF-8 enforcement vs Linux permissive behavior
- **Windows-Specific Testing**: Windows 8.3 short name symlink expansion tests

### Improved
- **Test Organization**: Reorganized security tests into dedicated `security_audit` module structure
- **Cross-Platform Coverage**: Better separation of platform-specific test cases for Unix and Windows
- **Race Condition Testing**: Advanced TOCTOU attack simulation with atomic directory-to-symlink replacement
- **Unicode Handling**: More comprehensive Unicode normalization and encoding bypass prevention tests
- **Error Handling**: Enhanced null byte injection testing with platform-specific error validation

### Fixed
- **Test Structure**: Moved and reorganized security hardening tests from single file to modular security audit structure
- **Platform Compatibility**: Improved handling of platform-specific filesystem limitations and behaviors

## [0.2.0] - 2025-08-09
### Added
- **Major Algorithm Optimization**: Complete rewrite for 1.3x-1.5x performance improvement over Python's pathlib
- **Binary Search Boundary Detection**: Replaced O(n) linear search with O(log n) binary search for existing path components
- **Fast-path Optimization**: Direct `std::fs::canonicalize` for existing paths (inspired by Python's strategy)
- **Single-pass Path Normalization**: Efficient batch processing of `.` and `..` components with minimal allocations
- **Optimized Symlink Resolution**: Smart symlink chain handling with O(1) cycle detection using HashSet
- **Comprehensive Performance Benchmarking**: Added extensive benchmark suite comparing against Python 3.12.4 pathlib

### Performance Improvements
- **Mixed workloads**: 6,089-6,769 paths/s (1.3x-1.5x faster than Python's 4,627 paths/s)
- **Existing paths**: 10,057-12,851 paths/s (1.5x-1.9x faster than Python's ~6,600 paths/s) 
- **Path traversal**: 11,551-13,529 paths/s (1.8x-2.1x faster than Python's ~6,500 paths/s)
- **Non-existing paths**: 1,950-2,072 paths/s (competitive with Python's 2,516-4,441 paths/s)

### Enhanced Security Testing
- **Comprehensive Black-box Security Testing**: New `blackbox_security.rs` test suite with extensive fuzzing and attack simulation
- **Advanced Attack Vector Testing**: Directory traversal, symlink escapes, performance attacks, race conditions, filesystem boundary crossing
- **Windows-specific Security Tests**: Enhanced testing for Windows short names (8.3), device names (CON, NUL, etc.), and NTFS Alternate Data Streams (ADS)
- **Resource Exhaustion Protection**: Added safeguards against long filenames, deep directory structures, and excessive path components
- **Complex Attack Pattern Testing**: Broken symlink jail escapes, case sensitivity bypasses, and API contract violations

### Technical Improvements
- **Algorithm Complexity**: Reduced from O(n) to O(log n) for boundary detection, O(k) overall where k = existing components
- **Memory Optimization**: Efficient component collection with reduced allocations and smarter buffering
- **Cross-platform Robustness**: Improved handling of platform-specific filesystem limits and system symlinks
- **Security Test Coverage**: Comprehensive test suite with 108 security-focused tests covering sophisticated attack patterns

### Code Quality
- **Removed unnecessary clippy allows** and improved code consistency across test modules
- **Better test organization** with clear attack vector categorization and comprehensive documentation
- **Enhanced inline documentation** explaining security test purposes, algorithm optimizations, and performance characteristics

## [0.1.4] - 2025-08-06
### Added
- **Fast-path optimization**: Added fast-path for absolute existing paths without dot components using `std::fs::canonicalize` directly
- **CVE Testing**: Added `src/tests/cve_tests.rs` module with CVE-2022-21658 race condition tests
- **Security Hardening**: Added `src/tests/security_hardening.rs` module with comprehensive security tests including null byte injection, Unicode normalization bypasses, double-encoding attacks, case sensitivity bypasses, and TOCTOU prevention
- **Symlink Resolution Order**: Added `symlink_dotdot_resolution_order` test module validating lexical dot-dot resolution behavior
- **Null Byte Handling**: Added explicit null byte detection for Unix and Windows platforms

### Improved  
- **Symlink Cycle Detection**: Changed from `HashSet<PathBuf>` to `HashSet<Rc<PathBuf>>` for visited symlink tracking
- **Test Coverage**: Added new test modules (`cve_tests`, `security_hardening`, `symlink_dotdot_resolution_order`) 
- **Error Handling**: Enhanced null byte error consistency with `std::fs::canonicalize`

### Fixed
- **Cross-platform Test Compatibility**: Fixed CVE-2022-21658 race condition test to handle macOS symlink canonicalization where `/var` is a symlink to `/private/var`
- **Windows UNC Path Compatibility**: Fixed `std_compat` test to correctly expect Windows UNC path format (`\\?\C:\`) returned by `std::fs::canonicalize`

### Technical
- **Fast-path Implementation**: Added condition checking for `path.is_absolute() && path.exists() && !path.components().any(|c| matches!(c, CurDir | ParentDir))`
- **Memory Optimization**: Use `Rc<PathBuf>` for symlink cycle detection to reduce memory allocations
- **Cross-platform**: Added platform-specific null byte detection using `OsStrExt` traits  
- **Symlink Cycle Detection**: Changed from `HashSet<PathBuf>` to `HashSet<Rc<PathBuf>>` for visited symlink tracking
- **Test Coverage**: Added new test modules (`cve_tests`, `security_hardening`, `symlink_dotdot_resolution_order`) 
- **Error Handling**: Enhanced null byte error consistency with `std::fs::canonicalize`

### Technical
- **Fast-path Implementation**: Added condition checking for `path.is_absolute() && path.exists() && !path.components().any(|c| matches!(c, CurDir | ParentDir))`
- **Memory Optimization**: Use `Rc<PathBuf>` for symlink cycle detection to reduce memory allocations
- **Cross-platform**: Added platform-specific null byte detection using `OsStrExt` traits


## [0.1.3] - 2025-08-04
### Added
- **Security Tests**: Added advanced tests for symlinked directory jail break prevention, including scenarios with new files and nested symlinked directories to ensure robust security boundaries.
- **Edge Case Robustness Module**: Introduced `edge_case_robustness` test module for improved coverage of rare and complex path resolution scenarios.

### Improved
- **Performance Documentation**: Clarified time complexity as O(k) where k = existing path components (best: O(1), worst: O(n)), and updated all relevant documentation and README sections for accuracy.
- **Test Coverage**: Expanded from 51 to 59 tests, including new security and edge case tests, and updated README to reflect the increased coverage.
- **Comparison Table**: Enhanced README comparison table to clarify handling of `..` components, jail enforcement, and type-safe jail markers for all compared crates.
- **Security Documentation**: Added explicit documentation of symlink cycle detection and jail break prevention mechanisms in README, with references to new tests.


## [0.1.2] - 2025-07-20

### Improved
- **Documentation**: Enhanced README.md with better code example formatting and improved readability
- **Code Examples**: Added proper spacing in code examples for better visual separation of logical steps
- **Security Examples**: Improved security validation example with clearer `.expect()` usage patterns

## [0.1.2] - 2025-07-20

### Improved
- **Documentation**: Enhanced README.md with better code example formatting and improved readability
- **Code Examples**: Added proper spacing in code examples for better visual separation of logical steps
- **Security Examples**: Improved security validation example with clearer `.expect()` usage patterns

## [0.1.1] - 2025-07-20

### Added
- **Comprehensive Test Suite**: Added 40 unit tests across 11 specialized modules, including Python-inspired edge cases, cross-platform validation, symlink handling, and advanced canonicalization scenarios
- **Python-Inspired Testing**: Added comprehensive edge case testing derived from Python's mature pathlib.resolve() implementation
- **Performance Optimization**: Added hybrid boundary detection optimization that uses `std::fs::canonicalize` for existing path portions before falling back to incremental resolution

### Improved
- **Test Coverage**: Expanded from 28 tests to 51 comprehensive tests (37 unit + 11 std compatibility + 3 doctests) covering Python-inspired edge cases, cross-platform scenarios, and advanced canonicalization patterns
- **Performance**: Enhanced boundary detection algorithm for better performance on paths with existing prefixes
- **Cross-Platform Robustness**: Enhanced CI-safe testing patterns with panic-safe cleanup and working directory handling
- **Documentation**: Enhanced "How It Works" section to clearly explain use of `std::fs::canonicalize` internally

## [0.1.0] - 2025-07-19

### Added
- **std Library Compatibility Tests**: Added comprehensive test suite (`tests/std_compat.rs`) importing and adapting original std library canonicalize tests to ensure 100% behavioral compatibility for existing paths
- **API Enhancement**: Updated `soft_canonicalize` to accept `impl AsRef<Path>` instead of generic `<P: AsRef<Path>>` for cleaner, more modern API following Rust 2018+ best practices
- **Contributing Guidelines**: Added `CONTRIBUTING.md` with project philosophy, AI prompt for contributors, testing guidelines, and development workflow
- **Documentation Examples**: Added comprehensive examples showing usage with different path types (`&str`, `PathBuf`, `&Path`, etc.)

### Changed
- **API Modernization**: Function signature changed from `soft_canonicalize<P: AsRef<Path>>(path: P)` to `soft_canonicalize(path: impl AsRef<Path>)` for consistency with modern Rust patterns
- **Test Infrastructure**: Standardized all tests to use `tempfile` crate instead of custom temporary directory implementation for better reliability and consistency
- **Version Bump**: First stable release (0.1.0) indicating API stability and production readiness

### Improved
- **Test Coverage**: Added 8 new tests specifically for API compatibility with different path parameter types
- **Test Reliability**: Replaced custom `create_temp_dir()` and `cleanup_temp_dir()` functions with industry-standard `tempfile::tempdir()` for automatic cleanup and thread safety
- **Code Quality**: Removed ~40 lines of custom temporary directory logic in favor of standard practices
- **Documentation**: Enhanced function documentation with more comprehensive examples showing all supported input types

### Technical Details
- Maintains 100% backward compatibility for function behavior
- All 28 tests pass (14 unit tests + 11 std compatibility tests + 3 doctests)
- Zero breaking changes for existing users
- Enhanced API ergonomics without performance impact
- Standardized development and testing practices

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
- **Performance**: O(k) time complexity where k = existing components (k ≤ n), with minimal filesystem access
- **Cross-Platform**: Handles Windows drive letters, UNC paths, and Unix absolute paths
- **Zero-Cost**: Minimal memory overhead with efficient path processing

### Documentation
- Comprehensive README with usage examples
- API documentation with detailed algorithm explanation
- Security considerations and best practices
- Performance characteristics and complexity analysis
- Cross-platform compatibility notes
- Comparison with existing canonicalization solutions
