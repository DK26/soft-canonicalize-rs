# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.4] - 2025-10-11

### Fixed

- **`anchored_canonicalize`**: Relative symlinks with excessive `..` components are now clamped during resolution instead of relying on caller post-processing
  - Improves performance by eliminating redundant safety checks
  - Enforces virtual filesystem semantics at the correct layer (defense-in-depth)
  - No observable behavior change - final output identical to previous versions
  - Both absolute and relative symlinks now consistently clamped in `resolve_anchored_symlink_chain`
- **Windows path prefix comparison bug**: Fixed component-based comparison to properly handle Windows path prefix format differences (`Prefix::VerbatimDisk` vs `Prefix::Disk`)
  - Previously, symlink clamping could fail when anchor had `\\?\` prefix but resolved symlink didn't (or vice versa)
  - Added `components_equal_windows_aware` helper that treats `VerbatimDisk(C)` and `Disk(C)` as equivalent
  - Fixes 3 test failures on GitHub Actions Windows runners with symlink privileges enabled

### Changed

- Documentation reorganization: "How It Works" and security sections moved lower for better user experience
- Improved discoverability and clarity of advanced implementation details

### Added

- New symlink-first resolution tests for anchored canonicalization, including Windows-compatible coverage
- Comprehensive test coverage for relative symlink clamping behavior (7 new tests in `anchored_relative_symlink_clamping.rs`)
- Feature-conditional assertions in Windows tests to properly validate dunce vs non-dunce output formats

## [0.4.3] - 2025-10-11

### Added

- **Documentation discoverability improvements**
  - Added `#[doc(alias)]` attributes to improve API discoverability:
    - `soft_canonicalize`: aliases for `realpath`, `canonicalize`, `resolve`, `absolute`
    - `anchored_canonicalize`: aliases for `chroot`, `jail`, `sandbox`, `virtual_root`
    - `MAX_SYMLINK_DEPTH`: aliases for `ELOOP`, `symlink_limit`
  - Added `#[must_use]` attributes to `soft_canonicalize` and `anchored_canonicalize` to prevent accidental result dropping

### Changed

- **Documentation enhancements**
  - Enhanced "Why Use This?" section to mention `dunce` feature in compatibility bullet point
  - Enhanced "Why Use This?" section to highlight `anchored` feature for virtual filesystem support
  - Fixed cross-platform doctest compatibility by adding `#[cfg(windows)]` to Windows-specific Basic Example

### Fixed

- Fixed raw string escaping in doc comments and test examples ([#34](https://github.com/DK26/soft-canonicalize-rs/pull/34))

## [0.4.2] - 2025-10-08

### Added

- **New `virtual_filesystem_demo` example** demonstrating multi-tenant security scenarios ([#31](https://github.com/DK26/soft-canonicalize-rs/pull/31))
  - Complete example showing anchored canonicalization preventing directory traversal attacks
  - Demonstrates proper symlink clamping in virtual filesystem contexts
  - Includes both attack scenarios (what doesn't work) and correct usage patterns

### Changed

- **Documentation polish and reorganization**
  - Improved README.md tagline for better clarity and searchability (mentions `realpath` for SEO)
  - Enhanced "Why Use This?" section with clearer value propositions
  - Streamlined "Comparison with Alternatives" section with "When to Use Each" bullet points
  - Removed redundant "Testing & Quality" section (covered by value props)
  - Added references to `virtual_filesystem_demo` example in README and lib.rs
  - Enhanced lib.rs documentation with comprehensive "Why Use This?" section matching README quality
  - Eliminated redundant messaging between sections

## [0.4.1] - 2025-10-08

### Added

- **New optional `dunce` feature** for simplified Windows path output (Windows-only) ([#26](https://github.com/DK26/soft-canonicalize-rs/issues/26))
  - **Windows-specific**: Feature only affects Windows; has no effect and adds no dependencies on Unix/Linux/macOS
  - Configured as target-conditional dependency in Cargo.toml (`[target.'cfg(windows)'.dependencies]`)
  - When enabled on Windows, returns familiar paths (`C:\foo`) instead of extended-length UNC format (`\\?\C:\foo`) when safe
  - Zero code duplication - delegates all safety logic to the battle-tested [dunce](https://crates.io/crates/dunce) crate
  - Opt-in feature provides user choice between security (UNC, default) and compatibility (simplified)
  - Captures the dunce crate's market: "Like dunce, but works with non-existing paths"
  - Automatically keeps UNC format for:
    - Paths longer than 260 characters
    - Reserved device names (CON, PRN, NUL, COM1-9, LPT1-9)
    - Paths with trailing spaces or dots
    - Paths containing literal `..` components
  
- **Comprehensive exotic edge case tests** from dunce/MSDN analysis ([#28](https://github.com/DK26/soft-canonicalize-rs/issues/28))
  - 14 new tests covering Windows filename edge cases
  - Reserved names with extensions and trailing characters
  - Unicode normalization and multibyte UTF-16 handling
  - Long paths and deeply nested directories
  - Control characters in different contexts
  - All edge cases verified - no implementation changes needed

- **Cross-platform path handling tests** (`tests/cross_platform_paths.rs`)
  - 12 new tests verifying graceful handling of Windows-style paths on Unix and vice versa
  - Unix tests: Windows UNC paths, drive letters, backslash handling, absolute paths
  - Windows tests: UNC network paths, device namespaces, mixed separators, Unix-style forward slashes
  - Important for build systems, package managers, and cross-compilation tools

- **Comprehensive Windows 8.3 short name test coverage**
  - 16 new tests for 8.3 detection and expansion behavior (`windows_8_3_actual_expansion.rs`, `windows_8_3_toctou_anchored.rs`, `windows_8_3_unit_tests.rs`)
  - 9 new tests for symlink+8.3 interaction scenarios (`windows_symlink_8_3_interaction.rs`)
  - Validates correct handling of short names, TOCTOU race conditions, and symlink resolution with extended-length prefixes

- **Documentation improvements** ([#23](https://github.com/DK26/soft-canonicalize-rs/issues/23), [#24](https://github.com/DK26/soft-canonicalize-rs/issues/24), [#25](https://github.com/DK26/soft-canonicalize-rs/issues/25))
  - Added `realpath()` (libc) to comparison tables for better discoverability
  - Added `std::path::absolute()` to comparison tables
  - Updated version references from 0.3 to 0.4
  - Enhanced feature documentation in README and lib.rs

### Fixed

- **Critical bug in `anchored_canonicalize` symlink clamping** ([#27](https://github.com/DK26/soft-canonicalize-rs/issues/27))
  - **Issue**: When a relative symlink resolved outside the anchor boundary, the function would discard all path information and return just the anchor itself
  - **Impact**: Broke virtual filesystem semantics for downstream crates (strict-path-rs)
  - **Fix**: Implemented proper common ancestor detection to preserve path structure while clamping
  - **Example**: `jail/special -> ../../opt/subdir` now correctly resolves to `jail/opt/subdir/...` instead of just `jail`
  - Discovered via downstream CI failure in strict-path-rs ([issue #18](https://github.com/DK26/strict-path-rs/issues/18))

### Performance

- **Updated benchmark results** (October 8, 2025, 5-run median protocol)
  - Windows: 9,907 paths/s (1.31x faster than Python pathlib) — improved from 7,985 paths/s
  - Linux (WSL): 238,038 paths/s (2.90x faster than Python 3.13 pathlib) — improved from 1.68x to 2.90x speedup

### Changed

- **Test suite enhancements**
  - Test count increased from 339 to 434 tests (429 unit tests + 5 doc tests)
  - Added comprehensive dunce feature test suite (585 lines)
  - Added format verification tests to ensure exact output format per feature state
  - Added cross-platform path handling tests (12 tests, 369 lines)
  - Added Windows 8.3 short name tests (25 tests across 4 files)
  - Added exotic edge case tests (14 tests, 880 lines)
  - Refactored 13+ test files to use explicit `#[cfg]` blocks for feature-conditional testing
  - Enhanced CI with feature matrix testing (anchored, anchored+dunce combinations)

### Internal

- Performance optimizations: Added `#[inline]` to hot paths (`simple_normalize_path`, `compute_existing_prefix`, `resolve_simple_symlink_chain`)
- Enhanced CI scripts (`ci-local.ps1`, `ci-local.sh`) with feature combination testing

## [0.4.0] - 2025-10-05

### Performance

- **Optimized `soft_canonicalize` and `anchored_canonicalize` functions**
  - Reduced allocations by eliminating unnecessary temporary `OsString` instances
  - Simplified control flow by replacing queue-based iteration with direct component streaming
  - Reduced memory usage by removing `VecDeque` overhead
  - Optimized string comparisons to avoid unnecessary allocations
  - **Benchmark Results (October 2025, 5-run median protocol)**:
    - Windows: 7,985 paths/s (1.57x faster than Python pathlib)
    - Linux (WSL): 239,059 paths/s (1.68x faster than Python 3.13 pathlib)
  - See `benches/README.md` for complete benchmark data and protocol

### Changed

- **BEHAVIOR CHANGE**: `anchored_canonicalize` now clamps absolute symlinks to the anchor (virtual filesystem semantics)
  - **Previous Behavior**: Absolute symlinks resolved to their actual filesystem targets (e.g., `/etc/config`)
  - **New Behavior**: Absolute symlink targets are reinterpreted relative to the anchor (e.g., `/etc/config` → `anchor/etc/config`)
  - **Implementation**: New `resolve_anchored_symlink_chain()` function with dual-case clamping:
    - Case 1: Target within anchor → strip anchor prefix, rejoin to anchor
    - Case 2: Target outside anchor → strip root prefix, join to anchor
  - **Rationale**: Makes `anchored_canonicalize` behave like a virtual filesystem where the anchor is the root
  - **Use Cases**: Archive extraction, containerized paths, virtual directory trees where absolute symlinks should stay within the tree

### Added

- **Enhanced documentation**: Comprehensive explanation of the dual-case clamping algorithm in `src/symlink.rs` and `src/lib.rs`

### Testing

- **Added**: Comprehensive CVE-2024-2025 security test suite (`src/tests/cve_2024_2025_security.rs`)
  - 30+ blackbox/whitebox tests covering recent CVE patterns:
    - CVE-2025-27210: Windows device name path traversal
    - CVE-2025-23084: Windows drive handling vulnerabilities
    - CVE-2024-23651: Symlink TOCTOU race conditions (Docker/Buildkit)
    - CVE-2024-21626: File descriptor leaks via /proc/self/fd
    - CVE-2025-9566: Podman symlink traversal (ConfigMap/Secret escapes)
    - CVE-2024-38819: Path traversal via crafted HTTP requests
  - Tests validate resilience against similar attack patterns

- **Added**: Dedicated symlink clamping test suite (`src/tests/anchored_symlink_clamping.rs`)
  - 12+ tests documenting and verifying correct absolute symlink clamping behavior
  - Archive extraction scenarios, chained symlinks, mixed absolute/relative chains
  - Confirms that ALL absolute symlink targets are clamped to anchor (virtual filesystem semantics)

- **Added**: Windows path stripping tests (`src/tests/windows_path_stripping.rs`)
  - Validates `strip_root_prefix` logic for all Windows path types
  - Covers: disk paths, UNC paths, extended-length paths, verbatim paths, drive-relative paths

- **Updated**: Test names updated to reflect new behavior
  - `absolute_symlink_drops_clamp` → `absolute_symlink_is_clamped` (multiple files)
  - Test assertions updated to verify clamping instead of escape

### Documentation

- **Updated**: Aligned documentation with new behavior
  - Updated `docs/SECURITY.md`, README.md, and inline function documentation to match the new implementation
  - Changed "drop the clamp by design" statements to "are clamped to the anchor"
  - Added detailed examples showing how absolute symlink clamping works in practice
  - Clarified that anchor acts as a chroot-like virtual root for all path resolution

### Notes

- **For Users**: If you're using `anchored_canonicalize`, absolute symlinks now resolve relative to the anchor (virtual filesystem semantics). Previously they resolved to their actual filesystem location.
- **Example**: A symlink `anchor/link -> /etc/config` now resolves to `anchor/etc/config` instead of `/etc/config`
- **Compatibility**: If your code expected absolute symlinks to resolve to their actual filesystem targets, this behavior has changed. The anchor now acts as a virtual root for all path resolution.
- All existing tests pass; 50+ new tests added covering the new clamping behavior.

## [0.3.6] - 2025-09-15

### Fixed
- Corrected `strict-path` feature comparison: `VirtualRoot` (not `PathBoundary`) is the correct equivalent to our `anchored_canonicalize` functionality

## [0.3.5] - 2025-09-13

### Changed
- Updated feature comparison table in README.md to reflect the new `strict-path` crate, replacing the previous `jailed-path` reference
- Clarified "Anchored canonicalization" feature description as "Virtual/bounded canonicalization" for better terminology alignment
- Version bump to 0.3.5

### Documentation
- Enhanced crate comparison clarity by updating the feature comparison table with more accurate descriptions of virtual/bounded path canonicalization capabilities

## [0.3.3] - 2025-09-09

### Changed
- Documentation and examples now pass raw anchors to `anchored_canonicalize`; clarified that the API soft-canonicalizes the anchor internally. No API changes.

### Added
- New Windows tests asserting exact, literal extended-length paths (e.g., `\\?\C:\Users\…`) for non-existing anchors and inputs.
- Test covering anchors that include `..` segments, confirming internal soft-canonicalization normalizes the base and yields equal results for equivalent inputs.

### Improved
- Test style hardened across the suite:
  - Prefer full `assert_eq!` comparisons over `starts_with`/`ends_with` hints.
  - Use raw strings for Windows inputs and readable, single-join or full-literal expected paths.
- Added “Testing Rules for Agents (must follow)” to `AGENTS.md` to codify exact-equality expectations, Windows raw-string usage, anchored semantics, symlink policy, and environment assumptions.
- Clarified ADS/CVE coverage in security tests; no behavior changes.

### Notes
- Behavior is unchanged; this release focuses on clearer docs/examples and stricter, more readable tests.

## [0.3.2] - 2025-01-27

### Added
- **🎯 NEW FEATURE: Anchored Canonicalization** - Correct symlink resolution within virtual/constrained directory spaces
  - **New public API**: `anchored_canonicalize(anchor_dir, path)` function for anchor-relative path resolution
  - **Feature-gated**: Available under the optional `anchored` feature flag (no additional dependencies)
  - **Virtual space symlinks**: Ensures proper symlink resolution behavior within bounded directory trees
  - **Use cases**: Virtual filesystems, containerized environments, chroot-like scenarios, build systems
  - **Cross-platform**: Works on Windows, macOS, and Linux with platform-specific optimizations

### Improved
- **Comprehensive test coverage**: Expanded from 273 to 299 comprehensive tests (+26 new tests)
  - New test modules covering symlink resolution in virtual spaces
  - Enhanced boundary condition testing and Unicode edge case coverage
  - Platform-specific behavior validation for Windows UNC paths and Unix symlinks
- **Performance optimizations**: Added `#[inline]` attributes to hot-path functions in symlink and Windows modules
- **Documentation**: New examples and enhanced security guidance for the anchored canonicalization feature

### Technical Details
- Feature flag `anchored` adds the new `anchored_canonicalize` function without increasing compile time for existing users
- Maintains zero runtime dependencies while providing enterprise-grade path security
- All existing APIs remain unchanged - this is a pure feature addition

## [0.3.1] - 2025-09-07

### Changed
- **Major code refactoring**: Split monolithic `lib.rs` into focused modules for better maintainability:
  - `src/error.rs` - Error handling utilities and path-aware error construction
  - `src/normalize.rs` - Path normalization algorithms (`simple_normalize_path`)
  - `src/prefix.rs` - Existing prefix computation and symlink handling (`compute_existing_prefix`)
  - `src/symlink.rs` - Symlink chain resolution (`resolve_simple_symlink_chain`)
  - `src/windows.rs` - Windows-specific functionality (ADS validation, UNC handling, 8.3 detection)

### Improved
- **Better error reporting**: ADS validation now uses path-aware error construction for clearer error messages
- **Better symlink handling**: Improved `.` and `..` processing during symlink traversal with "symlink-first semantics"
- **Performance optimization**: Restored fast-path optimization for non-existing first components
- **Code organization**: Better separation of concerns and module boundaries for easier maintenance

### Technical Details
- Moved ~1000+ lines from `lib.rs` to specialized modules while preserving all functionality
- Improved `validate_windows_ads_layout` error reporting with path-aware error construction
- Maintained full API compatibility - no breaking changes to public interface
- All 110+ unit tests and integration tests continue to pass

## [0.3.0] - 2025-08-18

### Fixed (CRITICAL)
- Fix path resolution order to prevent an edge case where a symlink followed by a `..` component could incorrectly resolve against the symlink's parent instead of the symlink target. This behavior was incorrect; the change restores the intended semantics and aligns behavior with platform expectations for existing paths by attempting `std::fs::canonicalize` on the original absolute path first, then lexically normalizing and retrying when appropriate. This is a bug fix, not a breaking behaviour change.

### Added
- Unit tests covering symlink-first `..` resolution semantics (`src/tests/symlink_dotdot_symlink_first.rs`).

### Improved
- Symlink chain resolution algorithm and cycle detection (smaller allocation strategy and safer textual cycle checks).
- Minor README and bench README clarifications; updated reported test count.
 - Optimized Windows path handling (small runtime optimizations to path processing on Windows).

## [0.2.5] - 2025-08-14

### Added
- **Windows NTFS Alternate Data Stream (ADS) Security Validation**: Comprehensive protection against ADS-based path traversal attacks
  - New `validate_windows_ads_layout()` function to detect malicious ADS patterns
  - Early and late ADS validation to prevent CVE-2025-8088 style attacks (e.g., `file.txt:..\\..\\evil.exe`)
  - Stream name validation for proper syntax, length limits, and forbidden content
  - Type token validation for NTFS stream types (`$DATA`, `$BITMAP`, etc.)
  - Unicode manipulation attack prevention (zero-width characters, BOM, etc.)
  - Reserved device name protection in stream names
- **Comprehensive ADS Attack Vector Test Suite**: 16 new test files covering sophisticated attack patterns:
  - `ads_advanced_exploits.rs`: Type token confusion, chaining attacks, filesystem limit exploitation
  - `ads_comprehensive_security.rs`: CVE patterns and malicious attack vectors
  - `ads_cross_platform_security.rs`: Cross-platform ADS security validation
  - `ads_performance_exploits.rs`: Memory exhaustion and DoS attack prevention
  - `ads_race_conditions.rs`: TOCTOU attack protection during ADS parsing
  - `ads_security_verification.rs`: High-risk attack vector verification
  - `archive_ads_exploits.rs`: Archive-style path pattern tests
  - `crypto_ads_bypass.rs`: Cryptographic bypass vulnerability tests
  - `encoding_penetration.rs`: Advanced Unicode/encoding attack tests
  - `filesystem_boundary_attacks.rs`: Filesystem limits and boundary condition tests
  - `filesystem_metadata_attacks.rs`: Extended attributes and metadata exploitation tests
  - `kernel_boundary_ads.rs`: Kernel/syscall boundary vulnerability tests
  - `protocol_confusion.rs`: Protocol confusion attack tests (UNC, HTTP, file URIs)
  - `unicode_advanced_attacks.rs`: Sophisticated Unicode-based attack vectors
  - `windows_ads_traversal.rs`: Windows-specific ADS traversal and CVE-2025-8088 regression tests
  - `windows_std_ads_behavior.rs`: Empirical `std::fs::canonicalize` behavior validation

### Security
- **CVE-2025-8088 Protection**: Specific protection against WinRAR-style ADS path traversal attacks
- **Malicious Stream Detection**: Validates NTFS ADS syntax, rejecting patterns like `file:../../../evil.exe`
- **Unicode Normalization Security**: Consistent behavior with Unicode normalization forms and edge cases
- **Path Boundary Validation**: Comprehensive testing of path resolution boundaries and component limits
- **Symlink Cycle Protection**: Enhanced detection and rejection of circular symlink references
- **Race Condition Robustness**: Protection against filesystem changes during canonicalization

### Improved
- **CI Quality**: Added MSRV Clippy auto-fix to CI scripts (`ci-local.ps1`, `ci-local.sh`) for better code quality
- **Documentation**: Updated to reflect 250+ comprehensive tests (previously 182)
- **Security Messaging**: Improved focus on robustness validation rather than penetration testing terminology
- **Test Coverage**: Expanded from 182 to 250+ comprehensive tests including Windows-specific attack vectors
- **Error Handling**: Enhanced InvalidInput error reporting for malformed ADS patterns

### Fixed
- **Trailing Whitespace**: Removed trailing whitespace in documentation causing formatting check failures

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
