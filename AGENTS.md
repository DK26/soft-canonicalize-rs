# AGENTS: AI Contributor Guide

This repo contains a zero-dependency Rust crate that canonicalizes paths when suffixes don't exist. It must match `std::fs::canonic## Coding Guideline## Coding Guidelines

- Style: Follow `rustfmt` defaults; keep code clear and small; avoid over-abstraction.
- Error handling: Use `error_with_path` to attach offending path context; ensure `SoftCanonicalizeError::detail` is human-readable.
- Allocation: Avoid temporary `String`s; prefer `PathBuf`, `OsString`, and component streaming.
- Syscalls: Minimize `metadata`/`canonicalize` calls; keep fast-paths and early exits intact.
- Performance: When adding or modifying functions in critical hot-path sections (e.g., path component iteration, validation checks, normalization helpers), consider using `#[inline]` to allow the compiler to optimize away function call overhead. Use `#[inline(always)]` sparingly and only when profiling confirms benefit.
- Platform cfg: Keep Windows/Unix branches correct and side-effect free; don't introduce behavioral drift between platforms.
- Dependencies: Do not add runtime dependencies. If you believe one is strictly necessary, open an issue first.le: Follow `rustfmt` defaults; keep code clear and small; avoid over-abstraction.
- Error handling: Use `error_with_path` to attach offending path context; ensu## Common Pitfalls (avoid)

- Reordering fast-paths: Do not remove/flip the early `fs::canonicalize` checks vs lexical normalization.
- Over-normalizing device/UNC prefixes: preserve verbatim/device prefixes; don't convert device namespaces.
- Popping too far: Never ascend past root/share/device floors.
- Eager symlink adoption: Only adopt resolved symlink path if target or its parent exists; otherwise keep the link as anchor.
- Dropping error context: Don't return bare `io::Error` without the payload created by `error_with_path`.
- **Using dunce without platform guard**: Never use `#[cfg(feature = "dunce")]` alone when calling `dunce::` functions. Always use `#[cfg(all(feature = "dunce", windows))]` because dunce is a Windows-only dependency.tCanonicalizeError::detail` is human-readable.
- Allocation: Avoid temporary `String`s; prefer `PathBuf`, `OsString`, and component streaming.
- Syscalls: Minimize `metadata`/`canonicalize` calls; keep fast-paths and early exits intact.
- Platform cfg: Keep Windows/Unix branches correct and side-effect free; don't introduce behavioral drift between platforms.
- Dependencies: Do not add runtime dependencies. If you believe one is strictly necessary, open an issue first.
- **dunce feature usage (CRITICAL)**: Any code that uses `dunce::` functions MUST be guarded with `#[cfg(all(feature = "dunce", windows))]`. The dunce crate is a Windows-only target-conditional dependency. Using `#[cfg(feature = "dunce")]` alone will cause compilation errors on non-Windows platforms when the feature is enabled.xactly for fully-existing paths, while extending behavior to non-existing paths safely and predictably across Windows, macOS, and Linux. AI Contributor Guide

This repo contains a zero-dependency Rust crate that canonicalizes pathsLinux/WSL (Bash):
- If running from Windows, prefer WSL for Linux benches. From the repo root on the Linux side, run:
  - for i in {1..5}; do cargo bench | tee "target/bench-linux-$i.txt"; done
- If running from Windows PowerShell and cargo is not in PATH for bash, adjust the path to your cargo installation
- Extract the same "Rust soft_canonicalize   : <N> paths/s" line from each run, sort the five numbers, and take the median. Report as "Linux median (paths/s)".
 - For latest Python comparison, ensure `python3.13` is installed/available. The harness auto-tries `python3.13` first on Linux. when suffixes don’t exist. It must match `std::fs::canonicalize` exactly for fully-existing paths, while extending behavior to non-existing paths safely and predictably across Windows, macOS, and Linux.

Use this guide when proposing changes, refactors, tests, or docs with an automated agent.

## Golden Rules

- Compatibility: Results for fully-existing paths must equal `std::fs::canonicalize`.
- Zero deps: Keep runtime dependencies at 0 (dev-only `tempfile` is allowed in tests).
- Security first: Preserve ADS validation, symlink cycle detection, null-byte checks, traversal clamping, and UNC/device semantics.
- MSRV: Keep Minimum Supported Rust Version at `1.70.0` (edition 2021; no unstable features).
- CI clean: `cargo fmt`, `clippy -D warnings`, tests, docs (rustdoc `-D warnings`), security audit, and MSRV all pass locally.

## Public Surface (do not break)

- `pub fn soft_canonicalize(path: impl AsRef<std::path::Path>) -> std::io::Result<std::path::PathBuf>`
- `pub const MAX_SYMLINK_DEPTH: usize`
- `pub struct SoftCanonicalizeError { path: PathBuf, detail: Cow<'static, str> }`
- `pub trait IoErrorPathExt { fn offending_path(&self) -> Option<&Path>; fn soft_canon_detail(&self) -> Option<&str>; }`

Do not change signatures or remove items without a clear migration plan and tests.

## Behavioral Invariants

- Existing paths: Return exactly what `std::fs::canonicalize` returns (including Windows case/UNC long-path formatting).
- Non-existing suffixes: Canonicalize only the deepest existing ancestor; append the non-existing tail lexically.
- Traversal semantics: Resolve `.`/`..` lexically with symlink-first behavior for existing links; never pop beyond root/share/device floors.
- Symlinks: Resolve with bounded depth (`MAX_SYMLINK_DEPTH`) and cycle detection; preserve attachment semantics if the resolved target and parent don’t exist.
- Windows specifics:
  - Return extended-length paths for absolute results (`\\?\C:\...` or `\\?\UNC\server\share\...`).
  - Preserve 8.3 short names in non-existing components; expand only when the component exists and is probed.
  - Validate NTFS ADS placement and token rules (early and late checks) and reject malformed patterns.
- Input validation: Reject embedded NUL bytes consistently.
- Performance: Prefer single-pass logic, minimal syscalls, no unnecessary allocations.

## Algorithm Overview (reference)

1) Input checks → 2) Relativeto-absolute → 3) Fast-path `fs::canonicalize` (original) → 4) Lexical normalize (streaming) → 5) Fast-path `fs::canonicalize` (normalized if changed) → 6) Deepest-existing-prefix discovery with inline symlink handling → 7) Optional re-canonicalize anchor when symlink seen (or Windows short-name expansion) → 8) Append non-existing suffix → 9) Windows extended-length normalization.

## Repository Layout

- `src/lib.rs`: Core algorithm, Windows/Unix branches, helpers, internal tests modules.
- `src/tests/`: Unit tests grouped by area (std-compat, traversal, symlink, platform, security, etc.).
- `tests/`: Integration and blackbox security tests, including Windows ADS and UNC coverage.
- `examples/`: Runnable examples and demos, including security demonstration.
- `benches/`: Benchmarks and Python baseline harness (`benches/python`).
- `docs/`: Deep-dives (e.g., Windows UNC research).
- CI helpers: `ci-local.sh` and `ci-local.ps1` replicate GitHub Actions locally.

## Local CI (run before any PR)

- Bash (Linux/macOS/WSL): `bash ci-local.sh`
- PowerShell (Windows): `.\ci-local.ps1`

These scripts:
- Check UTF-8 encodings and BOM for critical files.
- Run `cargo fmt --check`, `clippy -D warnings`, `cargo test --verbose` (includes doctests), and `cargo doc` with `RUSTDOCFLAGS='-D warnings'`.
- **Test feature combinations explicitly**: `--features anchored` and `--features anchored,dunce` (NOT `--all-features`).
- Run `cargo audit` (install if missing).
- Verify MSRV by building and linting on Rust 1.70.0 (regenerates `Cargo.lock` as needed).

### Feature Testing Policy (CRITICAL)

**Feature combinations to test explicitly:**

1. **`cargo test --features anchored`** - Primary use case (anchored canonicalization only)
2. **`cargo test --features anchored,dunce`** - Full feature set (anchored + Windows path simplification)

**Can now use `--all-features`** for testing on all platforms. The dunce feature is properly guarded with `#[cfg(all(feature = "dunce", windows))]` in all code that directly uses `dunce::` functions.

**Important**: The `dunce` feature changes output format on Windows (UNC `\\?\C:\...` → simplified `C:\...`), so tests MUST use feature-conditional assertions with `#[cfg(feature = "dunce")]` blocks when comparing with `std::fs::canonicalize` (which always returns UNC format).

**Critical rule for code**: Any code that calls `dunce::` functions directly MUST use `#[cfg(all(feature = "dunce", windows))]`, not just `#[cfg(feature = "dunce")]`.

**Platform-specific feature testing**:
- **dunce on Linux/Unix**: The dunce feature is a Windows-only dependency (target-conditional in Cargo.toml). On non-Windows platforms, it adds no dependencies and has no effect. Therefore, testing `--features anchored,dunce` on Linux is redundant—it behaves identically to `--features anchored`. The CI pipeline does NOT need to test dunce on Linux.
- **Cross-platform path handling**: While dunce doesn't need Linux testing, we DO test how the crate handles Windows-style paths (UNC, backslashes, drive letters) on Unix to ensure graceful behavior in cross-platform scenarios (see `tests/cross_platform_paths.rs`). These tests verify that:
  - Windows UNC paths fail gracefully on Unix (no panics)
  - Windows drive letters are handled predictably on Unix
  - Unix-style forward slashes work on Windows (Windows accepts / as separator)
  - Relative paths and dot-dot resolution work consistently across platforms

**Rationale**: Explicit feature flags make CI intentions clear and catch feature-specific issues. The ambiguous `--all-features` hides which combinations are being tested and makes failures harder to debug.

### ⚠️ CRITICAL: Symlink Permission Testing Trap (Windows)

**Problem**: On Windows, creating symlinks requires elevated privileges or Developer Mode. This creates a dangerous testing blind spot:

- **Locally**: Tests that create symlinks skip gracefully with error 1314 (`ERROR_PRIVILEGE_NOT_HELD`)
- **CI (GitHub Actions)**: Windows runners have symlink privileges enabled, so these tests RUN

**Why This Matters**:
1. Tests that skip locally will execute on GitHub Actions
2. If these tests compare with `std::fs::canonicalize` without feature-conditional assertions, they will FAIL in CI when dunce feature is enabled
3. You won't catch these failures until after you push to GitHub

**How to Identify These Tests**:
Search for these patterns in test files:
```bash
# Tests that skip on permission errors
grep -r "PermissionDenied\|raw_os_error.*1314\|Skipping.*permission" tests/
grep -r "got_symlink_permission" tests/
```

**Mandatory Pattern for These Tests**:
ALL tests that:
- Check `PermissionDenied` or `raw_os_error() == Some(1314)`
- Call `got_symlink_permission()` helper
- Would skip locally but run on GitHub Actions

MUST have feature-conditional assertions when comparing with `std::fs::canonicalize`:

```rust
#[test]
fn test_with_symlinks() -> std::io::Result<()> {
    let tmpdir = tmpdir();
    
    // Permission check - test skips locally but runs on CI
    if !got_symlink_permission(&tmpdir) {
        return Ok(());
    }
    
    // ... create symlinks ...
    let result = soft_canonicalize(&path)?;
    
    // CRITICAL: Must use feature-conditional assertion!
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, std::fs::canonicalize(&path)?);
    }
    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        let std_str = std::fs::canonicalize(&path)?.to_string_lossy();
        assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
        assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
        assert_eq!(result_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
    }
    
    Ok(())
}
```

**Files with Symlink-Skipping Tests** (all must have feature guards):
- `tests/std_compat.rs` - Tests with `got_symlink_permission()`
- `tests/blackbox_toctou_attacks.rs` - TOCTOU race condition tests
- `tests/blackbox_complex_attacks.rs` - Complex attack vectors
- `tests/blackbox_security.rs` - Security escape attempts
- `tests/windows_symlink_8_3_interaction.rs` - All 7 tests with permission checks
- `src/tests/symlink_dotdot_symlink_first.rs` - Symlink-first resolution tests

**Before Committing**:
1. Search for ALL tests with symlink permission checks
2. Verify each has feature-conditional assertions when comparing with `std::fs::canonicalize`
3. Look for `assert_eq!`, `assert!(...starts_with(...))`, and direct path comparisons
4. If unsure, add feature guards - they're safe even if not strictly needed

**Remember**: Tests that pass locally might fail on GitHub Actions if they lack proper feature guards!

## Coding Guidelines

- Style: Follow `rustfmt` defaults; keep code clear and small; avoid over-abstraction.
- Error handling: Use `error_with_path` to attach offending path context; ensure `SoftCanonicalizeError::detail` is human-readable.
- Allocation: Avoid temporary `String`s; prefer `PathBuf`, `OsString`, and component streaming.
- Syscalls: Minimize `metadata`/`canonicalize` calls; keep fast-paths and early exits intact.
- Platform cfg: Keep Windows/Unix branches correct and side-effect free; don’t introduce behavioral drift between platforms.
- Dependencies: Do not add runtime dependencies. If you believe one is strictly necessary, open an issue first.

## Tests & Quality Gates

- Run `cargo test` on all platforms you can. Many tests are platform-conditional (`#[cfg(windows)]`, etc.).
- Coverage areas include: std-compat, traversal, symlinks, Unicode/encoding, Windows UNC and 8.3, ADS validation, TOCTOU race robustness, null bytes, boundary conditions.
- When changing behavior, add focused tests alongside the changed logic:
  - Unit tests under `src/tests/…`
  - Integration tests under `tests/…`
  - Example-based docs (doctests) when clarifying public behavior
- Keep tests deterministic and filesystem-safe; avoid relying on external shares or network state.

### Testing Rules for Agents (must follow)

- Prefer exact equality over hints:
  - Do not use `starts_with`/`ends_with` to “approximate” expected paths. Compute or state the full expected path and `assert_eq!`.
  - Windows: when asserting final absolute results, use extended-length expectations (e.g., `\\?\C:\\...`) if applicable.

- Build expected paths simply and readably:
  - For inputs (what a user would type), use raw strings (e.g., `r"hello\dir\..\world"`).
  - For expected results, either:
    - Use a single raw-string tail with one `join` (e.g., `base.join(r"etc\passwd")`), or
    - Compare against a full literal built via `format!` and `PathBuf::from` when you want to assert the entire string.
  - Avoid long chains of `join("segment")` unless necessary; keep tests human-readable.

- Anchored semantics:
  - `anchored_canonicalize` soft-canonicalizes the anchor internally. Do not pre-canonicalize anchors in examples unless demonstrating manual behavior.
  - **Virtual filesystem semantics (v0.4.0+)**: The anchor acts as a virtual root. All symlinks (both absolute and relative) that resolve outside the anchor are clamped back into the virtual filesystem.
    - Absolute symlinks: Reinterpreted relative to the anchor (e.g., `/etc/passwd` → `anchor/etc/passwd`)
    - Relative symlinks that escape: Clamped using common ancestor logic (e.g., `../../opt/file` → `anchor/opt/file`)
    - Lexical `..` traversal: Always clamps to the anchor boundary
  - Write tests that affirm these clamping rules explicitly using exact path assertions.

- Symlinks in tests:
  - Unix: symlink creation is reliable; create real symlinks and assert exact resolved results.
  - Windows: symlink creation requires privileges (error 1314 = `ERROR_PRIVILEGE_NOT_HELD`).
    - **Local testing policy**: Tests should skip gracefully on symlink privilege errors. Local developers and `ci-local` scripts run without elevated privileges, and these tests will be validated by GitHub Actions runners which have symlink privileges enabled.
    - **Test implementation patterns**:
      - **Regression/behavior tests**: Always skip gracefully on error 1314 with a clear message (e.g., "skipping: symlink creation not permitted"). These are the majority of tests and must not fail locally.
      - **Diagnostic tests**: May panic on error 1314 to inform developers that the diagnostic requires privileges to run locally. These are debugging tools, not regular tests.
    - **CI environment**: GitHub Actions Windows runners have symlink privileges enabled, so all symlink tests (both regression and diagnostic) will execute fully in CI.

- Feature-conditional assertions (dunce feature):
  - **IMPORTANT**: The dunce feature is Windows-only (target-conditional dependency in Cargo.toml). On non-Windows platforms, the feature is effectively disabled and adds no dependencies.
  - **Testing pattern**: Tests comparing results with `std::fs::canonicalize` MUST use `#[cfg(feature = "dunce")]` guards for UNC-specific assertions.
  - **CRITICAL**: If test code directly calls `dunce::` functions (not just our library functions), use `#[cfg(all(feature = "dunce", windows))]` to prevent compilation errors on non-Windows platforms.
  - Without dunce: `assert_eq!(result, std::fs::canonicalize(&path)?)` - exact match expected (UNC on Windows, normal on Unix).
  - With dunce on Windows: Compare simplified result (no `\\?\` prefix) with stripped version of std's UNC output.
  - Recommended pattern:
    ```rust
    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(result, std::fs::canonicalize(&path)?);
    }
    #[cfg(feature = "dunce")]
    {
        let result_str = result.to_string_lossy();
        let std_str = std::fs::canonicalize(&path)?.to_string_lossy();
        assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
        assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
        assert_eq!(result_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
    }
    ```
  - **Cleaner alternative using macro** (optional, for tests with many repetitive comparisons):
    ```rust
    // Define at top of test file (use sparingly - explicit patterns are more debuggable)
    macro_rules! assert_std_compat {
        ($result:expr, $path:expr) => {
            #[cfg(not(feature = "dunce"))]
            {
                assert_eq!($result, std::fs::canonicalize(&$path)?);
            }
            #[cfg(feature = "dunce")]
            {
                let result_str = $result.to_string_lossy();
                let std_str = std::fs::canonicalize(&$path)?.to_string_lossy();
                assert!(!result_str.starts_with(r"\\?\"), "dunce should simplify");
                assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
                assert_eq!(result_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
            }
        };
    }
    
    // Usage in test
    let result = soft_canonicalize(&path)?;
    assert_std_compat!(result, path);
    ```
  - **If calling dunce directly in tests** (e.g., for building expected paths):
    ```rust
    // CORRECT: Platform guard when calling dunce:: directly
    #[cfg(all(feature = "dunce", windows))]
    let expected = dunce::canonicalize(&path)?;
    #[cfg(not(feature = "dunce"))]
    let expected = std::fs::canonicalize(&path)?;
    
    // WRONG: Will fail on Linux with --all-features
    #[cfg(feature = "dunce")]
    let expected = dunce::canonicalize(&path)?; // ❌ dunce not available on Linux
    ```

- Environment assumptions:
  - Do not depend on global machine directories (e.g., `C:\\Users`) unless you defend with a skip or your assertion is valid for non-existing paths as well.
  - Prefer `TempDir`-based fixtures; avoid network paths and external shares.

- Examples of good assertions:
  - Full equality under an anchored base:
    ```rust
    let base = soft_canonicalize(&anchor)?;
    let out = anchored_canonicalize(&base, r"c\d\e.txt")?;
    assert_eq!(out, base.join(r"c\d\e.txt"));
    ```
  - Literal Windows expectation (non-existing is OK):
    ```rust
    let anchor = r"C:\\Users\\non-existing\\dir1\\dir2\\..\\..\\folder";
    let out = anchored_canonicalize(anchor, r"hello\\world")?;
    assert_eq!(out, std::path::PathBuf::from(r"\\?\C:\\Users\\non-existing\\folder\\hello\\world"));
    ```
  - Relative symlink keeps clamp (Windows example fails on local machines without privileges but runs on GitHub Actions): ensure equality with exact expected path, not hints.

- Virtual vs system paths (for downstream crates):
  - If a downstream crate exposes a “virtual” display that’s lexical, assert lexical results there.
  - For symlink-resolved system paths, use our `anchored_canonicalize` with a canonicalized anchor and assert the fully-resolved `PathBuf`.

## Performance & Benchmarks

- Run subset benches locally via `cargo bench`.
- Python baseline lives in `benches/python/python_fair_comparison.py`; requires a system Python (`python|python3|py`).
 - Python baseline lives in `benches/python/python_fair_comparison.py`; the harness prefers `python3.13` when available to match latest Python on Linux/WSL, then falls back to `python`, `python3`, or `py`.
- Bench numbers are environment-dependent; only use them as trend indicators.
- Do not regress performance by adding extra syscalls or full-path canonicalizations—justify any changes with comments and tests.

### How to run benches (5-run median)

When asked to “run benches,” use this exact 5-run protocol and report medians from the mixed-workload benchmark (`benches/performance_comparison.rs`). The benchmark itself invokes the Python baseline automatically when Python is available.

Requirements:
- Windows: PowerShell, Rust toolchain installed and on PATH.
- Linux/WSL/macOS: Bash with Rust toolchain installed.
- Python available as `python`, `python3`, or `py` for the baseline (optional but recommended).

Windows (PowerShell):
- From repo root, run this 5-run loop and capture logs:
  - for ($i=1; $i -le 5; $i++) { cargo bench | Tee-Object -FilePath "target\bench-windows-$i.txt" }
- From each run, extract the value printed by performance_comparison as:
  - "Rust soft_canonicalize   : <N> paths/s"
- Sort the five numbers and take the middle one (median). Report that as “Windows median (paths/s)”.

Linux/WSL (Bash):
- If running from Windows, prefer WSL for Linux benches. From the repo root on the Linux side, run:
  - for i in {1..5}; do cargo bench | tee "target/bench-linux-$i.txt"; done
- Extract the same "Rust soft_canonicalize   : <N> paths/s" line from each run, sort the five numbers, and take the median. Report as “Linux median (paths/s)”.
 - For latest Python comparison, ensure `python3.13` is installed/available. The harness auto-tries `python3.13` first on Linux.

Notes and tips:
- Ignore Criterion output/tests lines; only the performance_comparison summary line matters for the primary mixed-workload figure.
- Ensure minimal background load; close heavy apps to reduce variance.
- If Python isn’t found on Linux, the runs still complete; only the baseline ratio will be skipped or use an alternate Python.
- The phrase “bash cargo brench” seen in some notes is a typo; use `cargo bench` under Bash/WSL as shown above.

## Platform Notes (Windows)

- Always ensure extended-length prefixes for absolute results when not already verbatim.
- Maintain ADS validation: colon-containing component must be final; validate stream name/type; block whitespace/control/illegal forms; reject traversal via ADS.
- Respect UNC floors: never pop above `\\server\share`.
- 8.3 short names detection is heuristic; only expand when components exist and we intentionally canonicalize.

## Common Pitfalls (avoid)

- Reordering fast-paths: Do not remove/flip the early `fs::canonicalize` checks vs lexical normalization.
- Over-normalizing device/UNC prefixes: preserve verbatim/device prefixes; don’t convert device namespaces.
- Popping too far: Never ascend past root/share/device floors.
- Eager symlink adoption: Only adopt resolved symlink path if target or its parent exists; otherwise keep the link as anchor.
- Dropping error context: Don’t return bare `io::Error` without the payload created by `error_with_path`.

## PR Checklist (agent self-check)

- Existing-path behavior unchanged and equal to `std::fs::canonicalize`.
- Non-existing suffix behavior preserved; Windows extended-length results correct.
- All CI steps in `ci-local.(sh|ps1)` pass locally.
- New/changed logic covered by unit and/or integration tests, plus doctests if public behavior changed.
- Docs updated (README/lib.rs) if user-visible behavior changed.
- No new runtime dependencies; MSRV respected; no unstable features.

## Quick Commands

- Run all local CI: `bash ci-local.sh` or `.\ci-local.ps1`
- Tests (verbose): `cargo test --verbose`
- Lints: `cargo clippy --all-targets --all-features -- -D warnings`
- Docs (warnings as errors): `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --document-private-items --all-features`
- Benches: `cargo bench`

## Test Counting

We track test count as the sum of: 
- Number of `#[test]` items found under `src/` and `tests/` folders
- Plus the number of Rust doc tests

**Important**: Doc tests must be runnable. Do not use `no_run`, `ignore`, `should_panic`, or other attributes that prevent execution. All doc tests must compile and run successfully as part of `cargo test`.

Commands to count tests:

**PowerShell (Windows):**
```powershell
# Count #[test] in src/ and tests/
$unit = (Get-ChildItem -Recurse -Path src, tests -Include *.rs | Select-String -Pattern '#\s*\[\s*test\s*\]')
$unit.Count

# Count doc tests
(cargo test --doc -- --list | Select-String -Pattern '^test ').Count
```

**Bash (Linux/macOS/WSL):**
```bash
# Count #[test] in src/ and tests/
grep -REo '#[[:space:]]*\[[[:space:]]*test[[:space:]]*\]' src tests | wc -l

# Count doc tests
cargo test --doc -- --list | grep '^test ' | wc -l
```

When documenting test count, use the sum of both numbers. Update README.md and other docs with dynamic counts rather than hardcoded numbers.

## One‑Shot Prompt for Agents

Use when spinning up an automated change:

"""
Work on soft-canonicalize. Constraints: zero runtime deps; preserve exact parity with std::fs::canonicalize for fully-existing paths; extend behavior to non-existing suffixes only; keep MSRV 1.70; pass clippy -D warnings and rustdoc -D warnings; run bash ci-local.sh or .\ci-local.ps1 before proposing changes. Never remove tests or weaken ADS/symlink/UNC/.. protections. Add focused tests for any behavior you touch.
"""

## Releasing (maintainers)

- Tag as `vX.Y.Z` to trigger publish and GitHub Release via workflows.
- Update `CHANGELOG.md` with clear, user-facing notes and security/perf impact.

—

If anything in this guide appears to conflict with the existing tests, treat the tests as the source of truth and open an issue to correct the guide.

