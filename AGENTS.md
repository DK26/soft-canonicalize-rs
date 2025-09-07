# AGENTS: AI Contributor Guide

This repo contains a zero-dependency Rust crate that canonicalizes paths even when suffixes don’t exist. It must match `std::fs::canonicalize` exactly for fully-existing paths, while extending behavior to non-existing paths safely and predictably across Windows, macOS, and Linux.

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
- Run `cargo audit` (install if missing).
- Verify MSRV by building and linting on Rust 1.70.0 (regenerates `Cargo.lock` as needed).

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

## Performance & Benchmarks

- Run subset benches locally via `cargo bench`.
- Python baseline lives in `benches/python/python_fair_comparison.py`; requires a system Python (`python|python3|py`).
- Bench numbers are environment-dependent; only use them as trend indicators.
- Do not regress performance by adding extra syscalls or full-path canonicalizations—justify any changes with comments and tests.

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

