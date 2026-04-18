# AGENTS: AI Contributor Guide

This repo contains a zero-dependency Rust crate that canonicalizes paths when suffixes don’t exist. It must match `std::fs::canonicalize` exactly for fully-existing paths, while extending behavior to non-existing paths safely and predictably across Windows, macOS, and Linux.

Use this guide when proposing changes, refactors, tests, or docs with an automated agent.

## Maintaining This File

AGENTS.md is read by stateless agents with no memory of prior sessions.
Every rule must stand on its own without session context.

- **General, not reactive.** Do not add rules to address a single past
  mistake.  Only codify patterns that could recur across sessions.
- **Context-free.** No references to specific conversations, resolved issues,
  commit hashes, or session artifacts.  A future agent must understand the
  rule without knowing what prompted it.
- **Principles over examples.** Prefer abstract guidance.  If an example is
  needed, make it generic — never name a specific module or function as the
  motivating case.
- **No stale specifics.** If a rule names a concrete item (file, function,
  feature), it must be because the item is structurally important (e.g. the
  repository layout table), not because it was the subject of a past debate.

## Golden Rules

- Compatibility: Results for fully-existing paths must equal `std::fs::canonicalize`.
- Minimal deps: Keep mandatory runtime dependencies at 0. Optional features may add well-justified lightweight deps (currently: `proc-canonicalize` default-enabled for Linux `/proc` magic-link handling; `dunce` Windows-only optional for UNC simplification). Dev-only `tempfile` is allowed in tests.
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
- `src/anchored.rs`: `anchored_canonicalize` implementation (compiled only with `--features anchored`).
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

### Junction Fallback — the Preferred Remedy, Not Plain Skip

A test that merely skips on error 1314 is a CI-only test: the developer never
sees it pass on their own machine and cannot reproduce a CI failure locally.
When the behavior under test does not require true symlink semantics
(reparse-point resolution is sufficient), use an NTFS **junction** as a
fallback so the test runs on non-admin Windows sessions too.

**Rules:**

1. **Use the existing helper, don't inline** — a `create_symlink_or_junction`
   helper already lives in `tests/test_helpers/`. Integration tests under
   `tests/` must call that helper rather than re-implementing the try-symlink-
   then-junction pattern. If you find yourself writing `match symlink_dir(...)
   { Err(e) if ... raw_os_error() == Some(1314) => junction_verbatim::create
   (...) }` by hand in an integration test, stop and use the helper.

2. **`src/tests/` unit tests** can't import the helper (different crate
   boundary). For those, either: (a) move the test to `tests/` and use the
   helper, or (b) inline the two-arm fallback with the `junction-verbatim`
   dev-dependency. Do NOT add a second module that re-exports a parallel
   helper; one canonical helper per repo.

3. **Junction semantic gotcha**: junctions require an ABSOLUTE target and can
   only point at directories on the same volume. Symlinks accept both
   relative and absolute targets. When designing a test that must work via
   either mechanism, structure it with an absolute target so the same setup
   works for both — don't write two parallel tests for the "symlink only" and
   "junction only" cases.

4. **When junction is not an acceptable fallback**: tests that specifically
   exercise relative-symlink target resolution, or absolute symlink targets
   outside the anchor's volume, must remain symlink-only and skip on 1314.
   Document why junction won't satisfy the test in a short comment.

5. **Do not replace or alter an existing regression test with a junction
   variant**. Junction covers a different code path (absolute-target reparse
   point) than a relative symlink. If both paths matter, ADD a sibling test;
   never rename or rewrite the original. Regression tests are append-only —
   the name and assertions at release time must survive intact so future
   bisects can pinpoint behaviour changes.

6. **Verify the test actually ran locally.** A test that prints "skipping:
   symlink creation not permitted" and returns `Ok(())` is not evidence of
   correctness. When reporting a fix, confirm via the test runner's output
   (`... ok` with execution time) that the test body executed. If every
   relevant test printed a skip line, you have no local proof — add a
   junction fallback (as a SIBLING test per rule 5) or run in an elevated /
   Developer-Mode session before claiming the fix works.

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
- `tests/compat_symlinks.rs` - Tests with `got_symlink_permission()`
- `tests/blackbox_toctou_attacks.rs` - TOCTOU race condition tests
- `tests/blackbox_complex_attacks.rs` - Complex attack vectors
- `tests/issue_53_symlink_dotdot_lexical_collapse.rs` - Regression test with symlink permission skip
- `tests/windows_anchored_verbatim_drive_bug_symlink.rs` - Windows anchored symlink tests
- `src/tests/symlink_dotdot_symlink_first.rs` - Symlink-first resolution tests
- `src/tests/anchored_symlink_clamping.rs` - Anchored symlink clamping tests
- `src/tests/anchored_security/windows_symlink.rs` - Windows anchored security symlink tests

Use the grep commands in "How to Identify These Tests" above to find the authoritative current list — it is more reliable than this enumeration.

**Before Committing**:
1. Search for ALL tests with symlink permission checks
2. Verify each has feature-conditional assertions when comparing with `std::fs::canonicalize`
3. Look for `assert_eq!`, `assert!(...starts_with(...))`, and direct path comparisons
4. If unsure, add feature guards - they're safe even if not strictly needed

**Remember**: Tests that pass locally might fail on GitHub Actions if they lack proper feature guards!

## Git Usage Policy (CRITICAL for Agents)

### Read-Only Git Operations Only

Agents are **only permitted to run read-only git commands**. Never run any git command that modifies the working tree, index, or history. This includes, but is not limited to:

**Banned (write) operations:**
- `git add`, `git stage`
- `git commit`, `git commit --amend`
- `git restore`, `git checkout -- <file>`
- `git reset` (any form)
- `git stash`, `git stash pop`
- `git merge`, `git rebase`
- `git push`, `git pull`, `git fetch`
- `git rm`, `git mv`
- `git tag`, `git branch -d`

**Allowed (read) operations:**
- `git status`, `git diff`, `git diff --staged`
- `git log`, `git show`, `git blame`
- `git ls-files`, `git stash list`

If you need to stage, commit, or modify git state, **ask the user to do it** or wait for an explicit instruction. Never take git write actions on your own initiative, even to "clean up" or "fix" something you changed.

## Git Commit Workflow (CRITICAL for Agents)

**ALWAYS check staged files before committing.** Before running `git commit`, you MUST:

1. **Run `git status`** to see what files are staged vs unstaged
2. **Run `git diff --staged --stat`** to see exactly what will be committed
3. **Review the staged changes** - ensure they match the intended commit scope
4. **If unrelated files are staged**, either:
   - Unstage them with `git reset HEAD <file>` before committing, OR
   - Ask the user if they should be included

**Never blindly run `git add <file>; git commit`** without checking what was already staged. The user may have staged files for a different purpose.

**Commit message must match staged content.** If the staged diff contains files unrelated to your commit message, STOP and clarify with the user.

**Example workflow:**
```bash
# WRONG - dangerous, ignores existing staged files
git add myfile.rs
git commit -m "fix: something"

# CORRECT - always check first
git status
git diff --staged --stat
# Review output, then if appropriate:
git add myfile.rs
git diff --staged --stat  # Check again after adding
git commit -m "fix: something"
```

## Coding Guidelines

- Style: Follow `rustfmt` defaults; keep code clear and small; avoid over-abstraction.
- Error handling: Use `error_with_path` to attach offending path context; ensure `SoftCanonicalizeError::detail` is human-readable.
- Allocation: Avoid temporary `String`s; prefer `PathBuf`, `OsString`, and component streaming.
- Syscalls: Minimize `metadata`/`canonicalize` calls; keep fast-paths and early exits intact.
- Platform cfg: Keep Windows/Unix branches correct and side-effect free; don’t introduce behavioral drift between platforms.
- Dependencies: Do not add new runtime dependencies. The existing `proc-canonicalize` (default feature) and `dunce` (Windows-only optional feature) are the approved optional deps. If you believe a new one is strictly necessary, open an issue first.
- No `.unwrap()` in production code: Production code must never call `.unwrap()`, `.expect()`, or any method that panics on `None`/`Err`. Use `?`, `.ok_or()`, `.map_err()`, or `.unwrap_or()` instead. Test code may use `.unwrap()` freely.
- No dead code: Do not use `#[allow(dead_code)]` or similar lint-suppression attributes. If the compiler says it's unused, either use it or remove it. Fix the root cause instead of silencing the warning.

### Safe Indexing — No Direct Indexing in Production Code

Production code must not use direct indexing (`data[i]`, `parts[1]`,
`slice[start..end]`) on slices, `Vec`, or `str`.  Direct indexing panics on
out-of-bounds access, which is a denial-of-service vector.

**Required replacements:**

| Banned                | Replacement                                               |
| --------------------- | --------------------------------------------------------- |
| `parts[i]`           | `parts.get(i).ok_or(…)?` or `parts.get(i).map(…)`        |
| `data[start..end]`   | `data.get(start..end).ok_or(…)?`                          |
| `slice[i..]`         | `slice.get(i..).unwrap_or_default()`                      |

For **sequential processing**, prefer iterators (`.iter()`, `.enumerate()`,
`.windows()`, `.chunks()`, `.split()`) over index-based loops.

**Test code** (`#[cfg(test)]` blocks, `tests/`) may use direct indexing when
the test controls the input and panic-on-bug is acceptable.

### Heap Allocation in Hot Paths

Hot-path functions (path component iteration, validation checks, normalization
helpers) must not heap-allocate.  Use stack buffers, iterators, and streaming
operations instead of intermediate `Vec`, `String`, or `Box`.

For necessary allocations (variable-length output):
- Use `Vec::with_capacity(known_size)` to avoid reallocation.
- Prefer `Vec::extend_from_slice` over N × `push` for bulk copies.

### Type Safety

- Prefer `Option` / `Result` over sentinel values.  Never use empty strings,
  `-1`, or null-equivalent magic values to signal absence.
- Prefer `match` over `if let` when handling enums so that adding a new variant
  produces a compile error at every call site, rather than silently falling
  through.
- Keep struct fields private when invariants must be enforced.  Expose
  transition methods that enforce them.

### Lifetime Naming

**Every named lifetime parameter must have a descriptive name that explains
whose lifetime it represents.**  Single-letter lifetimes (`'a`, `'b`, `'c`,
...) are **banned** — no exceptions, no "simple signature" carve-out.

Name lifetimes after the data they bind to: `'path`, `'input`, `'src`,
`'buf`, `'anchor`, `'cfg`, `'err`.  When a function takes two references,
give each one a name that identifies its source (e.g. `fn f<'input, 'buf>
(src: &'input str, dst: &'buf mut String)`).

Exceptions (these are not "single-letter" names, they are language built-ins):

- `'static` — Rust's built-in lifetime for program-long data.  Use it when
  the borrow must outlive the process.
- `'_` — the elided / anonymous lifetime.  Use it only where the compiler
  already infers the lifetime and naming it would add no information
  (e.g. `fmt::Formatter<'_>`).  Prefer a real name whenever the lifetime
  appears in a function or type signature you author.

**Why:** lifetimes are a contract between the caller and the function about
who owns what for how long.  A name like `'a` forces every reader to
reverse-engineer that contract from the signature.  A name like `'anchor`
tells them instantly — the same way a well-named parameter does.  Stale
single-letter names rot fastest: add a second lifetime and now `'a` and
`'b` are a puzzle.  Descriptive names never rot.

### Comments Explain Reasoning, Not Mechanics

Comments must answer **why**: the reasoning, invariant, security property,
non-obvious constraint, or history behind a workaround.  Never comment what
the code already says — well-named identifiers are the canonical "what".

- Good: `// SECURITY: clamp before join — raw target may contain ".." that`
  `// escape the anchor when the OS resolves the returned path.`
- Good: `// Fast-path: skip fs::canonicalize when lexical form is unchanged;`
  `// avoids a syscall in the hot case.`
- Bad: `// increment counter` above `counter += 1;`
- Bad: `// call the helper` above a function call.

When in doubt, add a short comment stating the invariant/reason.  A future
reader (human or agent) who asks "why is this here?" must find the answer in
the code — not in a commit message, issue tracker, or vanished conversation.
Delete comments that only restate identifiers.

### Doc Comment Discipline

Doc comments (`///`, `//!`) must never hide executable content from the test
harness.  **Forbidden fence styles in Rust doc comments** (they are all
treated as test-skip or test-bypass mechanisms):

- ` ```text ` — blocks code from compiling.  Use plain prose (no fence) or a
  bulleted list instead.  For pseudocode illustrations, write them as prose.
- ` ```ignore `, ` ```no_run `, ` ```should_panic `, ` ```compile_fail ` —
  block or redirect execution.  Rewrite as a real runnable ` ```rust ` block
  that `cargo test --doc` compiles and runs, or move the illustration into
  a regular `#[test]` and reference it from the doc comment.

Rules of thumb:

- **Pseudocode** → write it as prose (no fence).
- **Runnable Rust** → use the default ` ``` ` or ` ```rust ` fence and make
  it actually compile and run under `cargo test --doc`.
- **Private / `pub(crate)` items**: rustdoc does not execute their doctests,
  so a ` ```rust ` block there is a lie that cannot be verified.  Use prose.

This discipline applies to every Rust source file.  Plain Markdown files
(`README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`) may use ` ```text ` freely —
they are not processed by rustdoc.

### RAG / LLM-Friendly File Size

Keep source files under **~600 lines** (production or test) to fit within a
single LLM context window and improve RAG retrieval precision.

- When a production file grows past ~600 lines, split into focused submodules
  (e.g. `foo.rs` → `foo/mod.rs` + `foo/helpers.rs`).
- When a test file grows past ~600 lines, split into thematic files
  (e.g. `tests_validation.rs`, `tests_security.rs`).
- Favour a stable top-to-bottom layout so any reader knows where to look:
  module docs → imports → constants → types → impl blocks → functions → tests.

## Coding Session Discipline

### Test-First / Proof-First

- For every non-trivial behavior change, bug fix, or regression fix:
  **write or update the tests first** so the expected behavior is explicit
  before implementation changes begin.
- The intended workflow is **red → green → refactor**:
  1. Encode the requirement in a test.
  2. Observe the old implementation fail or lack the behavior.
  3. Implement the change.
  4. Rerun the tests to prove the new behavior.
- If a task is purely structural (rename, move, formatting) and has no
  behavioral delta, a new failing test is not required.
- Every problem or bug fixed must include a regression test as part of the
  same change set.

### Evidence Rule

Do not claim a feature or fix is complete without evidence:

- Tests (unit, integration, or doctests) proving the behavior.
- CI output showing clean build + test pass.
- Manual verification notes (if no automation exists yet).

"Implemented" or "fixed" without proof is not acceptable.

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
  - Windows: when asserting final absolute results, use extended-length expectations (e.g., `\\?\C:\...`) if applicable.
  - Positive-only: Main test assertions must validate the correct expected output, not enumerate incorrect forms. Avoid patterns like `assert!(!path.starts_with("\\?\"))` for final correctness; instead assert equality with the properly transformed path. Negative checks may appear only in input precondition validation.

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
  - Recommended pattern (positive-only final assertion):
    ```rust
  #[cfg(not(feature = "dunce"))]
  {
    assert_eq!(result, std::fs::canonicalize(&path)?);
  }
  #[cfg(feature = "dunce")]
  {
    let result_str = result.to_string_lossy();
    let std_str = std::fs::canonicalize(&path)?.to_string_lossy();
    // Positive-only: equality with simplified expected (std UNC minus verbatim prefix)
    assert_eq!(result_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
  }
    ```
  - **Cleaner alternative using macro** (optional, for tests with many repetitive comparisons; positive-only):
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

## Handling External Feedback & Reviews

Treat feedback as input, not instruction. Validate every claim before acting.

1. **Check against established principles first.** Before applying any fix —
   whether from a reviewer, from your own analysis, or from a pragmatic
   shortcut — ask: "Does this change violate a design principle we already
   settled?" If yes, the change is wrong regardless of how reasonable it
   sounds. Fix the surrounding code to uphold the principle; never weaken
   the principle to match the surrounding code.

2. **Use git history to resolve contradictions.** When two representations
   disagree, run `git log -S "<term>" --oneline -- <file>` on both sides to
   determine which text is newer. The newer commit represents the more
   recent design decision. Always upgrade stale text to match the newer
   decision, never the reverse.

3. **Verify the factual claim.** Read the text being criticized. Is the
   characterization accurate? Quote the actual text. If the reviewer
   misread or mischaracterized the code/doc, say so and reject the finding.

4. **Independently assess severity.** Do not accept a reviewer's severity
   rating at face value. Assign your own and state it if it differs.

5. **Distinguish bugs from preferences.** A factual contradiction or
   invariant violation is a bug — fix it. "The code could be cleaner" is a
   preference — evaluate against the cost of the change.

6. **Reject or downgrade with justification.** If a finding is invalid,
   reject it explicitly and state the reason. Do not implement changes just
   because someone flagged something.

7. **Check for cascade inconsistencies.** When fixing a confirmed finding,
   search for the same pattern in other files. Fix all occurrences in one
   pass — but only where the same error actually exists.

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

**Important**: Doc tests must be runnable.  See "Doc Comment Discipline"
under Coding Guidelines for the authoritative rule — in short, the fences
` ```text `, `no_run`, `ignore`, `should_panic`, and `compile_fail` are
all banned in Rust doc comments.  All doc tests must compile and run
successfully as part of `cargo test`.

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
Work on soft-canonicalize. Constraints: no new runtime deps (approved deps: `proc-canonicalize` default feature, `dunce` Windows-only optional); preserve exact parity with std::fs::canonicalize for fully-existing paths; extend behavior to non-existing suffixes only; keep MSRV 1.70; pass clippy -D warnings and rustdoc -D warnings; run bash ci-local.sh or .\ci-local.ps1 before proposing changes. Never remove tests or weaken ADS/symlink/UNC/.. protections. Add focused tests for any behavior you touch.
"""

## Releasing (maintainers)

- Tag as `vX.Y.Z` to trigger publish and GitHub Release via workflows.
- Update `CHANGELOG.md` with clear, user-facing notes and security/perf impact.

—

If anything in this guide appears to conflict with the existing tests, treat the tests as the source of truth and open an issue to correct the guide.

