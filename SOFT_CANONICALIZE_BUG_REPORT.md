# Windows: `anchored_canonicalize` returns malformed verbatim drive path (missing backslash)

Status (2025-11-11)
- Fixed on dev. Root cause: extended-length builder allowed a drive-relative Disk prefix; fix ensures verbatim absolute form `\\?\C:\...` even for drive-relative anchors.
- Verification: covered by positive-only tests
  - `tests/windows_anchored_drive_relative_anchor_regression.rs`
  - `tests/windows_anchored_verbatim_drive_bug.rs`
- Code: `src/windows.rs::ensure_windows_extended_prefix`

Summary
- On Windows, `soft_canonicalize::anchored_canonicalize(anchor, candidate)` can return an extended-length (verbatim) drive path that is missing the backslash after the drive colon: `\\?\C:Users\…`.
- Correct and expected form is `\\?\C:\Users\…`. The malformed path behaves like a drive-relative path and breaks downstream boundary checks.

Environment
- OS: Windows 10/11
- Rust: stable (1.71+)
- Crate: `soft-canonicalize = { version = "0.4.5", features = ["anchored"] }`
- Filesystem: NTFS

Minimal Repro (single-binary project)

`Cargo.toml`
```toml
[package]
name = "sc-anchored-bug-repro"
version = "0.1.0"
edition = "2021"

[dependencies]
soft-canonicalize = { version = "0.4.5", features = ["anchored"] }
tempfile = "3.22"
```

`src/main.rs`
```rust
use soft_canonicalize::anchored_canonicalize;
use std::path::Path;

fn is_malformed_verbatim_drive(p: &std::path::Path) -> bool {
    // Detect "\\\\?\\X:…" where the backslash after the colon is missing
    let s = p.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && (b[0] as char).is_ascii_alphabetic() && b[1] == b':' {
            // Bug condition: next char after drive colon is NOT '\\' or '/'
            return b[2] != b'\\' && b[2] != b'/';
        }
    }
    false
}

fn main() {
    // 1) Canonicalized temp dir as anchor (common usage pattern)
    let anchor = std::fs::canonicalize(std::env::temp_dir()).unwrap();

    // 2) Candidate with a root component (absolute-like). Anchored semantics interpret this
    //    relative to the anchor (i.e., should end up under `anchor`).
    let candidate = Path::new("/data/dir");

    // 3) Call anchored canonicalization
    let raw = anchored_canonicalize(&anchor, candidate).unwrap();
    println!("anchor:   {:?}", anchor);
    println!("raw:      {:?}", raw);

    // 4) Assert against malformed pattern – FAIL if bug exists
    assert!(
        !is_malformed_verbatim_drive(&raw),
        "anchored_canonicalize returned malformed verbatim drive path: {:?}",
        raw
    );
}
```

Run steps (on Windows):
```powershell
cargo run -q
```

Expected
- Output `raw` is an extended-length drive path with a backslash after the colon, e.g.:
  `"\\?\C:\\Users\\<…>\\AppData\\Local\\Temp\\data\\dir"`

Actual (buggy)
- In some environments, `raw` is:
  `"\\?\C:Users\\<…>\\AppData\\Local\\Temp\\data\\dir"`
  (Missing the backslash after the drive colon). This is interpreted as a drive-relative path and can cause
  `starts_with(anchor)` checks and boundary verification to fail in downstream consumers.

Impact
- Downstream path-security libraries (e.g., strict-path-rs) rely on `anchored_canonicalize` for virtual-root semantics.
  The malformed path is treated as drive-relative and triggers false "escapes boundary" conditions.

Analysis
- `soft_canonicalize::soft_canonicalize` (non-anchored) returns correct verbatim drive roots (e.g., `\\?\C:\…`).
- The issue seems specific to the anchored variant’s path construction on Windows when the candidate begins with a root (e.g., `"/data/dir"`).

Resolution
- Ensure verbatim extended-length paths are always absolute for Disk prefixes. If the input is drive-relative (e.g., `C:dir`), synthesize `\\?\C:\` and then append remaining components. If already absolute (`C:\...`), just prefix `\\?\`.

Additional note (downstream mitigation)
- In strict-path-rs, we added a Windows-only normalization guard that rewrites `\\?\X:rest` → `\\?\X:\rest` if the backslash is missing, so boundary checks remain correct while this is fixed upstream.
- We also added a Windows regression test that fails if the malformed verbatim drive path is returned.

Thank you! This is straightforward to detect and fix, and it unblocks boundary/virtual-root consumers on Windows.

