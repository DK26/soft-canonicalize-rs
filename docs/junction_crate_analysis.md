# Learnings from the `junction` Crate

Date: October 13, 2025  
Crate analyzed: [`tesuji/junction`](https://github.com/tesuji/junction) v1.3.0  
Relevance: Testing strategy and Windows permission handling

## Executive Summary

The `junction` crate provides valuable insights for improving our test infrastructure, specifically:

1. **Junction points as symlink alternatives in tests** (no admin required)
2. **"Ask for forgiveness" permission handling pattern**
3. **Robust error handling for privilege escalation**

## What is the `junction` Crate?

A specialized Windows-only library for creating and managing **NTFS junction points** (directory junctions/mount points).

**Key difference from symlinks:**
- ✅ **Junctions don't require admin privileges** on any Windows version
- ⚠️ Symlinks need `SeCreateSymbolicLinkPrivilege` (admin) on Windows < 10 build 14972
- ✅ Junctions work for directories only (symlinks work for files too)

## Do We Need It for Canonicalization?

**No.** Our crate already handles junctions correctly because:
- `std::fs::metadata().is_symlink()` detects junctions on Windows
- `std::fs::read_link()` resolves both symlinks and junctions
- `std::fs::canonicalize()` follows junctions automatically

The junction crate is for **creating/managing** junctions, not traversing them.

## What Can We Learn?

### 1. Permission Handling Pattern (Critical Learning)

**The "Ask for Forgiveness" Pattern** from `junction/src/internals/helpers.rs`:

```rust
pub fn open_reparse_point(reparse_point: &Path, write: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    // ... setup options ...
    
    // Try without privilege elevation first
    match opts.open(reparse_point) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            // ONLY on permission error, try to elevate
            set_privilege(write)?;
            opts.open(reparse_point)  // Retry after elevation
        }
        other => other,  // Success or other errors
    }
}
```

**Benefits:**
- ✅ No privilege overhead for normal operations
- ✅ Graceful fallback only when needed
- ✅ Better performance (avoids unnecessary privilege checks)

**Their changelog (v0.1.4, 2020-01-30):**
> "Ask for forgiveness in case we have no necessary permission instead of always asking for permission."

### 2. Test Strategy: Junction Fallback

Since junctions don't require admin, we can use them in tests:

**Current problem:**
```rust
// Our tests fail in non-admin environments
match symlink_dir(&target, &link) {
    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
        eprintln!("Skipping test - no symlink permission");
        return Ok(()); // Test passes but provides no coverage
    }
    // ...
}
```

**Solution with junction fallback:**
```rust
// Try symlink first, fall back to junction
match create_symlink_or_junction(&target, &link) {
    Ok(true) => { /* test continues with link created */ }
    Ok(false) => { /* skip only if both fail */ }
    Err(e) => { /* real error */ }
}
```

**Result:**
- ✅ Tests run on non-admin Windows (junction fallback)
- ✅ Tests run on admin Windows (symlink preferred)
- ✅ Tests run on Unix (symlink always)
- ✅ Better test coverage in CI and local environments

### 3. Consistent Error Checking

Junction crate checks **both** error conditions:
```rust
if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314)
```

Error 1314 = `ERROR_PRIVILEGE_NOT_HELD` (Windows-specific)

We already do this in some tests, but could improve consistency.

## Implementation

### Added Files

1. **`tests/test_helpers/symlink_or_junction.rs`**
   - Helper function: `create_symlink_or_junction()`
   - Auto-fallback: symlink → junction → skip

2. **`tests/test_helpers/mod.rs`**
   - Module organization for test helpers

### Modified Files

1. **`Cargo.toml`**
   - Added Windows-only dev-dependency: `junction = "1.3"`
   - No feature flag is required; it’s a target-conditional test-only dependency

### Usage Example

```rust
// In any test file (integration)
mod test_helpers;
use crate::test_helpers::symlink_or_junction::create_symlink_or_junction;

#[test]
fn test_symlink_behavior() -> io::Result<()> {
    let tmp = TempDir::new()?;
    let target = tmp.path().join("target");
    let link = tmp.path().join("link");

    fs::create_dir(&target)?;

    match create_symlink_or_junction(&target, &link)? {
        true => {
            // Link created via symlink or junction — proceed
            let result = soft_canonicalize(&link)?;
            assert!(result.is_absolute());
        }
        false => {
            eprintln!("Skipping: symlink and junction creation not permitted");
            return Ok(());
        }
    }

    Ok(())
}
```

### Running Tests with Junction Fallback

```powershell
# Standard test run — junction fallback is available on Windows
cargo test
```

## Recommendations

### Immediate Actions

1. ✅ **Document junction handling** in README/docs
   - Mention that we resolve both symlinks and junctions
   - Note that our tests can use junctions on Windows

2. ✅ **Use test helper in new tests**
   - Replace direct `symlink_dir()` calls with `create_symlink_or_junction()`
   - Enables better CI coverage on Windows runners

3. ⚠️ **Optional: Refactor existing tests** (low priority)
   - Gradually migrate existing symlink tests to use the helper
   - Only worth it if tests are actively failing

### Future Considerations

1. **CI improvement:**
   - Run Windows tests with `--features test-junctions`
   - Increases coverage without requiring admin privileges

2. **Documentation:**
   - Add note about Windows symlink vs junction behavior
   - Explain when each is used and why

3. **Testing best practices:**
   - Always use `create_symlink_or_junction()` for new tests
   - Only use direct `symlink_*()` when testing symlink-specific behavior

## Related Crate Analysis

The junction crate also references these useful resources:

1. **Google Project Zero's symlink-testing-tools:**
   - https://github.com/googleprojectzero/symboliclink-testing-tools
   - Security-focused symlink testing utilities

2. **James Forshaw's Win32-to-NT path guide:**
   - https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
   - Definitive guide on Windows path parsing

These could be valuable for future security hardening.

## Conclusion

**Key takeaway:** Use junctions as a fallback in tests to avoid admin privilege requirements on Windows.

**Impact:**
- ✅ Better test coverage in restricted environments
- ✅ More reliable CI runs on Windows
- ✅ Easier local development on non-admin Windows machines
- ✅ Maintains Unix compatibility (transparent symlink usage)

**No changes needed for production code** - junctions are already handled correctly by `std::fs` APIs.
