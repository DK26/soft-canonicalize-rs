# Analysis: dunce crate & Microsoft MSDN Documentation

**Date:** October 7, 2025  
**Purpose:** Evaluate relevance to `soft-canonicalize-rs`

## Executive Summary

Both the `dunce` crate and Microsoft's official documentation provide valuable insights for our crate. The `dunce` crate solves the *opposite* problem (UNC → simplified), while we solve existing → UNC. However, their validation logic and edge cases are highly relevant to our security and correctness requirements.

---

## 1. dunce Crate Analysis

**Repository:** https://gitlab.com/kornelski/dunce  
**Purpose:** Strip Windows UNC paths (`\\?\C:\foo`) back to legacy format (`C:\foo`) when safe

### Key Similarities to Our Crate

1. **Same Microsoft documentation basis**
   - Both based on https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
   - Same fundamental understanding of Windows path semantics

2. **Opposite transformation direction**
   - dunce: UNC → simplified (when safe)
   - soft-canonicalize: existing → UNC (for absolute results)
   - **Insight:** Their safety checks for simplification mirror our safety requirements for extension

### Relevant Implementation Details

#### 1.1 Reserved Names Validation
```rust
const RESERVED_NAMES: [&str; 22] = [
    "AUX", "NUL", "PRN", "CON", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];
```

**Our status:** ✅ We already handle this in `windows.rs` with identical list

**Difference:** They check `COM¹`, `COM²`, `COM³`, `LPT¹`, `LPT²`, `LPT³` (superscript digits)
- Microsoft docs mention: "Windows recognizes the 8-bit ISO/IEC 8859-1 superscript digits ¹, ², and ³ as digits"
- **Action item:** Consider if we should add these edge cases (low priority, extremely rare)

#### 1.2 Filename Validation Function
```rust
fn is_valid_filename(file_name: &OsStr) -> bool {
    // 255 character limit (both bytes and UTF-16 code units)
    if file_name.len() > 255 && windows_char_len(file_name) > 255 {
        return false;
    }
    
    // Check for control characters and reserved chars
    if byte_str.iter().any(|&c| matches!(c, 0..=31 | b'<' | b'>' | b':' | b'"' | b'/' | b'\\' | b'|' | b'?' | b'*')) {
        return false
    }
    
    // Filename can't end with . or space
    if matches!(byte_str.last(), Some(b' ' | b'.')) {
        return false;
    }
}
```

**Our status:** 
- ✅ We validate against control characters and reserved chars
- ✅ We check trailing space/dot in ADS validation
- ⚠️ We do NOT enforce 255-char component limit explicitly

**Consideration:** The 255-char limit is a per-component restriction. When we're in UNC mode (`\\?\`), Windows allows longer components, but for non-UNC, components are limited. This is more of a dunce concern (they're converting TO non-UNC) than ours (we output UNC for absolute paths).

#### 1.3 Reserved Name Detection Logic
```rust
fn is_reserved<P: AsRef<OsStr>>(file_name: P) -> bool {
    // con.txt is reserved too
    // "con.. .txt" is "CON" for DOS
    if let Some(name) = Path::new(&file_name).file_stem().and_then(|s| s.to_str()?.split('.').next()) {
        let trimmed = name.trim_end_matches(' ');
        return trimmed.len() <= 4 && RESERVED_NAMES.into_iter().any(|name| trimmed.eq_ignore_ascii_case(name));
    }
    false
}
```

**Key insight:** They check `file_stem()` and handle edge cases like `con.. .txt` → `CON`

**Our status:** ✅ We do this in our reserved name detection

#### 1.4 Path Length Check
```rust
// However, if the path is going to be used as a directory it's 248
if path_os_str.len() > 260 && windows_char_len(path_os_str) > 260 {
    return None;
}
```

**Insight:** MAX_PATH (260) applies to legacy paths, but they use UTF-16 code unit count, not bytes

**Our status:** ✅ We use UNC extended-length format which bypasses MAX_PATH

#### 1.5 Test Coverage Insights

Their tests reveal important edge cases:

```rust
#[test]
fn reserved() {
    assert!(is_reserved("CON"));
    assert!(is_reserved("con.con"));
    assert!(is_reserved("COM4.txt"));
    assert!(is_reserved("COM4 .txt"));
    assert!(is_reserved("con."));
    assert!(is_reserved("con ."));
    assert!(is_reserved("con  "));
    assert!(is_reserved("con . "));
    assert!(is_reserved("con . .txt"));
    assert!(is_reserved("con.....txt"));
    
    assert!(!is_reserved(" CON"));      // Leading space makes it non-reserved
    assert!(!is_reserved("COM0"));      // 0 is not valid
    assert!(!is_reserved("COM77"));     // Only COM1-9
    assert!(!is_reserved(".CON"));      // Dot prefix
    assert!(!is_reserved("not.CON"));   // CON must be stem
}
```

**Action:** Cross-check our test suite covers these patterns ✅ (verified in our tests)

```rust
#[test]
fn valid() {
    assert!(!is_valid_filename("..".as_ref()));
    assert!(!is_valid_filename(".".as_ref()));
    assert!(!is_valid_filename("aaaaaaaaaa:".as_ref()));
    assert!(!is_valid_filename("a ".as_ref()));           // Trailing space
    assert!(!is_valid_filename(" a. ".as_ref()));         // Trailing space
    assert!(!is_valid_filename("a*".as_ref()));
    assert!(!is_valid_filename("a\0a".as_ref()));
    assert!(!is_valid_filename("\x1f".as_ref()));         // Control char
}
```

**Our status:** ✅ Covered in our validation and tests

#### 1.6 Simplification Safety Checks
```rust
fn try_simplified(path: &Path) -> Option<&Path> {
    // Only handle VerbatimDisk UNC paths
    match p.kind() {
        Prefix::VerbatimDisk(..) => {},
        _ => return None,  // Other kinds of UNC paths left as-is
    }
    
    // Check each component
    for component in components {
        match component {
            Component::RootDir => {},
            Component::Normal(file_name) => {
                if !is_valid_filename(file_name) || is_reserved(file_name) {
                    return None;  // Keep as UNC if unsafe
                }
            }
            _ => return None,  // ".." and "." are NOT simplified from UNC
        }
    }
}
```

**Key insight:** They do NOT simplify paths containing `.` or `..` because "UNC paths take things like '..' literally"

**Our status:** ✅ We handle this correctly in our lexical normalization

---

## 2. Microsoft Documentation Analysis

**Source:** https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file

### 2.1 Reserved Characters (Comprehensive List)

From Microsoft:
```
< (less than)
> (greater than)
: (colon)
" (double quote)
/ (forward slash)
\ (backslash)
| (vertical bar or pipe)
? (question mark)
* (asterisk)
Integer value zero (NUL)
Characters 1-31 (control characters)
```

**Exception noted:** "except for alternate data streams where these characters are allowed"

**Our status:** ✅ We validate this in our ADS checks

### 2.2 Reserved Names (Official List)

Microsoft states:
```
CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
COM¹, COM², COM³, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9,
LPT¹, LPT², LPT³
```

**Key quote:** "Also avoid these names followed immediately by an extension; for example, NUL.txt and NUL.tar.gz are both equivalent to NUL."

**Our status:** ✅ We handle this (but may want to add superscript digit variants)

### 2.3 Trailing Space/Dot Rules

Microsoft states:
- "Do not end a file or directory name with a space or a period"
- "However, it is acceptable to specify a period as the first character of a name. For example, '.temp'"

**Our status:** ✅ Handled correctly

### 2.4 8.3 Short Names

Key points from Microsoft:
1. "When you create a long file name, Windows may also create a short 8.3 form"
2. "On many file systems, a file name will contain a tilde (~) within each component"
3. "Not all file systems follow the tilde substitution convention"
4. "Systems can be configured to disable 8.3 alias generation"
5. **"Therefore, do not make the assumption that the 8.3 alias already exists on-disk"**

**Functions mentioned:**
- `GetShortPathName` - get 8.3 form
- `GetLongPathName` - get long form from short
- `GetFullPathName` - get full path

**Our status:** ✅ We handle 8.3 heuristically and only expand when we probe existing components

### 2.5 UNC Path Namespaces

Microsoft defines these namespaces:

#### Win32 File Namespace (`\\?\`)
- "Disables all string parsing and sends the string straight to the file system"
- "Allows use of '.' and '..' in path names" (literal, not processed)
- "Allows exceeding MAX_PATH limits"
- **"Many but not all file I/O APIs support '\\?\'"**
- **"Unicode APIs should be used to make sure the '\\?\' prefix allows you to exceed the MAX_PATH"**

**Our approach:** ✅ We use extended-length format for all absolute results

#### Win32 Device Namespace (`\\.\`)
- "Accesses Win32 device namespace instead of file namespace"
- Used for physical disks, volumes, COM ports, etc.
- Examples: `\\.\PhysicalDriveX`, `\\.\CdRomX`, `\\.\COM56`

**Our status:** ✅ We preserve device paths and don't try to normalize them

#### NT Namespace
- Root is `\` (not `\\?\` or `C:\`)
- Contains `\Global??` (Win32 namespace), `\Device` (device objects), etc.
- `\\?\GLOBALROOT` prefix ensures true root path
- Used for symlinks and low-level system access

**Our status:** ✅ We handle `\\?\GLOBALROOT` as verbatim and don't normalize

### 2.6 Relative vs. Absolute Path Rules

Microsoft defines absolute paths as:
1. UNC name (starts with `\\`)
2. Disk designator with backslash (`C:\`)
3. Single backslash (`\directory`) - "absolute path" but relative to current drive

**Our status:** ✅ We correctly identify and handle all three cases

### 2.7 MAX_PATH Limitation

From Microsoft:
- Before Windows 10 1607: MAX_PATH = 260 characters (hard limit)
- After Windows 10 1607: Can be removed via registry or Group Policy
- **Solution:** Use `\\?\` prefix to bypass

**Our approach:** ✅ We use extended-length format which bypasses this entirely

---

## 3. Relevant Test Cases We Should Add/Verify

### 3.1 From dunce Tests

1. **Superscript digit reserved names** (low priority)
   ```rust
   // Add tests for COM¹, COM², COM³, LPT¹, LPT², LPT³
   ```

2. **Length boundary tests** (already covered, but verify)
   ```rust
   // Verify 255-char component handling
   // Verify 260-char path handling (we use UNC so should bypass)
   ```

3. **UTF-16 code unit vs byte count** (verify)
   ```rust
   // emoji and multi-byte characters: "🧐" = 2 UTF-16 code units
   ```

### 3.2 From Microsoft Docs

1. **Control character range 1-31** (verify coverage)
2. **ADS control character exceptions** (verify we allow in stream names)
3. **GLOBALROOT namespace** (add test if missing)
4. **Device namespace preservation** (verify `\\.\` handling)

---

## 4. Security Implications

### 4.1 Lessons from dunce

Their conservative approach to simplification provides validation for our conservative approach to extension:
- They refuse to simplify if ANY component is invalid
- They refuse to simplify if ANY component is reserved
- They refuse to simplify if path contains `.` or `..`
- They refuse to simplify if path exceeds 260 chars

**Takeaway:** Our requirement to maintain security boundaries and validate rigorously is sound.

### 4.2 ADS Edge Cases

Microsoft explicitly states control characters (1-31) are allowed in ADS, but we must still validate:
- Colon placement (must be final component)
- Stream name format (alphanumeric + allowed symbols)
- Type format (must be valid)
- No traversal via ADS

**Our status:** ✅ We have comprehensive ADS validation and security tests

---

## 5. Recommendations

### 5.1 High Priority

None - our implementation already covers all critical aspects correctly.

### 5.2 Medium Priority

1. **Cross-reference tests:** Ensure our test suite covers all edge cases from dunce's test suite (✅ COMPLETED)

### 5.3 Low Priority

1. **Superscript digit reserved names:** Add tests for `COM¹`, `COM²`, `COM³`, `LPT¹`, `LPT²`, `LPT³`
   - Microsoft officially lists these
   - Extremely rare in practice
   - Could add as defensive measure

2. **UTF-16 code unit counting:** Verify our length checks use proper UTF-16 code unit counts
   - Only relevant if we ever decide to enforce MAX_PATH limits
   - Currently bypassed by our UNC extended-length format

---

## 6. Test Suite Alignment (✅ COMPLETED)

### 6.1 Test Suite Cross-Reference

We should verify our test suite covers the same edge cases as dunce's, particularly:
- ✅ Reserved name detection with extensions
- ✅ Trailing space/dot validation
- ✅ Control character rejection
- ✅ Null byte rejection
- ⚠️ Superscript digit reserved names (consider adding)

---

## 7. Conclusion

Both sources validate our current implementation approach and provide no contradictory information. The dunce crate's conservative simplification logic mirrors our conservative extension logic, confirming our security-first approach is sound.

### Key Takeaways:

1. **No implementation gaps identified** - we already handle all critical cases
2. **Documentation could reference dunce** - complementary functionality
3. **Microsoft docs confirm our understanding** - no surprises or missed edge cases
4. **Test coverage is comprehensive** - minor gaps only in exotic edge cases (superscript digits)

### Action Items:

- [x] Cross-reference test coverage with dunce patterns (✅ COMPLETED - see src/tests/exotic_edge_cases.rs)
- [x] Add tests for superscript digit reserved names (✅ COMPLETED - documented behavior in exotic_edge_cases.rs)
- [x] Verify UTF-16 code unit counting (✅ COMPLETED - tests confirm extended-length format bypasses limits)
- [x] Verify control character handling in ADS context (✅ COMPLETED - extensive coverage in ads_*.rs tests)

**Overall assessment:** ✅ Our implementation is sound and complete relative to both sources. All identified edge cases have been verified with comprehensive test coverage.
