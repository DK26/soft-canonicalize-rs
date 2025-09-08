# Security Notes and CVE-Class Review (soft-canonicalize + anchored)

This document summarizes threat classes relevant to path resolution and how this
crate mitigates them in both `soft_canonicalize` and the optional
`anchored_canonicalize` feature.

The anchored function is feature-gated (`features = ["anchored"]`) and reuses the
same hardened core: symlink chain resolution (`MAX_SYMLINK_DEPTH` + cycle
checks), NUL-byte rejection, Windows ADS validation, UNC/device semantics, and
Windows extended-length normalization. The anchor itself is canonicalized by
`soft_canonicalize`, so platform-specific protections are shared.

Run the full suite (including anchored tests):
- `cargo test --all-features`
- CI scripts: `bash ci-local.sh` or `./ci-local.ps1` (run both configs)

## Threat Classes and Mitigations

- Path Traversal / “Zip Slip”-like bypasses
  - Risk: `..` components or decoded bytes escape a boundary.
  - Mitigation: Lexical `..` processing with clamping (never pops above floor).
    No decoding of percent-encodings; input is treated as text.
  - Tests: `anchored_security/dotdot.rs`, `anchored_blackbox_security.rs` (deep chains, preservation).
  - Notes: Anchored semantics interpret input as if rooted under the anchor;
    absolute symlink targets explicitly drop the clamp by design.

- TOCTOU / Symlink Races
  - Risk: Retargeting links between checks and use.
  - Mitigation: Bounded chain resolver with stable, deterministic processing;
    no panics/hangs. For anchored, we treat the resolution as a pure step;
    callers should still open the final path with appropriate flags/policies.
  - Tests: `anchored_security/race.rs`.

- Symlink Cycles / Depth Exhaustion
  - Mitigation: Shared resolver with `MAX_SYMLINK_DEPTH` and cycle detection.
  - Tests: `anchored_security/symlink.rs`.

- Windows NTFS ADS (Alternate Data Streams)
  - Mitigation: Early and late ADS validation (component placement rules,
    non-empty stream name, control/zero-width protections, length checks,
    restricted types). Identical checks as `soft_canonicalize`.
  - Tests: `anchored_security/windows.rs`; black-box ADS preservation in
    `anchored_blackbox_security.rs`.

- Windows UNC Floors and Device Namespaces
  - Mitigation: Inputs with root/prefix are stripped for anchored processing;
    clamp applies to the suffix. UNC floors are respected; device namespaces are
    not converted. Final absolute results use extended-length prefixes.
  - Tests: `anchored_security/windows.rs`, `anchored_security/unc.rs`.

- Windows 8.3 Short Names
  - Mitigation: For non-existing suffixes we do not expand 8.3 names; existing
    anchor is canonicalized and follows the same rules as `soft_canonicalize`.
  - Tests: Covered by `short_filename_detection` for soft; anchored inherits
    through base canonicalization.

- NUL-Byte Injection
  - Mitigation: `reject_nul_bytes` on both Unix and Windows; returns InvalidInput.
  - Tests: `anchored_security/unicode.rs`.

- Unicode / Zero-Width / Control Characters
  - Mitigation: Characters are preserved (not stripped/normalized) and treated as
    text. ADS validation defends against Unicode manipulation within ADS tokens.
  - Tests: `anchored_security/unicode.rs`.

- Percent-Encoding / Mixed Encodings
  - Mitigation: Not decoded. Treated as text and thus subject to clamp rules.
  - Tests: `anchored_blackbox_security.rs`.

## CVE-Class Mapping and Applicability

- CVE-2022-21658 (symlink race conditions; canonicalization vs use)
  - Our suite includes white-box symlink race tests for both soft and anchored.
  - Anchored behavior is deterministic and robust against races during resolution;
    callers must still open files safely to avoid use-after-recheck issues.

- Historical libc realpath(3) pitfalls (buffer/length handling, existence-only)
  - We do not call libc `realpath` directly for non-existing suffixes. For fully
    existing paths, `std::fs::canonicalize` is used; Rust’s safety and dynamic
    `PathBuf` allocation avoid classic fixed-buffer hazards. Anchored traversal
    uses our own lexical engine + shared symlink resolver, independent of libc
    `realpath`.

- Windows path canonicalization issues (device/UNC/ADS)
  - Addressed by explicit ADS validation, UNC-floor semantics, verbatim/extended-
    length handling, and input root stripping in anchored mode.
  - Tests: `anchored_security/windows.rs`, `anchored_security/unc.rs`.

## References

- Apache HTTP Server traversal normalization defects:
  - CVE-2021-41773 — https://nvd.nist.gov/vuln/detail/CVE-2021-41773
  - CVE-2021-42013 — https://nvd.nist.gov/vuln/detail/CVE-2021-42013
- Symlink race condition class:
  - CVE-2022-21658 — https://nvd.nist.gov/vuln/detail/CVE-2022-21658
- “Zip Slip” archival path traversal (research article):
  - https://snyk.io/research/zip-slip-vulnerability
- POSIX `realpath(3)` documentation:
  - https://man7.org/linux/man-pages/man3/realpath.3.html
- Microsoft documentation:
  - NTFS Alternate Data Streams — https://learn.microsoft.com/en-us/windows/win32/fileio/ntfs-alternate-data-streams
  - File path formats, UNC, verbatim, extended-length — https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file

## Verification Matrix (Threat → Tests)

| Threat/Class | References | Mitigation (summary) | Tests (anchored) | Tests (soft) |
| --- | --- | --- | --- | --- |
| Traversal normalization (escape via ..) | CVE-2021-41773, CVE-2021-42013 | Lexical normalization with clamp; no decoding | src/tests/anchored_security/dotdot.rs::clamp_prevents_escape_on_lexical_dotdot; tests/anchored_blackbox_security.rs::deep_dotdot_chain_is_clamped | src/tests/path_traversal.rs::test_mixed_existing_and_nonexisting_with_traversal; src/tests/security_audit/dotdot.rs::* |
| Symlink race (TOCTOU) | CVE-2022-21658 | Deterministic chain resolve; bounded; no panic/hang | src/tests/anchored_security/race.rs::concurrent_symlink_modification_anchor | src/tests/cve_tests.rs::test_cve_2022_21658_race_condition; src/tests/security_audit/race.rs::* |
| Archive traversal (Zip Slip class) | Snyk Zip Slip | No percent-decoding; clamp enforced | tests/anchored_blackbox_security.rs::blackbox_clamp_and_preservation | src/tests/security_audit/unicode.rs::test_double_encoding_bypass_prevention |
| realpath(3) pitfalls (existence-only, buffers) | POSIX man7 realpath | Avoid libc realpath for non-existing tails; use lexical + shared resolver | src/tests/anchored_security/boundary.rs::{absolute_and_relative_inputs_under_anchor,long_tail_and_component_limits_do_not_break} | src/tests/std_behavior.rs::*; src/tests/python_inspired_tests.rs::* |
| Windows ADS misuse | MS ADS docs | Early/late ADS validation; invalid non-final colon rejected | src/tests/anchored_security/windows.rs::ads_layout_validation_applies_to_input; tests/anchored_blackbox_security.rs::windows_ads_percent_encoded_colon_is_not_decoded | tests/windows_ads_traversal.rs; src/tests/security_audit/windows.rs::* |
| Windows UNC/device namespace confusion | MS naming docs | Strip input roots for anchored; respect UNC floors; extended-length | src/tests/anchored_security/unc.rs::unc_anchor_clamp_floor_respected; tests/anchored_blackbox_security.rs::windows_device_and_verbatim_inputs_are_sandboxed | tests/blackbox_unc_*; src/tests/security_audit/unc.rs::* |
| Windows extended-length normalization | MS naming docs | Ensure extended-length on absolute outputs | src/tests/anchored_security/windows.rs::extended_length_prefix_on_absolute_results | src/tests/platform_specific.rs::* (Windows); tests/std_compat.rs::* (Windows) |
| Symlink cycles/exhaustion | — | Depth cap + cycle detection (shared resolver) | src/tests/anchored_security/symlink.rs::cycle_and_hop_limit_protected | src/tests/symlink_depth.rs::*; src/tests/security_audit/symlink.rs::* |
| Symlink semantics: relative vs absolute | — | Relative keeps clamp; absolute drops clamp by policy | src/tests/anchored_security/symlink.rs::{relative_symlink_keeps_clamp,absolute_symlink_drops_clamp} | src/tests/symlink_dotdot_symlink_first.rs::*; src/tests/symlink_dotdot_resolution_order.rs::* |
| NUL-byte injection | — | Reject NUL (InvalidInput) | src/tests/anchored_security/unicode.rs::null_byte_injection_rejected | src/tests/security_audit/unicode.rs::{test_null_byte_injection,test_null_byte_error_consistency} |
| Unicode/zero-width/control | — | Preserve characters; ADS unicode defense | src/tests/anchored_security/unicode.rs::zero_width_and_control_preserved | src/tests/security_audit/unicode.rs::{test_zero_width_and_control_character_handling,test_unicode_path_edge_cases} |
| Unix backslash literal | — | Treat '\\' as ordinary char on Unix | tests/anchored_blackbox_security.rs::unix_backslash_is_literal_not_separator | src/tests/python_inspired_tests.rs::test_resolve_unusual_characters |
| Windows 8.3 short names | — | Do not expand for non-existing suffix; inherit anchor handling | (Inherits via anchored base canonicalization) | src/tests/short_filename_detection.rs::*; src/tests/security_audit/windows.rs::* |

## Guidance for Callers

- Anchored canonicalization is a deterministic resolution step. To prevent TOCTOU
  issues, prefer opening the file with policies (e.g., O_NOFOLLOW where available)
  and avoid subsequent symlinkable lookups before file operations.
- Do not decode URL-encoded or other encodings before validation unless you intend
  to allow those semantics; if you do, pass the decoded path into anchored
  canonicalization and validate containment explicitly.
