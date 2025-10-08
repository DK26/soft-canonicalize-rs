# Security Overview

Security does not depend on enabling features. The core API is secure-by-default; the optional `anchored` feature is a convenience for virtual roots.

Always-on protections:
- Lexical `.`/`..` handling with floors (root/share/device) — never pops above floor
- Symlink resolution with bounded depth (`MAX_SYMLINK_DEPTH`) and cycle detection
- Windows ADS validation (placement rules, token checks, control/whitespace, length)
- UNC/device namespace semantics; extended-length normalization on Windows
- NUL byte rejection; Unicode preserved as text (no unintended normalization)
- Percent encodings are not decoded (treated as text)

Anchored convenience (optional):
- Reinterprets absolute inputs and clamps both relative and absolute symlink targets to the anchor (virtual filesystem semantics)
- Shares the same hardened core; enabling it never weakens validation

Local CI exercises all modes: no features; `--features anchored`; and `--features anchored,dunce`. The `dunce` feature is presentation-only and never changes validation outcomes; unsafe cases remain UNC.

## Threat Classes and Mitigations

- Path Traversal / "Zip Slip"-like bypasses
  - Mitigation: Lexical `..` processing with clamping. No decoding of percent encodings.
  - Tests: `src/tests/platform_specific.rs`, `tests/anchored_blackbox_security.rs`.

- TOCTOU / Symlink Races
  - Mitigation: Deterministic resolver; no panics/hangs. Use race-resistant open flags for final writes (e.g., O_NOFOLLOW / CreateFileW policies).
  - Tests: `tests/blackbox_toctou_attacks.rs`, `src/tests/anchored_security/windows_symlink.rs` (swap to UNC/device).

- Symlink Cycles / Depth Exhaustion
  - Mitigation: `MAX_SYMLINK_DEPTH` and cycle detection.
  - Tests: `src/tests/symlink_depth.rs`.

- Windows NTFS ADS (Alternate Data Streams)
  - Mitigation: Early + late ADS validation; legitimate ADS (final component) accepted.
  - Tests: `tests/windows_ads_traversal.rs`, `tests/ads_advanced_exploits.rs`, `tests/ads_comprehensive_security.rs`, `tests/ads_security_verification.rs`.

- Windows UNC Floors and Device Namespaces
  - Mitigation: Respect UNC floors; treat device namespaces lexically; preserve trailing spaces/dots under verbatim paths.
  - Tests: `src/tests/platform_specific.rs`, `tests/blackbox_unc_attacks.rs`, `tests/blackbox_unc_corner_cases.rs`.

- Windows 8.3 Short Names
  - Mitigation: No expansion for non-existing suffixes; existing components probe normally.
  - Tests: `src/tests/short_filename_detection.rs`, Windows symlink + 8.3 suites.

- NUL-Byte / Unicode / Control Characters
  - Mitigation: Reject embedded NUL; preserve Unicode as text; validate ADS tokens strictly.
  - Tests: `src/tests/platform_specific.rs`, `tests/ads_*`, `tests/unicode_advanced_attacks.rs`.

## CVE-Class Mapping and Applicability

These CVE families are mitigated when using `soft_canonicalize` with a simple prefix policy — or `anchored_canonicalize` for a virtual root. Use race-resistant open flags to prevent TOCTOU during writes.

- GNU tar path escape (e.g., CVE-2025-45582)
  - Mitigation: `let base = soft_canonicalize(base_dir)?; let out = soft_canonicalize(base.join(member))?;` reject if `!out.starts_with(&base)`.
  - Tests: traversal/clamp suites listed above.

- Archive symlink handling (e.g., CVE-2024-0406, CVE-2025-55188)
  - Mitigation: Clamp symlink targets; absolute targets are reinterpreted under anchor; cycles bounded; prefix policy for core.
  - Tests: anchored symlink suites; TOCTOU swaps.

- Python tarfile traversal (e.g., CVE-2024-12718)
  - Mitigation: Clamp `..` lexically; no percent-decoding.
  - Tests: anchored black-box traversal; core platform traversal tests.

- Container volume symlink traversal (e.g., CVE-2025-9566)
  - Mitigation: virtual root semantics (anchored) or core + prefix policy; UNC/device quirks covered.
  - Tests: anchored symlink + UNC/device namespaces tests.

- Windows ADS traversal (WinRAR-style)
  - Mitigation: strict ADS placement/token validation; legit final-component ADS accepted (local and UNC).
  - Tests: ADS suites listed above.

If you have details for CVE-2025-61882, please share; existing suites already cover the common traversal/symlink/ADS classes.

## Secure Usage Pattern (no features required)

Archive extraction or "stay under base" policy:

```rust
let base = soft_canonicalize(base_dir)?; // absolute, normalized
let dest = soft_canonicalize(base.join(member_path))?; // resolve member under base
if !dest.starts_with(&base) {
    anyhow::bail!("escape attempt: {dest:?}");
}
// Open/write with race-resistant flags (O_NOFOLLOW / CreateFileW policies)
```

## CI / Local

- Run tests without features, with `--features anchored`, and with `--features anchored,dunce`.
- Local helpers: `bash ci-local.sh`, `./ci-local.ps1`.

## References

- Apache HTTP Server traversal normalization defects: CVE-2021-41773, CVE-2021-42013
- NIST NVD references for cited CVEs

Notes:
- Core and anchored flows are deterministic and panic-free.
- Do not decode URL-encoded or other encodings before validation unless you explicitly allow them; if you do, validate containment after decoding.

