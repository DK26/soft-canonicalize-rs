#![cfg(windows)]
//! Advanced Unicode Attack Vector Tests
//!
//! This suite covers sophisticated Unicode-based attack vectors that could potentially
//! confuse path canonicalization, including mixed-script attacks, normalization edge cases,
//! and complex encoding boundary conditions.

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io::{self, ErrorKind};

fn expect_invalid(res: io::Result<impl std::fmt::Debug>, pattern: &str) {
    match res {
        Ok(v) => panic!("Expected InvalidInput for pattern '{pattern}', got Ok({v:?})"),
        Err(e) => assert_eq!(
            e.kind(),
            ErrorKind::InvalidInput,
            "Expected InvalidInput for pattern '{pattern}', got {e:?}"
        ),
    }
}

#[test]
fn test_mixed_script_unicode_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Mixed script attacks using characters from multiple Unicode blocks
    let mixed_script_attacks = [
        // Latin + Cyrillic mix in stream names
        "test.txt:streaм..\\evil.exe", // Latin 'stream' + Cyrillic 'м'
        "test.txt:strеam..\\bypass.exe", // Latin 'str' + Cyrillic 'е' + Latin 'am'
        "test.txt:ѕtream..\\exploit.exe", // Cyrillic 'ѕ' + Latin 'tream'
        // Latin + Greek mix
        "test.txt:streαm..\\evil.exe", // Latin 'stre' + Greek 'α' + Latin 'm'
        "test.txt:streaμ..\\bypass.exe", // Latin 'strea' + Greek 'μ'
        // Latin + Arabic mix
        "test.txt:streaم..\\exploit.exe", // Latin 'strea' + Arabic 'م'
        // Triple script mix (Latin + Cyrillic + Greek)
        "test.txt:stгeaμ..\\evil.exe", // Latin 'st' + Cyrillic 'г' + Latin 'ea' + Greek 'μ'
        // Mixed scripts in filename base with ADS
        "teѕt.txt:stream..\\evil.exe",   // Cyrillic 'ѕ' in filename
        "tеst.txt:stream..\\bypass.exe", // Cyrillic 'е' in filename
    ];

    for pattern in mixed_script_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Mixed script attack correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_unicode_normalization_boundary_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Unicode normalization form confusion attacks
    let normalization_attacks = [
        // NFD vs NFC confusion in path traversal
        "test.txt:stre\u{0061}\u{0301}m..\\evil.exe", // 'e' + combining acute accent (NFD)
        "test.txt:stre\u{00E1}m..\\bypass.exe",       // precomposed 'á' (NFC)
        // Combining character ordering attacks
        "test.txt:stre\u{0061}\u{0301}\u{0300}m..\\evil.exe", // 'a' + acute + grave
        "test.txt:stre\u{0061}\u{0300}\u{0301}m..\\evil.exe", // 'a' + grave + acute (different order)
        // Multiple combining characters
        "test.txt:str\u{0065}\u{0301}\u{0302}\u{0308}am..\\evil.exe", // 'e' + acute + circumflex + diaeresis
        // Decomposed characters in traversal
        "test.txt:stream:\u{0041}\u{0301}..\\evil.exe", // decomposed 'Á' in fake type
        // Mixed normalization forms
        "test.txt:\u{00E9}tre\u{0061}\u{0301}m..\\evil.exe", // NFC 'é' + NFD 'á'
    ];

    for pattern in normalization_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Normalization attack correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_reserved_name_unicode_variants() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;

    // Reserved names with Unicode variants
    let reserved_name_attacks = [
        // Cyrillic variants of reserved names
        "СОN.txt:stream..\\evil.exe",    // Cyrillic 'С' and 'О'
        "СОN:stream..\\bypass.exe",      // Full Cyrillic CON
        "AΥΧ.txt:stream..\\exploit.exe", // Greek 'Υ' instead of 'U'
        "PRΝ.txt:stream..\\evil.exe",    // Greek 'Ν' instead of 'N'
        // Reserved names with combining characters
        "CO\u{0300}N.txt:stream..\\evil.exe", // 'O' with combining grave
        "CON\u{200B}.txt:stream..\\evil.exe", // CON with zero-width space
        // Mixed case with Unicode variants
        "Сon.txt:stream..\\bypass.exe",  // Cyrillic 'С' + Latin 'on'
        "cОn.txt:stream..\\exploit.exe", // Latin 'c' + Cyrillic 'О' + Latin 'n'
        // Reserved extensions with Unicode
        "file.txt:СОN..\\evil.exe",          // Cyrillic CON as stream name
        "file.txt:stream:$DΑTA..\\evil.exe", // Greek 'Α' in $DATA
    ];

    for pattern in reserved_name_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Reserved name Unicode variant correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_long_stream_name_boundary() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Test very long stream names near Windows limits (255 chars)
    let base_attack = "..\\evil.exe";
    let padding_lengths: &[usize] = &[240, 250, 255, 260, 300]; // Around and over the limit

    for &length in padding_lengths {
        let stream_part = "a".repeat(length.saturating_sub(base_attack.len()));
        let pattern = format!("test.txt:{stream_part}{base_attack}");

        let path = tmp.path().join(&pattern);
        expect_invalid(soft_canonicalize(&path), &pattern);
        println!(
            "✓ Long stream name attack correctly rejected (length {}): {:.50}...",
            pattern.len(),
            pattern
        );
    }

    // Test with Unicode characters that take multiple bytes
    let unicode_padding = "🔥".repeat(50); // Each emoji is 4 bytes in UTF-8
    let unicode_pattern = format!("test.txt:{unicode_padding}..\\evil.exe");
    let path = tmp.path().join(&unicode_pattern);
    expect_invalid(soft_canonicalize(path), &unicode_pattern);
    println!("✓ Long Unicode stream name attack correctly rejected");

    Ok(())
}

#[test]
fn test_file_extension_homoglyph_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;

    // File extension homoglyph attacks
    let extension_attacks = [
        // Cyrillic extensions that look like common ones
        "script.рy:stream..\\evil.exe", // Cyrillic 'р' instead of 'p'
        "config.јs:stream..\\bypass.exe", // Cyrillic 'ј' instead of 'j'
        "data.ехе:stream..\\exploit.exe", // Cyrillic 'е' and 'х'
        "readme.tхt:stream..\\evil.exe", // Cyrillic 'х' instead of 'x'
        // Greek extensions
        "script.pγ:stream..\\bypass.exe", // Greek 'γ' instead of 'y'
        "config.jѕ:stream..\\exploit.exe", // Cyrillic 'ѕ' instead of 's'
        // Mixed script extensions
        "file.tхt:stream..\\evil.exe", // Latin 't' + Cyrillic 'х' + Latin 't'
        "script.руthοn:stream..\\evil.exe", // Mix of Cyrillic and Greek
        // Extensions with combining characters
        "script.p\u{0079}\u{0301}:stream..\\evil.exe", // 'y' with combining acute
        "config.t\u{0078}\u{0308}t:stream..\\evil.exe", // 'x' with combining diaeresis
    ];

    for pattern in extension_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Extension homoglyph attack correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_advanced_case_folding_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;

    // Advanced case folding edge cases
    let case_folding_attacks = [
        // Turkish dotted/dotless i variations
        "test.txt:streAm..\\evil.exe", // Turkish context could affect case folding
        "test.txt:STREAM..\\evil.exe", // All caps
        "test.txt:Stream..\\evil.exe", // Title case
        // German ß (eszett) variations - ß folds to 'ss'
        "test.txt:straße..\\evil.exe",  // German ß
        "test.txt:strasse..\\evil.exe", // Equivalent 'ss'
        // Case folding with combining characters
        "test.txt:stre\u{0041}\u{0301}m..\\evil.exe", // Uppercase A with acute accent
        "test.txt:stre\u{0061}\u{0301}m..\\evil.exe", // Lowercase a with acute accent
        // Greek case folding edge cases
        "test.txt:ΣTREAM..\\evil.exe", // Greek sigma at end vs middle
        "test.txt:σTREAM..\\evil.exe", // Mixed case with Greek
        // Complex case folding sequences
        "test.txt:STREAm..\\evil.exe", // Mixed case pattern
        "test.txt:sTrEaM..\\evil.exe", // Alternating case
    ];

    for pattern in case_folding_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Case folding attack correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_utf16_surrogate_boundary_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // UTF-16 surrogate pair edge cases
    // Note: These should be properly handled by Rust's UTF-8 string validation
    let surrogate_attacks = [
        // High surrogate without low surrogate (would be invalid UTF-8 in Rust)
        // These patterns use valid UTF-8 that represents edge cases

        // Emoji that use surrogate pairs in UTF-16 but are valid UTF-8
        "test.txt:🔥tream..\\evil.exe",  // Fire emoji + traversal
        "test.txt:str💀eam..\\evil.exe", // Skull emoji in middle
        "test.txt:stream🎯..\\evil.exe", // Target emoji + traversal
        // Complex emoji sequences
        "test.txt:str👨‍💻eam..\\evil.exe", // Man technologist (multi-codepoint)
        "test.txt:stream🏴‍☠️..\\evil.exe", // Pirate flag (complex sequence)
        // Mathematical symbols that could be surrogates in UTF-16
        "test.txt:str𝔸eam..\\evil.exe", // Mathematical double-struck A
        "test.txt:stream𝕏..\\evil.exe", // Mathematical double-struck X
        // Ancient scripts (high Unicode planes)
        "test.txt:str𐍈eam..\\evil.exe", // Gothic letter
        "test.txt:stream𝼀..\\evil.exe", // CJK ideograph extension
    ];

    for pattern in surrogate_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Surrogate boundary attack correctly rejected: {pattern}");
    }

    Ok(())
}
