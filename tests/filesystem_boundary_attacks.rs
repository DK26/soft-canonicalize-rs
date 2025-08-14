#![cfg(windows)]
//! Filesystem Boundary and Edge Case Tests
//!
//! This suite tests edge cases around filesystem limits, complex path structures,
//! and boundary conditions that could potentially bypass validation.

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
fn test_complex_path_component_limits() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Test paths near Windows component length limits (255 chars per component)
    let component_sizes: &[usize] = &[250, 255, 256, 300, 1000];

    for &size in component_sizes {
        // Test long filename with ADS
        let long_filename = format!("{}.txt", "a".repeat(size));
        let pattern = format!("{long_filename}:stream..\\evil.exe");
        let path = tmp.path().join(&pattern);

        match soft_canonicalize(&path) {
            Ok(_) => panic!("Long filename component should be rejected: {pattern:.50}..."),
            Err(e) => {
                // Should be InvalidInput for malformed ADS or potentially other filesystem errors
                println!(
                    "✓ Long filename component correctly rejected (size {}): {:?}",
                    size,
                    e.kind()
                );
            }
        }

        // Test long directory component
        let long_dir = "a".repeat(size);
        let pattern = format!("{long_dir}\\file.txt:stream..\\evil.exe");
        let path = tmp.path().join(&pattern);

        match soft_canonicalize(&path) {
            Ok(_) => {
                // If accepted, verify it doesn't escape temp directory
                let canonical = soft_canonicalize(&path)?;
                assert!(
                    canonical.starts_with(tmp.path()),
                    "Long directory component path escaped temp directory"
                );
                println!("✓ Long directory component handled safely (size {size})");
            }
            Err(e) => {
                println!(
                    "✓ Long directory component rejected (size {}): {:?}",
                    size,
                    e.kind()
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_deeply_nested_path_structures() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Test deeply nested path structures with ADS
    let depths: &[usize] = &[10, 50, 100, 200];

    for &depth in depths {
        // Create deeply nested directory structure
        let mut nested_path = String::new();
        for i in 0..depth {
            if i > 0 {
                nested_path.push('\\');
            }
            nested_path.push_str(&format!("dir{i}"));
        }

        let pattern = format!("{nested_path}\\file.txt:stream..\\evil.exe");
        let path = tmp.path().join(&pattern);

        match soft_canonicalize(&path) {
            Ok(canonical) => {
                // If accepted, verify it stays within bounds
                assert!(
                    canonical.starts_with(tmp.path()),
                    "Deeply nested path escaped temp directory at depth {depth}"
                );
                println!("✓ Deeply nested path handled safely (depth {depth})");
            }
            Err(e) => {
                println!(
                    "✓ Deeply nested path rejected (depth {}): {:?}",
                    depth,
                    e.kind()
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_mixed_separator_boundary_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Test various separator mixing that could confuse parsing
    let separator_attacks = [
        // Forward slash in ADS stream names (should be invalid)
        "test.txt:stream/../evil.exe",
        "test.txt:stream/.\\evil.exe",
        "test.txt:stream/..\\evil.exe",
        // Mixed separators in complex patterns
        "test.txt:stream:../\\evil.exe",
        "test.txt:stream:\\../evil.exe",
        "test.txt:stream:.\\../evil.exe",
        // Multiple separator types
        "test.txt:stream:.\\..\\../evil.exe",
        "test.txt:stream:..\\../\\evil.exe",
        // Separator confusion with Unicode lookalikes
        "test.txt:stream\u{2215}..\\evil.exe", // Division slash
        "test.txt:stream\u{29F8}..\\evil.exe", // Big solidus
        "test.txt:stream\u{FF0F}..\\evil.exe", // Fullwidth solidus
    ];

    for pattern in separator_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Mixed separator attack correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_whitespace_boundary_exploitation() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Test various whitespace characters that could be used for confusion
    let whitespace_attacks = [
        // Different Unicode whitespace characters
        "test.txt:stream\u{00A0}..\\evil.exe", // Non-breaking space
        "test.txt:stream\u{2000}..\\evil.exe", // En quad
        "test.txt:stream\u{2001}..\\evil.exe", // Em quad
        "test.txt:stream\u{2002}..\\evil.exe", // En space
        "test.txt:stream\u{2003}..\\evil.exe", // Em space
        "test.txt:stream\u{2004}..\\evil.exe", // Three-per-em space
        "test.txt:stream\u{2005}..\\evil.exe", // Four-per-em space
        "test.txt:stream\u{2006}..\\evil.exe", // Six-per-em space
        "test.txt:stream\u{2007}..\\evil.exe", // Figure space
        "test.txt:stream\u{2008}..\\evil.exe", // Punctuation space
        "test.txt:stream\u{2009}..\\evil.exe", // Thin space
        "test.txt:stream\u{200A}..\\evil.exe", // Hair space
        "test.txt:stream\u{202F}..\\evil.exe", // Narrow no-break space
        "test.txt:stream\u{205F}..\\evil.exe", // Medium mathematical space
        "test.txt:stream\u{3000}..\\evil.exe", // Ideographic space
        // Combining whitespace with regular characters
        "test.txt:stre\u{00A0}am..\\evil.exe", // Non-breaking space in middle
        "test.txt:\u{2000}stream..\\evil.exe", // En quad at start
        "test.txt:stream\u{3000}..\\evil.exe", // Ideographic space before traversal
        // Multiple whitespace types
        "test.txt:str\u{00A0}\u{2000}eam..\\evil.exe", // Mixed whitespace
    ];

    for pattern in whitespace_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Whitespace boundary attack correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_control_character_boundary_attacks() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Test control characters that could be used for obfuscation
    let control_attacks = [
        // C0 control characters
        "test.txt:stream\u{0001}..\\evil.exe", // Start of heading
        "test.txt:stream\u{0002}..\\evil.exe", // Start of text
        "test.txt:stream\u{0003}..\\evil.exe", // End of text
        "test.txt:stream\u{0004}..\\evil.exe", // End of transmission
        "test.txt:stream\u{0005}..\\evil.exe", // Enquiry
        "test.txt:stream\u{0006}..\\evil.exe", // Acknowledge
        "test.txt:stream\u{0007}..\\evil.exe", // Bell
        "test.txt:stream\u{0008}..\\evil.exe", // Backspace
        "test.txt:stream\u{000B}..\\evil.exe", // Vertical tab
        "test.txt:stream\u{000C}..\\evil.exe", // Form feed
        "test.txt:stream\u{000E}..\\evil.exe", // Shift out
        "test.txt:stream\u{000F}..\\evil.exe", // Shift in
        "test.txt:stream\u{007F}..\\evil.exe", // Delete
        // C1 control characters
        "test.txt:stream\u{0080}..\\evil.exe", // Padding character
        "test.txt:stream\u{0081}..\\evil.exe", // High octet preset
        "test.txt:stream\u{0084}..\\evil.exe", // Index
        "test.txt:stream\u{0085}..\\evil.exe", // Next line
        "test.txt:stream\u{0086}..\\evil.exe", // Start of selected area
        "test.txt:stream\u{0087}..\\evil.exe", // End of selected area
        "test.txt:stream\u{009F}..\\evil.exe", // Application program command
        // Format control characters
        "test.txt:stream\u{200E}..\\evil.exe", // Left-to-right mark
        "test.txt:stream\u{200F}..\\evil.exe", // Right-to-left mark
        "test.txt:stream\u{202A}..\\evil.exe", // Left-to-right embedding
        "test.txt:stream\u{202B}..\\evil.exe", // Right-to-left embedding
        "test.txt:stream\u{202C}..\\evil.exe", // Pop directional formatting
        "test.txt:stream\u{202D}..\\evil.exe", // Left-to-right override
        "test.txt:stream\u{202E}..\\evil.exe", // Right-to-left override
        // Variation selectors
        "test.txt:stream\u{FE0E}..\\evil.exe", // Variation selector-15
        "test.txt:stream\u{FE0F}..\\evil.exe", // Variation selector-16
    ];

    for pattern in control_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Control character attack correctly rejected: {pattern}");
    }

    Ok(())
}

#[test]
fn test_filesystem_metadata_confusion() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("test.txt");
    fs::write(&base, b"test")?;

    // Test patterns that could confuse filesystem metadata parsing
    let metadata_attacks = [
        // Patterns that could be confused with filesystem attributes
        "test.txt:stream:HIDDEN..\\evil.exe",
        "test.txt:stream:SYSTEM..\\evil.exe",
        "test.txt:stream:READONLY..\\evil.exe",
        "test.txt:stream:ARCHIVE..\\evil.exe",
        // Patterns mimicking file permissions
        "test.txt:stream:755..\\evil.exe",
        "test.txt:stream:644..\\evil.exe",
        "test.txt:stream:777..\\evil.exe",
        // Patterns mimicking special filesystem entries
        "test.txt:stream:..\\..\\..\\evil.exe", // Multiple traversal
        "test.txt:stream:.DS_Store..\\evil.exe", // macOS metadata
        "test.txt:stream:Thumbs.db..\\evil.exe", // Windows thumbnail cache
        "test.txt:stream:desktop.ini..\\evil.exe", // Windows folder config
        // NTFS-specific metadata confusion
        "test.txt:stream:$FILE_NAME..\\evil.exe",
        "test.txt:stream:$STANDARD_INFORMATION..\\evil.exe",
        "test.txt:stream:$ATTRIBUTE_LIST..\\evil.exe",
    ];

    for pattern in metadata_attacks {
        let path = tmp.path().join(pattern);
        expect_invalid(soft_canonicalize(&path), pattern);
        println!("✓ Metadata confusion attack correctly rejected: {pattern}");
    }

    Ok(())
}
