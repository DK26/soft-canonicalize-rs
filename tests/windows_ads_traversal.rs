// Windows-only tests covering ADS + traversal + short-name edge cases inspired by CVE-2025-8088 PoC patterns
// Focus: Ensure soft_canonicalize preserves textual intent and does not collapse traversal inside ADS-like segments.
// These are defense-in-depth; Windows path semantics may reject some patterns (invalid stream names),
// but the library must not panic or incorrectly normalize across ':' boundaries.

#![cfg(windows)]

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io;

fn expect_invalid(res: io::Result<impl std::fmt::Debug>, pattern: &str) {
    match res {
        Ok(v) => panic!("Expected InvalidInput for pattern '{pattern}', got Ok({v:?})"),
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidInput,
            "Expected InvalidInput for pattern '{pattern}', got {e:?}"
        ),
    }
}

#[test]
fn test_ads_stream_traversal_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("decoy.txt");
    fs::write(base, b"decoy")?;

    let cases = [
        "decoy.txt:..\\..\\evil.exe",
        "decoy.txt:..\\..\\..\\deep\\evil.bat:$DATA",
        "decoy.txt:..\\PaYlOaD\\script.ps1:$DATA",
    ];
    for raw in cases {
        let path = tmp.path().join(raw);
        expect_invalid(soft_canonicalize(&path), raw);
    }
    Ok(())
}

#[test]
fn test_ads_traversal_plus_shortname_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    // Simulate a short-name-like base component with ADS traversal injection
    let pattern = "DOCUME~1:..\\..\\payload.bin";
    let path = tmp.path().join(pattern);
    expect_invalid(soft_canonicalize(path), pattern);
    Ok(())
}

#[test]
fn test_long_ads_placeholder_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("decoy.txt");
    fs::write(base, b"decoy")?;
    let placeholder = "X".repeat(256); // simulate patched placeholder length
    let pattern = format!("decoy.txt:{placeholder}..\\..\\pivot.exe");
    let path = tmp.path().join(&pattern);
    expect_invalid(soft_canonicalize(path), &pattern);
    Ok(())
}

#[test]
fn test_original_ads_traversal_poc_regression() -> io::Result<()> {
    // Regression for earlier behavior where the library would incorrectly return an Ok path
    // (base_dir/evil.exe) for pattern: decoy.txt:..\\..\\evil.exe
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("decoy.txt");
    std::fs::write(base, b"decoy")?;

    let exploit = "decoy.txt:..\\..\\evil.exe"; // exact PoC pattern
    let exploit_path = tmp.path().join(exploit);

    // What the previous (vulnerable) logic produced after lexical normalization
    // (effectively dropping the colon + traversal intent): tmp/evil.exe
    let previously_incorrect = tmp.path().join("evil.exe");

    let res = soft_canonicalize(exploit_path);
    match res {
        Ok(p) => panic!(
            "Exploit pattern unexpectedly succeeded. Got {p:?} (expected InvalidInput). Prior bug would have returned {previously_incorrect:?}"
        ),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "Expected InvalidInput"),
    }
    Ok(())
}

#[test]
fn test_ads_additional_valid_stream_names_accepted() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    std::fs::write(tmp.path().join("file.txt"), b"x")?;
    let accepted = [
        "file.txt:alpha",
        "file.txt:..hiddenstream", // leading dots but not traversal
        "file.txt:multi.part.name",
        "file.txt:alpha_numeric_123",
    ];
    for pat in accepted {
        let res = soft_canonicalize(tmp.path().join(pat));
        assert!(res.is_ok(), "Expected Ok for {pat}, got {res:?}");
    }
    Ok(())
}

#[test]
fn test_ads_reject_dot_and_dotdot_stream_names() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    std::fs::write(tmp.path().join("file.txt"), b"x")?;
    let rejected = ["file.txt:", "file.txt:.", "file.txt:.."];
    for pat in rejected {
        expect_invalid(soft_canonicalize(tmp.path().join(pat)), pat);
    }
    Ok(())
}

#[test]
fn test_multiple_colons_stream_variants_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    fs::write(&base, b"file")?;
    let variants = [
        "file.txt:placeholder:..\\..\\x:$DATA",
        "file.txt:one:two:three", // colon-containing non-final component
        "file.txt:one:..\\two:three:$DATA",
    ];
    for raw in variants {
        let path = tmp.path().join(raw);
        expect_invalid(soft_canonicalize(&path), raw);
    }
    Ok(())
}

#[test]
fn test_deep_ads_traversal_stress_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("decoy.txt");
    fs::write(base, b"decoy")?;
    let depth = 40; // deeper than typical exploit requirement
    let traversal = (0..depth).map(|_| "..\\").collect::<String>();
    let pattern = format!("decoy.txt:{traversal}final.bin");
    let path = tmp.path().join(&pattern);
    expect_invalid(soft_canonicalize(path), &pattern);
    Ok(())
}

#[test]
fn test_positive_ads_final_component_allowed() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let p1 = tmp.path().join("file.txt:stream");
    let p2 = tmp.path().join("file.txt:stream:$DATA");
    // These should be accepted (non-final colon only inside final component)
    let r1 = soft_canonicalize(p1);
    assert!(r1.is_ok(), "Expected Ok for file.txt:stream");
    let r2 = soft_canonicalize(p2);
    assert!(r2.is_ok(), "Expected Ok for file.txt:stream:$DATA");
    Ok(())
}

#[test]
fn test_directory_ads_final_component_allowed() -> io::Result<()> {
    // Accept ADS pattern when applied to a directory as the final component
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("mydir");
    fs::create_dir(&dir)?;

    // Build input with ADS suffix on the directory
    let input = std::path::PathBuf::from(format!("{}:stream", dir.display()));
    let out = soft_canonicalize(input)?;

    // Expected: canonicalize(dir) with the ADS suffix appended textually
    let canon_dir = std::fs::canonicalize(&dir)?;
    let expected = std::path::PathBuf::from(format!("{}:stream", canon_dir.display()));

    #[cfg(not(feature = "dunce"))]
    {
        assert_eq!(out, expected);
    }

    #[cfg(feature = "dunce")]
    {
        // For ADS-bearing paths, keep UNC for safety; do not simplify
        assert!(out.to_string_lossy().starts_with(r"\\?\"));
        assert_eq!(out, expected);
    }

    Ok(())
}

#[test]
fn test_directory_ads_type_only_final_rejected() -> io::Result<()> {
    // Type-only ADS token as final component should be rejected for directories
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("adsdir");
    fs::create_dir(&dir)?;

    let input = std::path::PathBuf::from(format!("{}::$DATA", dir.display()));
    let err = soft_canonicalize(input).expect_err("dir::$DATA must be invalid");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    Ok(())
}

#[test]
fn test_trailing_colon_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    std::fs::write(base, b"x")?;
    let pattern = "file.txt:"; // empty stream name
    let path = tmp.path().join(pattern);
    expect_invalid(soft_canonicalize(path), pattern);
    Ok(())
}

#[test]
fn test_invalid_stream_type_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("file.txt");
    std::fs::write(base, b"x")?;
    // Third segment (type) missing leading '$' should be rejected
    let pattern = "file.txt:stream:DATA";
    let path = tmp.path().join(pattern);
    expect_invalid(soft_canonicalize(path), pattern);
    Ok(())
}

#[test]
fn test_ads_traversal_all_existence_scenarios_rejected() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;

    // Case A: fully existing file
    let base = tmp.path().join("decoy.txt");
    fs::write(base, b"decoy")?;
    let raw_a = "decoy.txt:..\\..\\evil.exe";
    let path_a = tmp.path().join(raw_a);
    expect_invalid(soft_canonicalize(path_a), raw_a);

    // Case B: partially existing (directory exists, file does not)
    let subdir = tmp.path().join("partial_dir");
    fs::create_dir(subdir)?;
    let raw_b = "partial_dir/decoy.txt:..\\..\\evil.exe";
    let path_b = tmp.path().join(raw_b);
    expect_invalid(soft_canonicalize(path_b), raw_b);

    // Case C: completely non-existing path — simple fully-qualified absolute path
    let raw_c = r"C:\no_such_dir\no_such_file.txt:..\..\evil.exe";
    expect_invalid(soft_canonicalize(raw_c), raw_c);

    Ok(())
}
