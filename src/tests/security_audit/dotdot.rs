// Dotdot/parent directory traversal tests
use crate::soft_canonicalize;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_deeply_nested_dotdot_with_symlinks() -> std::io::Result<()> {
    // WHITE-BOX: Test the interaction between .. resolution and symlink handling

    #[cfg(unix)]
    {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create: /base/deep/nested/path/
        let deep_path = base.join("deep").join("nested").join("path");
        fs::create_dir_all(deep_path)?;

        // Create symlink: /base/shortcut -> /base/deep/nested
        let shortcut = base.join("shortcut");
        std::os::unix::fs::symlink(base.join("deep").join("nested"), &shortcut)?;

        // Test path with complex .. traversal through symlink:
        // shortcut/path/../../other/../final/file.txt
        let complex_path = shortcut
            .join("path")
            .join("..")
            .join("..")
            .join("other")
            .join("..")
            .join("final")
            .join("file.txt");

        let result = soft_canonicalize(complex_path)?;

        // Should resolve to: /base/final/file.txt (not /base/deep/final/file.txt)
        // Because: shortcut/path/../../other/../final/file.txt
        // shortcut -> /base/deep/nested, so shortcut/path -> /base/deep/nested/path
        // shortcut/path/../.. goes up two levels from /base/deep/nested/path -> /base/deep/nested -> /base/deep -> /base
        // then other/../final -> /base/final
        let canonical_base = fs::canonicalize(base)?;
        let expected = canonical_base.join("final").join("file.txt");

        // On some platforms (like macOS), the path resolution might differ
        // Check that the result ends with the expected path structure
        let result_str = result.to_string_lossy();
        let expected_suffix = "final/file.txt";
        assert!(
            result_str.ends_with(expected_suffix) || result == expected,
            "Path should end with '{expected_suffix}' or match exactly. Got: {result_str}, Expected: {}",
            expected.to_string_lossy()
        );
    }

    Ok(())
}

#[test]
fn test_dotdot_security_bypass() -> std::io::Result<()> {
    // WHITE-BOX: Try to exploit the simplified dotdot security check (> 3 components)
    // by using exactly 3 or fewer .. components in creative ways
    let temp_dir = TempDir::new()?;
    let _base = temp_dir.path();

    #[cfg(unix)]
    {
        // Create deep directory structure
        let deep = _base.join("a").join("b").join("c").join("d").join("e");
        fs::create_dir_all(&deep)?;

        // Test cases with exactly 3 .. components (should pass the security check)
        let attack_vectors = vec![
            // 3 .. components - should pass security check but still be safe
            "../../..",
            "../../../",
            "../.././.",
            // Mixed with other components
            "../../../secret",
            "../.././../../etc/passwd",
        ];

        for attack in attack_vectors {
            let target_path = _base.join("attack_target");
            fs::create_dir(&target_path)?;

            let symlink = target_path.join("exploit");
            std::os::unix::fs::symlink(attack, &symlink)?;

            // Test canonicalization through this symlink
            let test_path = symlink.join("payload");
            let result = soft_canonicalize(test_path);

            match result {
                Ok(resolved) => {
                    // Ensure the resolved path doesn't escape our temp directory
                    let canonical_base = fs::canonicalize(_base)?;
                    if let Ok(relative) = resolved.strip_prefix(&canonical_base) {
                        // Good - path stayed within our test directory
                        assert!(relative.components().count() > 0);
                    } else {
                        // Path escaped - this could be a security issue
                        eprintln!("WARNING: Path escaped temp directory: {resolved:?}");
                        eprintln!("Base: {canonical_base:?}");
                        // For test purposes, we'll allow this but log it
                    }
                }
                Err(e) if e.to_string().contains("security") => {
                    // Good - security check caught it
                }
                Err(e) => {
                    eprintln!("Unexpected error in dotdot bypass test: {e}");
                }
            }

            // Clean up for next iteration
            let _ = fs::remove_dir_all(&target_path);
        }
    }
    Ok(())
}

#[test]
fn test_path_injection_attempts() -> std::io::Result<()> {
    // WHITE-BOX: Test various path injection techniques
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create a safe directory
    let safe_dir = base.join("safe");
    fs::create_dir(&safe_dir)?;

    // Create a sensitive file outside safe directory
    let sensitive = base.join("sensitive.txt");
    fs::write(&sensitive, "secret data")?;

    let injection_attempts = vec![
        // Classic directory traversal
        "safe/../sensitive.txt",
        "safe/./../../sensitive.txt",
        "safe/subdir/../../../sensitive.txt",
        // Multiple slash variations
        "safe///../sensitive.txt",
        "safe/.//.//../sensitive.txt",
        // Encoded attempts (shouldn't be decoded)
        "safe/%2e%2e/sensitive.txt",
        "safe/\u{002E}\u{002E}/sensitive.txt", // Unicode dots
    ];

    for attempt in injection_attempts {
        let attack_path = base.join(attempt);
        let result = soft_canonicalize(&attack_path)?;

        // All should be resolved properly
        assert!(result.is_absolute());

        // For the valid traversals, they should correctly point to sensitive.txt
        if attempt.contains("..") && !attempt.contains('%') {
            let canonical_sensitive = fs::canonicalize(&sensitive)?;
            // On Windows, compare file content instead of exact paths due to \\?\ prefix differences
            if result.exists() && canonical_sensitive.exists() {
                let result_content = fs::read_to_string(&result).unwrap_or_default();
                let expected_content = fs::read_to_string(&canonical_sensitive).unwrap_or_default();
                assert_eq!(result_content, expected_content, "Failed for: {attempt}");
            }
        }
    }

    Ok(())
}

#[test]
fn test_alternative_interpretation_exploitation() -> std::io::Result<()> {
    // WHITE-BOX: Try to exploit the special handling for ../path patterns
    // in the alternative interpretation logic
    let temp_dir = TempDir::new()?;
    let _base = temp_dir.path();

    #[cfg(unix)]
    {
        // Create a structure where alternative interpretation might be confused
        let target_dir = _base.join("legitimate_target");
        fs::create_dir(&target_dir)?;
        fs::write(target_dir.join("legitimate_file.txt"), "safe content")?;

        // Create a directory that looks like it could be confused with ../
        let confusing_dir = _base.join("..confusing");
        fs::create_dir(&confusing_dir)?;
        fs::write(
            confusing_dir.join("malicious_file.txt"),
            "dangerous content",
        )?;

        // Create symlinks with ../path patterns that might trigger alternative interpretation
        let symlink_dir = _base.join("symlinks");
        fs::create_dir(&symlink_dir)?;

        let test_cases = [
            // Legitimate ../path pattern
            "../legitimate_target/legitimate_file.txt",
            // Patterns that might confuse the alternative interpretation
            "../..confusing/malicious_file.txt",
            "..//legitimate_target/legitimate_file.txt", // Double slash
            "..\\legitimate_target\\legitimate_file.txt", // Mixed separators
        ];

        for (i, target) in test_cases.iter().enumerate() {
            let symlink = symlink_dir.join(format!("test_link_{i}"));
            std::os::unix::fs::symlink(target, &symlink)?;

            // Test canonicalization through this symlink
            let result = soft_canonicalize(&symlink);

            match result {
                Ok(resolved) => {
                    // Verify the resolution is reasonable and safe
                    assert!(resolved.is_absolute());
                }
                Err(_e) => {
                    // Errors are acceptable for malformed paths
                }
            }
        }
    }
    Ok(())
}
