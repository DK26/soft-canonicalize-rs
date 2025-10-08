//! Black-box security tests for soft_canonicalize
//!
//! These tests treat soft_canonicalize as a black box and try to break it
//! through the public API without knowledge of internal implementation.
//! Focus is on discovering vulnerabilities through external behavior.

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_api_fuzzing_with_malformed_inputs() -> std::io::Result<()> {
    // BLACK-BOX: Fuzz the API with various malformed inputs
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Very long strings
    let very_long_string = "a".repeat(10000);
    let long_component_path = format!("{}/file.txt", "long_component_name".repeat(100));

    let malformed_inputs = vec![
        // Empty and whitespace
        "",
        " ",
        "\t",
        "\n",
        "\r\n",
        // Special characters
        "con",  // Windows reserved name
        "aux",  // Windows reserved name
        "nul",  // Windows reserved name
        "prn",  // Windows reserved name
        "com1", // Windows reserved name
        "lpt1", // Windows reserved name
        // Path traversal variations
        "..",
        "...",
        "../..",
        "../../..",
        "./././.",
        "../../../../../../../../../../../etc/passwd",
        // Unusual separators and encoding
        "test\\path/mixed\\separators",
        "test//double//slash",
        "test///triple///slash",
        // Special Unicode
        "\u{FEFF}bom_at_start.txt",     // BOM
        "file\u{200B}invisible.txt",    // Zero-width space
        "file\u{202E}rtl_override.txt", // Right-to-left override
        "test\u{0000}null.txt",         // Embedded null (might be filtered)
        // Long strings
        &very_long_string,
        &long_component_path,
    ];

    for input in malformed_inputs {
        let test_path = if input.is_empty() {
            PathBuf::new()
        } else {
            base.join(input)
        };

        let result = soft_canonicalize(&test_path);

        // Function should either succeed or fail gracefully
        match result {
            Ok(canonical) => {
                // If it succeeds, result should be well-formed
                assert!(canonical.is_absolute() || input.is_empty());
                println!("✓ Accepted input: {input:?} -> {canonical:?}");
            }
            Err(e) => {
                // If it fails, should be with appropriate error
                println!("✓ Rejected input: {input:?} -> {e}");
                assert!(
                    e.kind() == std::io::ErrorKind::InvalidInput
                        || e.kind() == std::io::ErrorKind::NotFound
                        || e.kind() == std::io::ErrorKind::PermissionDenied
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_directory_traversal_attack_vectors() -> std::io::Result<()> {
    // BLACK-BOX: Test various directory traversal attack patterns
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create a "secure" directory and a sensitive file outside it
    let secure_dir = base.join("secure");
    fs::create_dir(&secure_dir)?;

    let sensitive_file = base.join("sensitive.txt");
    fs::write(&sensitive_file, "SECRET DATA")?;

    let overlong_path = format!("{}/../sensitive.txt", "subdir/".repeat(100));

    let traversal_attacks = vec![
        // Basic traversal
        "../sensitive.txt",
        "secure/../sensitive.txt",
        "secure/../../sensitive.txt",
        // URL encoding (should not be decoded)
        "%2e%2e/sensitive.txt",
        "%2e%2e%2fsensitive.txt",
        "secure/%2e%2e/sensitive.txt",
        // Double encoding
        "%252e%252e/sensitive.txt",
        // Unicode variations
        "\u{002E}\u{002E}/sensitive.txt", // Unicode dots
        "\u{FF0E}\u{FF0E}/sensitive.txt", // Fullwidth dots
        // Mixed case (on case-insensitive systems)
        "../SENSITIVE.TXT",
        "../Sensitive.Txt",
        // Alternate separators
        "..\\sensitive.txt",   // Backslash
        "..//sensitive.txt",   // Double slash
        "../\\/sensitive.txt", // Mixed separators
        // Null byte injection attempts
        "../sensitive.txt%00",
        "../sensitive.txt\0hidden",
        // Overlong paths
        &overlong_path,
        // Combination attacks
        "secure/.././..//sensitive.txt",
        "secure/%2e%2e/./sensitive.txt",
    ];

    for attack in traversal_attacks {
        let attack_path = base.join(attack);
        let result = soft_canonicalize(&attack_path);

        match result {
            Ok(canonical) => {
                println!("Attack resolved: {} -> {}", attack, canonical.display());

                // Verify it correctly points to sensitive file for legitimate traversals
                if attack.contains("..") && !attack.contains('%') && !attack.contains('\0') {
                    // Should resolve to the actual sensitive file
                    if attack.ends_with("sensitive.txt") {
                        let expected = fs::canonicalize(&sensitive_file)?;
                        // On Windows, paths might have different prefixes (\\?\ vs normal)
                        // so we compare the file contents instead of exact paths
                        if canonical.exists() && expected.exists() {
                            let canonical_content =
                                fs::read_to_string(&canonical).unwrap_or_default();
                            let expected_content =
                                fs::read_to_string(&expected).unwrap_or_default();
                            assert_eq!(
                                canonical_content, expected_content,
                                "Attack '{attack}' should resolve to sensitive file content"
                            );
                        }
                    }
                }

                // Result should always be absolute
                assert!(
                    canonical.is_absolute(),
                    "Result should be absolute for: {attack}"
                );
            }
            Err(e) => {
                println!("Attack rejected: {attack} -> {e}");
                // Rejection is acceptable for malformed inputs
            }
        }
    }

    Ok(())
}

#[test]
fn test_symlink_escape_attempts() -> std::io::Result<()> {
    // BLACK-BOX: Test various symlink-based escape attempts

    #[cfg(unix)]
    {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path();

        // Create a jail directory
        let jail = base.join("jail");
        fs::create_dir(&jail)?;

        // Create sensitive area outside jail
        let secrets = base.join("secrets");
        fs::create_dir(&secrets)?;
        fs::write(secrets.join("secret.txt"), "TOP SECRET")?;

        // Create various symlink escape attempts
        let traversal_target = PathBuf::from("../secrets");
        let escape_attempts = vec![
            // Direct symlink to outside
            ("direct_escape", &secrets),
            // Symlink with traversal
            ("traversal_escape", &traversal_target),
            // Nested directory symlink
            ("nested", &secrets),
        ];

        for (link_name, target) in escape_attempts {
            let link_path = jail.join(link_name);

            // Try to create symlink (might fail on some systems)
            let symlink_result = std::os::unix::fs::symlink(target, &link_path);

            if symlink_result.is_ok() {
                // Test accessing file through symlink
                let attack_path = link_path.join("secret.txt");
                let result = soft_canonicalize(&attack_path);

                match result {
                    Ok(canonical) => {
                        println!(
                            "Symlink escape succeeded: {} -> {}",
                            attack_path.display(),
                            canonical.display()
                        );

                        // Verify it points outside jail (enabling detection)
                        let canonical_jail = fs::canonicalize(&jail)?;

                        #[cfg(not(feature = "dunce"))]
                        let escapes_jail = !canonical.starts_with(&canonical_jail);

                        #[cfg(feature = "dunce")]
                        let escapes_jail = {
                            let canonical_str = canonical.to_string_lossy();
                            let jail_str = canonical_jail.to_string_lossy();
                            let jail_simplified = jail_str.trim_start_matches(r"\\?\");
                            !canonical_str.starts_with(jail_simplified)
                        };

                        if escapes_jail {
                            println!(
                                "⚠️ Symlink escape detected: {} escapes {}",
                                canonical.display(),
                                canonical_jail.display()
                            );
                        }

                        // Should resolve to actual target location
                        let expected_target = secrets.join("secret.txt");
                        if expected_target.exists() {
                            let canonical_target = fs::canonicalize(&expected_target)?;

                            #[cfg(not(feature = "dunce"))]
                            {
                                assert_eq!(canonical, canonical_target);
                            }
                            #[cfg(feature = "dunce")]
                            {
                                let canonical_str = canonical.to_string_lossy();
                                let target_str = canonical_target.to_string_lossy();
                                assert!(
                                    !canonical_str.starts_with(r"\\?\"),
                                    "dunce should simplify"
                                );
                                assert!(target_str.starts_with(r"\\?\"), "std returns UNC");
                                assert_eq!(
                                    canonical_str.as_ref(),
                                    target_str.trim_start_matches(r"\\?\")
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "Symlink escape rejected: {} -> {}",
                            attack_path.display(),
                            e
                        );
                    }
                }

                // Test with non-existing file through symlink
                let nonexist_attack = link_path.join("nonexistent.txt");
                let result2 = soft_canonicalize(&nonexist_attack);

                match result2 {
                    Ok(canonical) => {
                        // Should still enable escape detection
                        let canonical_jail = fs::canonicalize(&jail)?;

                        #[cfg(not(feature = "dunce"))]
                        {
                            assert!(
                                !canonical.starts_with(&canonical_jail),
                                "Non-existing file through symlink should enable escape detection"
                            );
                        }
                        #[cfg(feature = "dunce")]
                        {
                            let canonical_str = canonical.to_string_lossy();
                            let jail_str = canonical_jail.to_string_lossy();
                            let jail_simplified = jail_str.trim_start_matches(r"\\?\");
                            assert!(
                                !canonical_str.starts_with(jail_simplified),
                                "Non-existing file through symlink should enable escape detection"
                            );
                        }
                        println!("✓ Non-existing symlink escape properly resolved for detection");
                    }
                    Err(e) => {
                        println!("Non-existing symlink attack rejected: {e}");
                    }
                }
            } else {
                println!(
                    "Symlink creation failed for {}: {}",
                    link_name,
                    symlink_result.unwrap_err()
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_performance_attack_vectors() -> std::io::Result<()> {
    // BLACK-BOX: Test inputs designed to cause performance issues
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Test 1: Very deep directory structure
    let deep_path = (0..1000).fold(base.to_path_buf(), |acc, i| {
        acc.join(format!("level_{i:04}"))
    });
    let deep_file = deep_path.join("deep_file.txt");

    let start = std::time::Instant::now();
    let result = soft_canonicalize(&deep_file);
    let duration = start.elapsed();

    println!("Deep path test: {:?} in {:?}", result.is_ok(), duration);
    assert!(
        duration.as_secs() < 5,
        "Should not take more than 5 seconds"
    );

    // Test 2: Path with many .. components
    let mut traversal_path = base.to_path_buf();
    for _ in 0..500 {
        traversal_path.push("..");
    }
    traversal_path.push("final.txt");

    let start = std::time::Instant::now();
    let result = soft_canonicalize(&traversal_path);
    let duration = start.elapsed();

    println!(
        "Traversal path test: {:?} in {:?}",
        result.is_ok(),
        duration
    );
    assert!(
        duration.as_secs() < 5,
        "Should not take more than 5 seconds"
    );

    // Test 3: Path with alternating patterns
    let mut pattern_path = base.to_path_buf();
    for i in 0..200 {
        if i % 2 == 0 {
            pattern_path.push("forward");
        } else {
            pattern_path.push("..");
        }
    }
    pattern_path.push("final.txt");

    let start = std::time::Instant::now();
    let result = soft_canonicalize(&pattern_path);
    let duration = start.elapsed();

    println!("Pattern path test: {:?} in {:?}", result.is_ok(), duration);
    assert!(
        duration.as_secs() < 5,
        "Should not take more than 5 seconds"
    );

    Ok(())
}

#[test]
fn test_race_condition_simulations() -> std::io::Result<()> {
    // BLACK-BOX: Simulate race conditions during path resolution
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create initial structure
    let target_dir = base.join("target");
    fs::create_dir(target_dir)?;

    #[cfg(unix)]
    {
        let symlink = base.join("racing_link");
        std::os::unix::fs::symlink(base.join("target"), &symlink)?;

        // Spawn thread to modify filesystem during resolution
        let symlink_clone = symlink.clone();
        let base_clone = base.to_path_buf();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1));

            // Try to replace symlink during resolution
            let _ = fs::remove_file(&symlink_clone);
            let _ = std::os::unix::fs::symlink(base_clone.join("other"), &symlink_clone);

            std::thread::sleep(std::time::Duration::from_millis(1));

            // Create/delete directories
            let _ = fs::create_dir(base_clone.join("other"));
            let _ = fs::remove_dir(base_clone.join("other"));
        });

        // Try to canonicalize during modifications
        for i in 0..10 {
            let test_path = symlink.join(format!("file_{i}.txt"));
            let result = soft_canonicalize(&test_path);

            // Should handle race conditions gracefully
            match result {
                Ok(canonical) => {
                    assert!(canonical.is_absolute());
                    println!("Race test {}: OK -> {}", i, canonical.display());
                }
                Err(e) => {
                    println!("Race test {i}: Error -> {e}");
                    // Errors are acceptable due to race conditions
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        handle.join().unwrap();
    }

    Ok(())
}

#[test]
fn test_case_sensitivity_bypass_attempts() -> std::io::Result<()> {
    // BLACK-BOX: Test case sensitivity bypass attempts
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Create files with different cases
    let sensitive_file = base.join("SECRET.txt");
    fs::write(&sensitive_file, "sensitive data")?;

    let case_variants = vec![
        "SECRET.txt",
        "secret.txt",
        "Secret.txt",
        "SECRET.TXT",
        "secret.TXT",
        "SeCrEt.TxT",
    ];

    for variant in case_variants {
        let test_path = base.join(variant);
        let result = soft_canonicalize(&test_path);

        match result {
            Ok(canonical) => {
                println!("Case variant '{}' -> {}", variant, canonical.display());

                // On case-insensitive systems, should resolve to actual file
                // On case-sensitive systems, might resolve to non-existing path
                assert!(canonical.is_absolute());

                if canonical.exists() {
                    // If it exists, verify it's the expected file
                    let content = fs::read_to_string(&canonical)?;
                    assert_eq!(content, "sensitive data");
                }
            }
            Err(e) => {
                println!("Case variant '{variant}' rejected: {e}");
            }
        }
    }

    Ok(())
}

#[test]
fn test_filesystem_boundary_crossing() -> std::io::Result<()> {
    // BLACK-BOX: Test behavior when crossing filesystem boundaries
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    let passwd_path = format!("{}/../../../etc/passwd", base.display());
    let sam_path = format!("{}/../../../windows/system32/config/sam", base.display());

    // Test paths that might cross filesystem boundaries
    let boundary_tests = vec![
        // System directories (might be on different filesystems)
        "/tmp/test.txt",
        "/var/test.txt",
        "/home/test.txt",
        // Windows system paths
        "C:\\temp\\test.txt",
        "D:\\test.txt",
        // UNC paths (Windows)
        "\\\\server\\share\\test.txt",
        // Relative paths that might escape temp directory
        &passwd_path,
        &sam_path,
    ];

    for test_path in boundary_tests {
        let path = Path::new(test_path);

        // Skip if path is not valid for current platform
        if (cfg!(windows) && test_path.starts_with('/')) || (cfg!(unix) && test_path.contains('\\'))
        {
            continue;
        }

        let result = soft_canonicalize(path);

        match result {
            Ok(canonical) => {
                println!("Boundary test '{}' -> {}", test_path, canonical.display());
                assert!(canonical.is_absolute());

                // Should not crash or cause undefined behavior
                println!("✓ Boundary crossing handled safely");
            }
            Err(e) => {
                println!("Boundary test '{test_path}' rejected: {e}");
                // Rejection is often expected for system paths
            }
        }
    }

    Ok(())
}

#[test]
fn test_api_contract_violations() -> std::io::Result<()> {
    // BLACK-BOX: Test edge cases in API contract
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Test 1: Empty path
    let empty_result = soft_canonicalize("");
    assert!(empty_result.is_err(), "Empty path should be rejected");

    // Test 2: Root paths
    let root_variants = if cfg!(windows) {
        vec!["C:\\", "D:\\", "\\", "C:/"]
    } else {
        vec!["/", "//", "///"]
    };

    for root in root_variants {
        if let Ok(canonical) = soft_canonicalize(root) {
            assert!(
                canonical.is_absolute(),
                "Root should canonicalize to absolute path"
            );
            println!("Root '{}' -> {}", root, canonical.display());
        }
    }

    // Test 3: Current directory references
    let current_refs = vec![".", "./", "./.", "././.", ".///."];

    for current_ref in current_refs {
        let test_path = base.join(current_ref);
        if let Ok(canonical) = soft_canonicalize(&test_path) {
            assert!(canonical.is_absolute());
            // Should resolve to somewhere reasonable
            println!("Current ref '{}' -> {}", current_ref, canonical.display());
        }
    }

    // Test 4: Parent directory references at root
    let parent_at_root = if cfg!(windows) {
        vec!["C:\\..\\test.txt", "C:\\..\\..\\test.txt"]
    } else {
        vec!["/../test.txt", "/../../test.txt", "/../../../test.txt"]
    };

    for parent_path in parent_at_root {
        if let Ok(canonical) = soft_canonicalize(parent_path) {
            assert!(canonical.is_absolute());
            // Should not go above root
            println!(
                "Parent at root '{}' -> {}",
                parent_path,
                canonical.display()
            );
        }
    }

    Ok(())
}

#[test]
fn test_stress_testing_patterns() -> std::io::Result<()> {
    // BLACK-BOX: Stress test with various problematic patterns
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path();

    // Pattern 1: Deeply nested dots
    let dot_pattern = (0..100).map(|_| ".").collect::<Vec<_>>().join("/");
    let dot_path = base.join(format!("{dot_pattern}/test.txt"));
    let _ = soft_canonicalize(&dot_path); // Should not crash

    // Pattern 2: Mixed separator mayhem
    let separator_chaos = "test\\//\\/..///\\./test.txt";
    let chaos_path = base.join(separator_chaos);
    let _ = soft_canonicalize(&chaos_path); // Should not crash

    // Pattern 3: Unicode stress test
    let unicode_stress = "\u{1F4A9}\u{200B}\u{FEFF}\u{202E}test\u{0000}file.txt";
    let unicode_path = base.join(unicode_stress);
    let _ = soft_canonicalize(&unicode_path); // Should not crash

    // Pattern 4: Alternating valid/invalid components
    let mut alternating = base.to_path_buf();
    for i in 0..50 {
        if i % 2 == 0 {
            alternating.push("valid");
        } else {
            alternating.push("../invalid");
        }
    }
    alternating.push("final.txt");
    let _ = soft_canonicalize(&alternating); // Should not crash

    println!("✓ All stress test patterns completed without crashing");
    Ok(())
}
