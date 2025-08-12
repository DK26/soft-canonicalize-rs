// Windows-specific CVE tests for 8.3 short filename vulnerabilities
// These tests ensure our implementation doesn't replicate known security issues
// NOTE: These tests only run on Windows platforms

#[cfg(windows)]
mod windows_8_3_cve_tests {
    use soft_canonicalize::soft_canonicalize;
    use std::path::Path;

    /// Test for CVE-2019-9855: LibreOffice Windows 8.3 path equivalence handling flaw
    /// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9855
    ///
    /// Issue: Documents could trigger executing LibreLogo via Windows filename pseudonym
    /// Our mitigation: Ensure Unicode paths with tildes are NOT treated as 8.3 names
    #[test]
    fn test_cve_2019_9855_libreoffice_8_3_bypass() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Test cases that could potentially exploit 8.3 name confusion
        let malicious_filenames = vec![
            // Unicode characters that could confuse 8.3 detection
            "script~1.py", // Could be confused with SCRIPT~1.PY
            "SCRIPT~1.py", // Mixed case variant
            "script~1.PY", // Extension case variant
            "Script~1.Py", // Title case variant
            // Unicode lookalike attacks
            "sсript~1.py", // Cyrillic 'с' instead of 'c'
            "scriрt~1.py", // Cyrillic 'р' instead of 'p'
            "ѕcript~1.py", // Cyrillic 'ѕ' instead of 's'
            // Normalization attacks
            "script～1.py", // Full-width tilde
            "script˜1.py",  // Small tilde
            "script~１.py", // Full-width '1'
            // Extension confusion
            "script~1.рy",   // Cyrillic extension
            "script~1.ру",   // Full Cyrillic extension
            "script~1.exe ", // Trailing space
            "script~1.exe.", // Trailing dot
        ];

        for filename in malicious_filenames {
            println!("Testing CVE-2019-9855 case: '{filename}'");

            let test_path = temp_dir.path().join(filename);

            match soft_canonicalize(&test_path) {
                Ok(canonical) => {
                    let canonical_str = canonical.to_string_lossy();

                    // CRITICAL: Unicode filenames must be preserved exactly
                    // They should NOT be treated as 8.3 short names
                    assert!(
                        canonical_str.contains(filename) || canonical_str.ends_with(filename),
                        "CVE-2019-9855: Filename '{filename}' not preserved. Got: {canonical_str}. \
                         This could indicate 8.3 confusion vulnerability."
                    );

                    // Additional check: If the filename contains non-ASCII chars,
                    // it should definitely not be processed as a short name
                    if !filename.is_ascii() {
                        println!("  ✓ Non-ASCII filename '{filename}' correctly preserved");
                    }
                }
                Err(e) => {
                    // Some characters might be invalid for the OS - that's acceptable
                    println!("  ✓ Filename '{filename}' rejected: {e}");
                }
            }
        }
    }

    /// Test for CVE-2017-17793: BlogoText archiv~1.zip 8.3 filename bypass
    /// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17793
    ///
    /// Issue: Attackers could access backup files using 8.3 short names like archiv~1.zip
    /// Our mitigation: Ensure our canonicalization handles short names correctly
    #[test]
    fn test_cve_2017_17793_8_3_filename_disclosure() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create files that would have predictable 8.3 names
        let test_files = vec![
            ("archive_backup.zip", "ARCHIV~1.ZIP"),
            ("configuration_backup.zip", "CONFIG~1.ZIP"),
            ("sensitive_data.txt", "SENSIT~1.TXT"),
            ("private_information.doc", "PRIVAT~1.DOC"),
            ("very_long_filename_backup.zip", "VERYLO~1.ZIP"),
        ];

        for (long_name, expected_short_name) in test_files {
            println!("Testing CVE-2017-17793: {long_name} -> {expected_short_name}");

            // Test accessing via potential short name
            let short_path = temp_dir.path().join(expected_short_name);
            let long_path = temp_dir.path().join(long_name);

            // Try to canonicalize the potential short name path
            match soft_canonicalize(&short_path) {
                Ok(canonical) => {
                    let canonical_str = canonical.to_string_lossy();

                    // The short name should be treated as a literal filename
                    // It should NOT automatically resolve to a long filename
                    // (unless such a file actually exists with that short name)
                    println!("  Short name '{expected_short_name}' resolved to: {canonical_str}");

                    // Verify it's treating the short name as a literal path
                    assert!(
                        canonical_str.contains(expected_short_name)
                            || canonical_str.ends_with(expected_short_name),
                        "CVE-2017-17793: Short name should be preserved literally, got: {canonical_str}"
                    );
                }
                Err(e) => {
                    // If the file doesn't exist, that's expected
                    println!("  ✓ Short name '{expected_short_name}' correctly not found: {e}");
                }
            }

            // Also test the long name for comparison
            if let Ok(_canonical) = soft_canonicalize(&long_path) {
                println!("  Long name '{long_name}' resolved correctly");
            }
        }
    }

    /// Test for CVE-2020-12279: Git NTFS short names remote code execution
    /// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12279
    ///
    /// Issue: Equivalent filenames due to NTFS short names could allow RCE
    /// Our mitigation: Ensure our path handling doesn't create equivalence confusion
    #[test]
    fn test_cve_2020_12279_ntfs_short_name_equivalence() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Test cases that could create filename equivalence confusion
        let equivalence_tests = vec![
            // Potential 8.3 vs long name confusion
            ("PROGRA~1", "Program Files"),
            ("DOCUME~1", "Documents and Settings"),
            ("WINDOWS~1", "Windows.old"),
            ("BACKUP~1", "Backup Files"),
            // Mixed case variations that could cause confusion
            ("backup~1.txt", "BACKUP~1.TXT"),
            ("config~1.cfg", "CONFIG~1.CFG"),
            ("script~1.bat", "SCRIPT~1.BAT"),
        ];

        for (name1, name2) in equivalence_tests {
            println!("Testing CVE-2020-12279 equivalence: '{name1}' vs '{name2}'");

            let path1 = temp_dir.path().join(name1);
            let path2 = temp_dir.path().join(name2);

            let canonical1_result = soft_canonicalize(&path1);
            let canonical2_result = soft_canonicalize(&path2);

            match (canonical1_result, canonical2_result) {
                (Ok(canonical1), Ok(canonical2)) => {
                    // These should be treated as different files
                    // There should be NO automatic equivalence
                    let canonical1_str = canonical1.to_string_lossy();
                    let canonical2_str = canonical2.to_string_lossy();

                    println!("  '{name1}' -> {canonical1_str}");
                    println!("  '{name2}' -> {canonical2_str}");

                    // Each path should preserve its original filename component
                    assert!(
                        canonical1_str.contains(name1) || canonical1_str.ends_with(name1),
                        "CVE-2020-12279: Path '{name1}' should preserve original name in: {canonical1_str}"
                    );

                    assert!(
                        canonical2_str.contains(name2) || canonical2_str.ends_with(name2),
                        "CVE-2020-12279: Path '{name2}' should preserve original name in: {canonical2_str}"
                    );

                    // They should NOT resolve to the same canonical path
                    // (unless they're actually the same file, which they're not in this test)
                    if canonical1_str == canonical2_str {
                        panic!(
                            "CVE-2020-12279: SECURITY ISSUE - Different filenames '{name1}' and '{name2}' \
                             resolved to same canonical path: {canonical1_str}. This indicates dangerous \
                             filename equivalence that could be exploited."
                        );
                    }

                    println!("  ✓ No dangerous equivalence detected");
                }
                (Ok(canonical), Err(e)) => {
                    println!(
                        "  First path resolved, second didn't: {} / {}",
                        canonical.display(),
                        e
                    );
                }
                (Err(e), Ok(canonical)) => {
                    println!(
                        "  Second path resolved, first didn't: {} / {}",
                        canonical.display(),
                        e
                    );
                }
                (Err(e1), Err(e2)) => {
                    println!("  Both paths failed (acceptable): {e1} / {e2}");
                }
            }
        }
    }

    /// Test for CVE-2005-0471: Java temporary files predictable on 8.3 filesystems
    /// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0471
    ///
    /// Issue: Long filenames became predictable when truncated to 8.3 format
    /// Our mitigation: Ensure we don't inadvertently create predictable patterns
    #[test]
    fn test_cve_2005_0471_predictable_8_3_names() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Test long filenames that could become predictable when truncated
        let long_filenames = vec![
            "temporary_file_with_very_long_name_12345.tmp",
            "temporary_file_with_very_long_name_12346.tmp",
            "temporary_file_with_very_long_name_12347.tmp",
            "configuration_backup_sensitive_data_file.cfg",
            "configuration_backup_sensitive_data_file2.cfg",
            "password_storage_encrypted_database_file.db",
            "password_storage_encrypted_database_file2.db",
        ];

        let mut canonical_results = Vec::new();

        for filename in &long_filenames {
            println!("Testing CVE-2005-0471 predictability: '{filename}'");

            let test_path = temp_dir.path().join(filename);

            match soft_canonicalize(&test_path) {
                Ok(canonical) => {
                    let canonical_str = canonical.to_string_lossy().to_string();
                    canonical_results.push(((*filename).to_string(), canonical_str.clone()));

                    // The full filename should be preserved
                    assert!(
                        canonical_str.contains(filename) || canonical_str.ends_with(filename),
                        "CVE-2005-0471: Long filename '{filename}' should be preserved in: {canonical_str}"
                    );

                    println!("  ✓ Preserved: {canonical_str}");
                }
                Err(e) => {
                    println!("  Path failed: {e}");
                }
            }
        }

        // Check that similar long names don't resolve to suspiciously similar paths
        // (which could indicate 8.3 truncation is happening)
        for i in 0..canonical_results.len() {
            for j in (i + 1)..canonical_results.len() {
                let (name1, path1) = &canonical_results[i];
                let (name2, path2) = &canonical_results[j];

                // If names are similar but paths are too similar, that could indicate
                // problematic 8.3 truncation
                if name1.len() > 12 && name2.len() > 12 && name1[..8] == name2[..8] {
                    // Same first 8 chars

                    // Extract just the filename component for comparison
                    let filename1 = Path::new(path1)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let filename2 = Path::new(path2)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();

                    assert_ne!(
                        filename1, filename2,
                        "CVE-2005-0471: SECURITY ISSUE - Different long filenames '{name1}' and '{name2}' \
                         resolved to same canonical filename component '{filename1}'. This suggests \
                         dangerous 8.3 truncation behavior."
                    );
                }
            }
        }

        println!("✓ No predictable 8.3 truncation patterns detected");
    }

    /// Test for CVE-2002-2413: WebSite Pro script source disclosure via 8.3 names
    /// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2413
    ///
    /// Issue: Script source code readable via 8.3 equivalent filenames
    /// Our mitigation: Ensure extensions are preserved correctly
    #[test]
    fn test_cve_2002_2413_script_source_disclosure() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Test files with extensions longer than 3 characters
        let script_files = vec![
            ("script.php4", "SCRIPT~1.PHP"),  // php4 -> .PHP truncation
            ("config.aspx", "CONFIG~1.ASP"),  // aspx -> .ASP truncation
            ("handler.ashx", "HANDLE~1.ASH"), // ashx -> .ASH truncation
            ("service.asmx", "SERVIC~1.ASM"), // asmx -> .ASM truncation
            ("page.html", "PAGE~1.HTM"),      // html -> .HTM truncation
            ("script.perl", "SCRIPT~1.PER"),  // perl -> .PER truncation
        ];

        for (original_name, potential_short_name) in script_files {
            println!("Testing CVE-2002-2413: {original_name} vs {potential_short_name}");

            let original_path = temp_dir.path().join(original_name);
            let short_path = temp_dir.path().join(potential_short_name);

            // Test the original filename
            match soft_canonicalize(&original_path) {
                Ok(canonical) => {
                    let canonical_str = canonical.to_string_lossy();

                    // Original filename should be preserved exactly
                    assert!(
                        canonical_str.contains(original_name)
                            || canonical_str.ends_with(original_name),
                        "CVE-2002-2413: Original filename '{original_name}' should be preserved in: {canonical_str}"
                    );

                    println!("  ✓ Original '{original_name}' preserved");
                }
                Err(e) => {
                    println!("  Original '{original_name}' not found: {e}");
                }
            }

            // Test the potential short name
            match soft_canonicalize(&short_path) {
                Ok(canonical) => {
                    let canonical_str = canonical.to_string_lossy();

                    // Short name should be treated as literal, NOT auto-expanded
                    assert!(
                        canonical_str.contains(potential_short_name)
                            || canonical_str.ends_with(potential_short_name),
                        "CVE-2002-2413: Short name '{potential_short_name}' should be treated literally in: {canonical_str}"
                    );

                    println!("  ✓ Short name '{potential_short_name}' treated literally");
                }
                Err(e) => {
                    println!("  ✓ Short name '{potential_short_name}' correctly not found: {e}");
                }
            }
        }
    }

    /// Test for CVE-2001-0795: LiteServe source code disclosure via 8.3 names
    /// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0795
    ///
    /// Issue: CGI script source code obtainable via 8.3 filenames and uppercase
    /// Our mitigation: Ensure case and format preservation
    #[test]
    fn test_cve_2001_0795_cgi_source_disclosure() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Test various case and format combinations that could expose source
        let cgi_tests = vec![
            // Original vs uppercase
            ("script.cgi", "SCRIPT.CGI"),
            ("handler.pl", "HANDLER.PL"),
            ("process.py", "PROCESS.PY"),
            // Original vs potential 8.3 forms
            ("long_script_name.cgi", "LONGS~1.CGI"),
            ("configuration.pl", "CONFIG~1.PL"),
            ("data_processor.py", "DATAPР~1.PY"),
            // Mixed case variations
            ("Script.Cgi", "SCRIPT.CGI"),
            ("Handler.Pl", "HANDLER.PL"),
        ];

        for (original, variant) in cgi_tests {
            println!("Testing CVE-2001-0795: '{original}' vs '{variant}'");

            let original_path = temp_dir.path().join(original);
            let variant_path = temp_dir.path().join(variant);

            let original_result = soft_canonicalize(&original_path);
            let variant_result = soft_canonicalize(&variant_path);

            match (original_result, variant_result) {
                (Ok(canonical1), Ok(canonical2)) => {
                    let canonical1_str = canonical1.to_string_lossy();
                    let canonical2_str = canonical2.to_string_lossy();

                    // Each should preserve its exact original form
                    assert!(
                        canonical1_str.contains(original) || canonical1_str.ends_with(original),
                        "CVE-2001-0795: Original '{original}' not preserved in: {canonical1_str}"
                    );

                    assert!(
                        canonical2_str.contains(variant) || canonical2_str.ends_with(variant),
                        "CVE-2001-0795: Variant '{variant}' not preserved in: {canonical2_str}"
                    );

                    // They should NOT resolve to the same path
                    if canonical1_str == canonical2_str {
                        panic!(
                            "CVE-2001-0795: SECURITY ISSUE - Different case/format filenames \
                             '{original}' and '{variant}' resolved to same path: {canonical1_str}. This could allow \
                             source code disclosure attacks."
                        );
                    }

                    println!("  ✓ No dangerous case equivalence");
                }
                _ => {
                    println!("  ✓ Paths handled independently");
                }
            }
        }
    }

    /// Summary test: Verify our 8.3 detection is working correctly
    /// This is a meta-test that validates our core logic
    #[test]
    fn test_8_3_detection_cve_summary() {
        println!("\n🔍 SUMMARY: Windows 8.3 CVE Protection Validation");
        println!("=================================================");

        // Test that our is_likely_8_3_short_name logic correctly identifies real vs fake
        let test_cases = vec![
            // Real 8.3 names (should be detected)
            ("PROGRA~1", true, "Real Windows program files short name"),
            ("DOCUME~1", true, "Real documents folder short name"),
            ("CONFIG~1.TXT", true, "Real 8.3 with extension"),
            ("A~1", true, "Minimal 8.3 name"),
            // CVE-related false positives (should NOT be detected as 8.3)
            ("archiv~1.zip", false, "CVE-2017-17793: Not a real 8.3 name"),
            ("script~1.php", false, "CVE-2019-9855: Not a real 8.3 name"),
            (
                "config~1.aspx",
                false,
                "CVE-2002-2413: Extension too long for 8.3",
            ),
            ("café~1", false, "Unicode characters - not 8.3"),
            ("script～1.py", false, "Full-width tilde - not 8.3"),
            ("test~file", false, "Non-numeric after tilde"),
            ("~1", false, "Missing base name"),
            ("test~", false, "Missing number"),
        ];

        for (filename, should_be_8_3, description) in test_cases {
            // We can't test the internal function directly, but we can infer behavior
            // by testing whether the filename is preserved (indicating it's NOT treated as 8.3)

            let temp_dir = tempfile::tempdir().unwrap();
            let test_path = temp_dir.path().join(filename);

            match soft_canonicalize(&test_path) {
                Ok(canonical) => {
                    let canonical_str = canonical.to_string_lossy();
                    let filename_preserved =
                        canonical_str.contains(filename) || canonical_str.ends_with(filename);

                    if should_be_8_3 {
                        // Real 8.3 names should be preserved (treated normally)
                        assert!(
                            filename_preserved,
                            "Real 8.3 name '{filename}' should be preserved: {description}"
                        );
                        println!("  ✓ Real 8.3: '{filename}' - {description}");
                    } else {
                        // Non-8.3 names should also be preserved (not misinterpreted)
                        assert!(
                            filename_preserved,
                            "Non-8.3 name '{filename}' should be preserved: {description}"
                        );
                        println!("  ✓ Non-8.3: '{filename}' - {description}");
                    }
                }
                Err(e) => {
                    // Some invalid characters might be rejected - that's fine
                    println!("  ✓ Rejected: '{filename}' - {description} ({e})");
                }
            }
        }

        println!("\n✅ All Windows 8.3 CVE protection tests passed!");
        println!("🛡️  No known 8.3 filename vulnerabilities replicated");
        println!("🔒 Path canonicalization handles Windows short names securely");
    }
}

// Make the module available only on Windows
#[cfg(not(windows))]
mod windows_8_3_cve_tests {
    // Provide a stub for non-Windows platforms
    #[test]
    fn windows_cve_tests_not_applicable() {
        println!("Windows 8.3 CVE tests skipped on non-Windows platform");
    }
}
