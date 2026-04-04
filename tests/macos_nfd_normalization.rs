#![cfg(target_os = "macos")]
//! macOS-Specific Security Tests — Part 1: Unicode NFD Normalization and Case-Insensitive Filesystem
//!
//! Covers:
//! 1. Unicode NFD normalization (APFS/HFS+ auto-decompose filenames)
//! 2. Case-insensitive but case-preserving filesystem (APFS default)

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io;
use std::path::Path;
use tempfile::TempDir;

// ─── 1. Unicode NFD Normalization (APFS/HFS+) ──────────────────────────────

mod nfd_normalization {
    use super::*;

    #[test]
    fn nfc_filename_stored_as_nfd() -> io::Result<()> {
        // macOS APFS normalizes filenames to NFD. A file created with NFC "é"
        // (U+00E9) is stored as NFD "e\u{0301}" (e + combining acute accent).
        // soft_canonicalize must return exactly what std::fs::canonicalize does.
        let tmp = TempDir::new()?;

        // Create file with NFC precomposed character
        let nfc_name = "caf\u{00E9}.txt"; // café with precomposed é
        let file = tmp.path().join(nfc_name);
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(
            result, expected,
            "NFC filename must match std::fs::canonicalize"
        );
        Ok(())
    }

    #[test]
    fn nfd_filename_resolves_same() -> io::Result<()> {
        // Create with NFC, access with explicit NFD — both should resolve identically
        let tmp = TempDir::new()?;

        let nfc_name = "caf\u{00E9}.txt";
        let nfd_name = "cafe\u{0301}.txt";

        let file = tmp.path().join(nfc_name);
        fs::write(&file, b"data")?;

        let result_nfc = soft_canonicalize(tmp.path().join(nfc_name))?;
        let result_nfd = soft_canonicalize(tmp.path().join(nfd_name))?;
        assert_eq!(
            result_nfc, result_nfd,
            "NFC and NFD must resolve to the same canonical path"
        );

        // Both must also match std::fs::canonicalize
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result_nfc, expected);
        Ok(())
    }

    #[test]
    fn nfd_directory_with_nonexisting_child() -> io::Result<()> {
        // Create a directory with NFC name, access via NFD, add non-existing child
        let tmp = TempDir::new()?;

        let nfc_dir = "r\u{00E9}pertoire"; // répertoire
        let nfd_dir = "re\u{0301}pertoire";

        let dir = tmp.path().join(nfc_dir);
        fs::create_dir(&dir)?;

        let path_nfc = tmp.path().join(nfc_dir).join("nonexist.txt");
        let path_nfd = tmp.path().join(nfd_dir).join("nonexist.txt");

        let result_nfc = soft_canonicalize(&path_nfc)?;
        let result_nfd = soft_canonicalize(&path_nfd)?;

        assert_eq!(
            result_nfc, result_nfd,
            "NFD/NFC directory with non-existing child must resolve identically"
        );

        // The existing directory should be canonicalized
        let canonical_dir = std::fs::canonicalize(&dir)?;
        assert!(
            result_nfc.starts_with(&canonical_dir),
            "Result should start with the canonical directory: {result_nfc:?}"
        );
        Ok(())
    }

    #[test]
    fn combining_diacriticals_multiple() -> io::Result<()> {
        // More complex Unicode: multiple combining marks
        let tmp = TempDir::new()?;

        // ñ can be NFC U+00F1 or NFD n + U+0303
        let nfc_name = "\u{00F1}ovel.txt";
        let nfd_name = "n\u{0303}ovel.txt";

        let file = tmp.path().join(nfc_name);
        fs::write(&file, b"data")?;

        let result_nfc = soft_canonicalize(tmp.path().join(nfc_name))?;
        let result_nfd = soft_canonicalize(tmp.path().join(nfd_name))?;
        assert_eq!(result_nfc, result_nfd, "ñ NFC/NFD must resolve identically");
        Ok(())
    }

    #[test]
    fn korean_jamo_normalization() -> io::Result<()> {
        // Korean Hangul has complex NFC/NFD behavior with Jamo decomposition
        let tmp = TempDir::new()?;

        // 한 = U+D55C (NFC) = ㅎ+ㅏ+ㄴ (U+1112 U+1161 U+11AB, NFD)
        let nfc_name = "\u{D55C}\u{AE00}.txt"; // 한글.txt
        let nfd_name = "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}.txt";

        let file = tmp.path().join(nfc_name);
        fs::write(&file, b"data")?;

        let result_nfc = soft_canonicalize(tmp.path().join(nfc_name))?;
        let result_nfd = soft_canonicalize(tmp.path().join(nfd_name))?;
        assert_eq!(
            result_nfc, result_nfd,
            "Korean Hangul NFC/NFD must resolve identically on macOS"
        );
        Ok(())
    }

    #[test]
    fn umlaut_normalization() -> io::Result<()> {
        // German umlauts: ü = U+00FC (NFC) = u + U+0308 (NFD)
        let tmp = TempDir::new()?;

        let nfc_name = "\u{00FC}bung.txt"; // übung.txt
        let nfd_name = "u\u{0308}bung.txt";

        let file = tmp.path().join(nfc_name);
        fs::write(&file, b"data")?;

        let result_nfc = soft_canonicalize(tmp.path().join(nfc_name))?;
        let result_nfd = soft_canonicalize(tmp.path().join(nfd_name))?;
        assert_eq!(result_nfc, result_nfd);
        assert_eq!(result_nfc, std::fs::canonicalize(&file)?);
        Ok(())
    }

    #[test]
    fn symlink_with_nfd_target() -> io::Result<()> {
        // Symlink pointing to a file with NFC name, accessed via NFD
        let tmp = TempDir::new()?;

        let nfc_name = "caf\u{00E9}.txt";
        let file = tmp.path().join(nfc_name);
        fs::write(&file, b"data")?;

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&file, &link)?;

        let result = soft_canonicalize(&link)?;
        let expected = std::fs::canonicalize(&link)?;
        assert_eq!(
            result, expected,
            "Symlink to NFC file must resolve correctly"
        );
        Ok(())
    }

    #[test]
    fn nfd_in_deep_path() -> io::Result<()> {
        // Multiple NFD-normalized directory components in a deep path
        let tmp = TempDir::new()?;

        // Create deep path with accented directory names
        let d1 = tmp.path().join("caf\u{00E9}");
        let d2 = d1.join("r\u{00E9}sum\u{00E9}");
        fs::create_dir_all(&d2)?;
        fs::write(d2.join("file.txt"), b"data")?;

        // Access via NFD spellings
        let nfd_path = tmp
            .path()
            .join("cafe\u{0301}")
            .join("re\u{0301}sume\u{0301}")
            .join("file.txt");

        let result = soft_canonicalize(&nfd_path)?;
        let expected = std::fs::canonicalize(d2.join("file.txt"))?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn nfd_nonexisting_suffix_preserves_input_form() -> io::Result<()> {
        // When the non-existing suffix contains NFD characters, they should be
        // preserved as-is (the library doesn't normalize non-existing components)
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("base");
        fs::create_dir(&dir)?;

        // Non-existing child with NFD characters
        let nfd_child = "cafe\u{0301}_new.txt";
        let path = dir.join(nfd_child);

        let result = soft_canonicalize(&path)?;
        let canonical_dir = std::fs::canonicalize(&dir)?;

        // The result should use the canonical directory + the non-existing suffix as-is
        assert!(result.starts_with(&canonical_dir));
        assert!(
            result.to_string_lossy().contains("caf"),
            "Result should contain the non-existing NFD suffix"
        );
        Ok(())
    }
}

// ─── 2. Case-Insensitive Filesystem ─────────────────────────────────────────

mod case_insensitive {
    use super::*;

    #[test]
    fn case_mismatch_resolves_to_ondisk_case() -> io::Result<()> {
        // APFS is case-insensitive-but-case-preserving by default.
        // soft_canonicalize must return the on-disk casing.
        let tmp = TempDir::new()?;
        let file = tmp.path().join("MyFile.TXT");
        fs::write(&file, b"data")?;

        // Access with different casing
        let lower = tmp.path().join("myfile.txt");
        let upper = tmp.path().join("MYFILE.TXT");
        let mixed = tmp.path().join("mYfIlE.tXt");

        let result_lower = soft_canonicalize(&lower)?;
        let result_upper = soft_canonicalize(&upper)?;
        let result_mixed = soft_canonicalize(&mixed)?;
        let expected = std::fs::canonicalize(&file)?;

        assert_eq!(
            result_lower, expected,
            "lowercase must resolve to on-disk case"
        );
        assert_eq!(
            result_upper, expected,
            "UPPERCASE must resolve to on-disk case"
        );
        assert_eq!(result_mixed, expected, "mIxEd must resolve to on-disk case");
        Ok(())
    }

    #[test]
    fn case_mismatch_directory_resolution() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("MyDirectory");
        fs::create_dir(&dir)?;
        let file = dir.join("Data.txt");
        fs::write(&file, b"content")?;

        // Navigate with wrong casing
        let wrong_case = tmp.path().join("mydirectory").join("data.txt");
        let result = soft_canonicalize(&wrong_case)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn case_mismatch_with_nonexisting_suffix() -> io::Result<()> {
        // Existing dir with wrong case + non-existing child
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("RealDir");
        fs::create_dir(&dir)?;

        let path = tmp.path().join("realdir").join("nonexist.txt");
        let result = soft_canonicalize(&path)?;

        // The existing directory should be resolved to on-disk case
        let canonical_dir = std::fs::canonicalize(&dir)?;
        assert_eq!(result, canonical_dir.join("nonexist.txt"));
        Ok(())
    }

    #[test]
    fn case_insensitive_symlink_resolution() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("TargetFile.dat");
        fs::write(&target, b"data")?;

        let link = tmp.path().join("MyLink");
        std::os::unix::fs::symlink(&target, &link)?;

        // Access symlink with wrong case
        let wrong = tmp.path().join("mylink");
        let result = soft_canonicalize(&wrong)?;
        let expected = std::fs::canonicalize(&wrong)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn case_insensitive_dotdot_traversal() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("Parent").join("Child");
        fs::create_dir_all(&dir)?;
        fs::write(tmp.path().join("Parent").join("sibling.txt"), b"data")?;

        // Wrong case + dotdot
        let path = tmp
            .path()
            .join("parent")
            .join("child")
            .join("..")
            .join("sibling.txt");
        let result = soft_canonicalize(&path)?;
        let expected = std::fs::canonicalize(tmp.path().join("Parent").join("sibling.txt"))?;
        assert_eq!(result, expected);
        Ok(())
    }
}
