#![cfg(target_os = "macos")]
//! macOS-Specific Security Tests
//!
//! These tests target macOS-unique filesystem behaviors that could be exploited:
//!
//! 1. Unicode NFD normalization (APFS/HFS+ auto-decompose filenames)
//! 2. Case-insensitive but case-preserving filesystem (APFS default)
//! 3. `/private` symlink family (`/tmp`, `/var`, `/etc` → `/private/…`)
//! 4. System symlink depth-budget heuristic (`is_likely_system_symlink`)
//! 5. Resource forks / named forks (`..namedfork/rsrc`)
//! 6. Firmlinks (`/Users` ↔ `/System/Volumes/Data/Users`)
//! 7. `/dev/fd/N` file descriptor paths (macOS equivalent of `/proc/self/fd`)
//! 8. Mounted volume paths (`/Volumes/…`)

use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
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

// ─── 3. /private Symlink Family ─────────────────────────────────────────────

mod private_symlinks {
    use super::*;

    #[test]
    fn tmp_resolves_to_private_tmp() -> io::Result<()> {
        // /tmp is a symlink to /private/tmp on macOS
        if Path::new("/tmp").exists() {
            let result = soft_canonicalize("/tmp")?;
            let expected = std::fs::canonicalize("/tmp")?;
            assert_eq!(result, expected);

            // Verify it goes through /private
            assert!(
                result.starts_with("/private"),
                "/tmp should resolve to /private/tmp: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn etc_resolves_to_private_etc() -> io::Result<()> {
        // /etc is a symlink to /private/etc on macOS
        if Path::new("/etc").exists() {
            let result = soft_canonicalize("/etc")?;
            let expected = std::fs::canonicalize("/etc")?;
            assert_eq!(result, expected);

            assert!(
                result.starts_with("/private"),
                "/etc should resolve to /private/etc: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn var_resolves_to_private_var() -> io::Result<()> {
        if Path::new("/var").exists() {
            let result = soft_canonicalize("/var")?;
            let expected = std::fs::canonicalize("/var")?;
            assert_eq!(result, expected);

            assert!(
                result.starts_with("/private"),
                "/var should resolve to /private/var: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn tmp_with_nonexisting_suffix() -> io::Result<()> {
        let leaf = "softcanon_macos_test_abcdef.txt";
        let path = format!("/tmp/{leaf}");

        let result = soft_canonicalize(&path)?;
        let expected = std::fs::canonicalize("/tmp")?.join(leaf);
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn etc_with_existing_file() -> io::Result<()> {
        // /etc/hosts exists on all macOS systems
        let path = Path::new("/etc/hosts");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn private_directly_matches_symlink() -> io::Result<()> {
        // Accessing /private/tmp directly vs /tmp should give same result
        if Path::new("/private/tmp").exists() && Path::new("/tmp").exists() {
            let via_symlink = soft_canonicalize("/tmp")?;
            let via_direct = soft_canonicalize("/private/tmp")?;
            assert_eq!(via_symlink, via_direct);
        }
        Ok(())
    }

    #[test]
    fn dotdot_from_private_tmp_to_private() -> io::Result<()> {
        // /tmp/../etc should resolve through /private
        let path = "/tmp/../etc/hosts";
        if Path::new("/etc/hosts").exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize("/etc/hosts")?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn var_folders_temp_dir() -> io::Result<()> {
        // macOS temp directories are often under /var/folders/…
        // Verify TempDir paths canonicalize correctly through the /var → /private/var symlink
        let tmp = TempDir::new()?;
        let file = tmp.path().join("test.txt");
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);

        // On macOS, TempDir is usually under /private/var/folders or /private/tmp
        let result_str = result.to_string_lossy();
        assert!(
            result_str.starts_with("/private"),
            "TempDir should resolve through /private: {result_str}"
        );
        Ok(())
    }

    #[test]
    fn symlink_chain_through_private() -> io::Result<()> {
        // Create a symlink chain: link1 → /tmp/subdir → (which is really /private/tmp/subdir)
        let tmp = TempDir::new()?;
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir)?;
        fs::write(real_dir.join("target.txt"), b"data")?;

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link)?;

        let result = soft_canonicalize(link.join("target.txt"))?;
        let expected = std::fs::canonicalize(real_dir.join("target.txt"))?;
        assert_eq!(result, expected);
        Ok(())
    }
}

// ─── 4. System Symlink Depth Budget Heuristic ────────────────────────────────

mod system_symlink_budget {
    use super::*;

    #[test]
    fn var_does_not_exhaust_depth_budget() -> io::Result<()> {
        // /var → /private/var consumes 1 symlink level.
        // Our heuristic reduces budget for /var paths to 5, which is still enough.
        // Create a chain through /var that exercises the heuristic.
        let tmp = TempDir::new()?;

        // Create a moderate symlink chain inside the temp dir (which is under /var)
        let dir = tmp.path().join("chain");
        fs::create_dir(&dir)?;
        fs::write(dir.join("target.txt"), b"data")?;

        // 3-level chain: l1 → l2 → l3 → chain
        let l3 = tmp.path().join("l3");
        std::os::unix::fs::symlink(&dir, &l3)?;
        let l2 = tmp.path().join("l2");
        std::os::unix::fs::symlink(&l3, &l2)?;
        let l1 = tmp.path().join("l1");
        std::os::unix::fs::symlink(&l2, &l1)?;

        // This should resolve despite the reduced budget
        let result = soft_canonicalize(l1.join("target.txt"))?;
        let expected = std::fs::canonicalize(l1.join("target.txt"))?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn etc_does_not_exhaust_depth_budget() -> io::Result<()> {
        // /etc → /private/etc is a system symlink.
        // Verify an existing file under /etc resolves correctly.
        let path = Path::new("/etc/hosts");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn tmp_tempdir_chain_within_budget() -> io::Result<()> {
        // TempDir on macOS is typically under /tmp or /var/tmp, both system symlinks.
        // Create the max budget chain (budget = 5, minus 1 for /var symlink = 4 remaining)
        let tmp = TempDir::new()?;
        let target = tmp.path().join("leaf");
        fs::create_dir(&target)?;

        let mut current = target.clone();
        for i in 0..4 {
            let link = tmp.path().join(format!("hop{i}"));
            std::os::unix::fs::symlink(&current, &link)?;
            current = link;
        }

        let result = soft_canonicalize(&current)?;
        let expected = std::fs::canonicalize(&current)?;
        assert_eq!(result, expected);
        Ok(())
    }
}

// ─── 5. Resource Forks / Named Forks ─────────────────────────────────────────

mod resource_forks {
    use super::*;

    #[test]
    fn namedfork_rsrc_path() -> io::Result<()> {
        // macOS supports resource forks via `file/..namedfork/rsrc`
        // This is a special path component that accesses the resource fork
        let tmp = TempDir::new()?;
        let file = tmp.path().join("test.txt");
        fs::write(&file, b"data")?;

        let rsrc_path = file.join("..namedfork").join("rsrc");
        let result = soft_canonicalize(&rsrc_path);
        // The resource fork may or may not exist, but the function must not panic
        // and should either resolve it or return a clean error
        match result {
            Ok(p) => {
                // If it resolves, verify it's sensible
                let p_str = p.to_string_lossy();
                assert!(
                    p_str.contains("test.txt"),
                    "Resource fork path should reference the base file: {p_str}"
                );
            }
            Err(_) => {} // Error is fine if resource forks aren't supported
        }
        Ok(())
    }

    #[test]
    fn namedfork_as_traversal_attempt() -> io::Result<()> {
        // Verify `..namedfork` is not confused with `..` (parent) traversal
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("subdir");
        fs::create_dir(&dir)?;
        let file = dir.join("test.txt");
        fs::write(&file, b"data")?;

        // `..namedfork` is NOT `..` — it should not traverse up
        let path = dir.join("..namedfork");
        let result = soft_canonicalize(&path);
        match result {
            Ok(p) => {
                // Must not resolve to tmp.path() (parent) — ..namedfork is not ..
                assert!(
                    p.starts_with(std::fs::canonicalize(&dir).unwrap_or(dir.clone())),
                    "..namedfork must not act as parent traversal: {p:?}"
                );
            }
            Err(_) => {} // Error is acceptable (component doesn't exist)
        }
        Ok(())
    }

    #[test]
    fn namedfork_with_nonexisting_suffix() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let file = tmp.path().join("base.txt");
        fs::write(&file, b"data")?;

        // Non-existing path through a named fork
        let path = file.join("..namedfork").join("rsrc").join("evil.txt");
        let result = soft_canonicalize(&path);
        // Must not panic
        match result {
            Ok(_) | Err(_) => {}
        }
        Ok(())
    }
}

// ─── 6. Firmlinks ───────────────────────────────────────────────────────────

mod firmlinks {
    use super::*;

    #[test]
    fn users_firmlink_consistency() -> io::Result<()> {
        // On macOS Catalina+, /Users is a firmlink to /System/Volumes/Data/Users
        // Both paths should resolve to the same canonical path
        let users = Path::new("/Users");
        let data_users = Path::new("/System/Volumes/Data/Users");

        if users.exists() && data_users.exists() {
            let result_users = soft_canonicalize(users)?;
            let result_data = soft_canonicalize(data_users)?;
            let expected_users = std::fs::canonicalize(users)?;
            let expected_data = std::fs::canonicalize(data_users)?;

            // Match std behavior — whether they resolve to the same path depends
            // on how macOS handles firmlinks in realpath()
            assert_eq!(result_users, expected_users);
            assert_eq!(result_data, expected_data);
        }
        Ok(())
    }

    #[test]
    fn applications_firmlink() -> io::Result<()> {
        let apps = Path::new("/Applications");
        if apps.exists() {
            let result = soft_canonicalize(apps)?;
            let expected = std::fs::canonicalize(apps)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn library_firmlink() -> io::Result<()> {
        let lib = Path::new("/Library");
        if lib.exists() {
            let result = soft_canonicalize(lib)?;
            let expected = std::fs::canonicalize(lib)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn system_library_deep_path() -> io::Result<()> {
        // /System/Library exists on all macOS
        let path = Path::new("/System/Library");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn firmlink_with_nonexisting_suffix() -> io::Result<()> {
        let users = Path::new("/Users");
        if users.exists() {
            let path = users
                .join("nonexistent_user_softcanon_test")
                .join("file.txt");
            let result = soft_canonicalize(&path)?;
            let canonical_users = std::fs::canonicalize(users)?;
            assert_eq!(
                result,
                canonical_users
                    .join("nonexistent_user_softcanon_test")
                    .join("file.txt")
            );
        }
        Ok(())
    }
}

// ─── 7. /dev/fd/N Paths ────────────────────────────────────────────────────

mod dev_fd {
    use super::*;

    #[test]
    fn dev_fd_stdin() -> io::Result<()> {
        // /dev/fd/0 is stdin on macOS (equivalent to /proc/self/fd/0 on Linux)
        let path = Path::new("/dev/fd/0");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dev_fd_with_nonexisting_suffix() -> io::Result<()> {
        // /dev/fd is a directory on macOS — trying to traverse past a fd number
        let path = Path::new("/dev/fd/999999/evil/passwd");
        let result = soft_canonicalize(path);
        // Must not panic — likely errors since fd 999999 doesn't exist
        match result {
            Ok(p) => {
                // Should not resolve to something outside /dev
                assert!(
                    p.starts_with("/dev"),
                    "/dev/fd traversal must stay in /dev: {p:?}"
                );
            }
            Err(_) => {} // Expected
        }
        Ok(())
    }

    #[test]
    fn dev_fd_dotdot_escape_attempt() -> io::Result<()> {
        // Try to use /dev/fd/../../../etc/passwd
        let path = Path::new("/dev/fd/../../../etc/passwd");
        if Path::new("/etc/passwd").exists() {
            let result = soft_canonicalize(path)?;
            // This should resolve /dev/fd/.. to /dev, then ../../etc/passwd to /etc/passwd
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dev_null_consistency() -> io::Result<()> {
        let result = soft_canonicalize("/dev/null")?;
        let expected = std::fs::canonicalize("/dev/null")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn dev_stderr_fd() -> io::Result<()> {
        // /dev/fd/2 = stderr
        let path = Path::new("/dev/fd/2");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }
}

// ─── 8. Volumes Mount Points ────────────────────────────────────────────────

mod volumes {
    use super::*;

    #[test]
    fn volumes_directory_exists() -> io::Result<()> {
        // /Volumes always exists on macOS
        let path = Path::new("/Volumes");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn volumes_with_nonexisting_mount() -> io::Result<()> {
        // Non-existing volume mount point
        let path = Path::new("/Volumes/NonExistentDisk_SoftCanon/file.txt");
        let result = soft_canonicalize(path)?;
        let canonical_volumes = std::fs::canonicalize("/Volumes")?;
        assert_eq!(
            result,
            canonical_volumes
                .join("NonExistentDisk_SoftCanon")
                .join("file.txt")
        );
        Ok(())
    }

    #[test]
    fn macintosh_hd_volume() -> io::Result<()> {
        // The main volume is often accessible at /Volumes/Macintosh HD
        let path = Path::new("/Volumes/Macintosh HD");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn dotdot_from_volumes_mount() -> io::Result<()> {
        // Traversing up from a mount point
        let path = Path::new("/Volumes/../etc/hosts");
        if Path::new("/etc/hosts").exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize("/etc/hosts")?;
            assert_eq!(result, expected);
        }
        Ok(())
    }
}

// ─── 9. Anchored Canonicalize: macOS-specific ───────────────────────────────

#[cfg(feature = "anchored")]
mod anchored_macos {
    use soft_canonicalize::anchored_canonicalize;
    use std::fs;
    use std::io;
    use tempfile::TempDir;

    #[test]
    fn anchored_resolves_through_private() -> io::Result<()> {
        // Anchor under /tmp (which resolves to /private/tmp)
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir(&anchor)?;

        let result = anchored_canonicalize(&anchor, "child/file.txt")?;
        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;

        assert!(
            result.starts_with(&canonical_anchor),
            "Anchored result should be within canonicalized anchor: {result:?}"
        );
        // Verify /private prefix
        assert!(
            result.to_string_lossy().starts_with("/private"),
            "macOS anchored result should go through /private: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn anchored_nfd_input() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir(&anchor)?;

        // NFD input should be preserved as non-existing suffix
        let nfd_input = "cafe\u{0301}/file.txt";
        let result = anchored_canonicalize(&anchor, nfd_input)?;
        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;

        assert!(
            result.starts_with(&canonical_anchor),
            "NFD input must stay within anchor: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn anchored_case_mismatch_in_anchor() -> io::Result<()> {
        // Anchor with wrong case — should still resolve correctly on macOS
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("MyAnchor");
        fs::create_dir(&anchor)?;

        let wrong_case_anchor = tmp.path().join("myanchor");
        let result = anchored_canonicalize(&wrong_case_anchor, "file.txt")?;

        // On case-insensitive macOS, this should resolve
        let canonical_anchor = std::fs::canonicalize(&anchor)?;
        assert!(
            result.starts_with(&canonical_anchor),
            "Case-insensitive anchor must resolve: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn anchored_symlink_escape_through_private_clamped() -> io::Result<()> {
        // Symlink inside anchor that points to /etc (→ /private/etc)
        // Should be clamped to the anchor
        let tmp = TempDir::new()?;
        let anchor = tmp.path().join("anchor");
        fs::create_dir(&anchor)?;

        let link = anchor.join("escape");
        std::os::unix::fs::symlink("/etc", &link)?;

        let result = anchored_canonicalize(&anchor, "escape/hosts")?;
        let canonical_anchor = soft_canonicalize::soft_canonicalize(&anchor)?;

        assert!(
            result.starts_with(&canonical_anchor),
            "Symlink to /etc must be clamped to anchor: {result:?}"
        );
        // The escape should be reinterpreted within the anchor, NOT follow to /private/etc
        Ok(())
    }
}

// ─── 10. macOS-Specific Edge Cases ──────────────────────────────────────────

mod macos_edge_cases {
    use super::*;

    #[test]
    fn dot_underscore_file() -> io::Result<()> {
        // macOS creates ._filename files for extended attributes on non-HFS volumes
        let tmp = TempDir::new()?;
        let file = tmp.path().join("._test.txt");
        fs::write(&file, b"xattr")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn ds_store_file() -> io::Result<()> {
        // .DS_Store is a common macOS file in directories
        let tmp = TempDir::new()?;
        let file = tmp.path().join(".DS_Store");
        fs::write(&file, b"store")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn hidden_directory_with_dot_prefix() -> io::Result<()> {
        // macOS has many dot-prefixed hidden directories
        let tmp = TempDir::new()?;
        let dir = tmp.path().join(".hidden_dir");
        fs::create_dir(&dir)?;
        let file = dir.join("file.txt");
        fs::write(&file, b"data")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn space_in_path_component() -> io::Result<()> {
        // macOS commonly has spaces in paths (e.g., "Macintosh HD", "Application Support")
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("Application Support");
        fs::create_dir(&dir)?;
        let file = dir.join("My Config.plist");
        fs::write(&file, b"xml")?;

        let result = soft_canonicalize(&file)?;
        let expected = std::fs::canonicalize(&file)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn very_long_utf8_filename() -> io::Result<()> {
        // APFS supports filenames up to 255 UTF-8 bytes
        let tmp = TempDir::new()?;

        // Use multi-byte characters to approach the limit
        // Each é in NFC is 2 bytes, so 127 of them = 254 bytes + ".t" = boundary
        let long_name = "\u{00E9}".repeat(120) + ".t";
        let file = tmp.path().join(&long_name);

        match fs::write(&file, b"data") {
            Ok(()) => {
                let result = soft_canonicalize(&file)?;
                let expected = std::fs::canonicalize(&file)?;
                assert_eq!(result, expected);
            }
            Err(_) => {} // Name too long on this filesystem — skip
        }
        Ok(())
    }

    #[test]
    fn usr_bin_through_firmlink() -> io::Result<()> {
        // /usr/bin exists on all macOS systems
        let path = Path::new("/usr/bin");
        if path.exists() {
            let result = soft_canonicalize(path)?;
            let expected = std::fs::canonicalize(path)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn usr_local_through_nonexisting() -> io::Result<()> {
        // /usr/local/bin might or might not exist, test with non-existing suffix
        let path = Path::new("/usr/local/bin/softcanon_test_nonexistent_binary");
        let result = soft_canonicalize(path)?;

        // The existing prefix (/usr/local/bin or /usr/local or /usr) should be canonicalized
        let result_str = result.to_string_lossy();
        assert!(
            result_str.starts_with("/usr"),
            "Should preserve /usr prefix: {result_str}"
        );
        assert!(
            result_str.contains("softcanon_test_nonexistent_binary"),
            "Should preserve non-existing suffix"
        );
        Ok(())
    }

    #[test]
    fn symlink_to_system_binary() -> io::Result<()> {
        // Create a symlink to a system binary (e.g., /bin/sh)
        let tmp = TempDir::new()?;
        let link = tmp.path().join("my_sh");
        if Path::new("/bin/sh").exists() {
            std::os::unix::fs::symlink("/bin/sh", &link)?;
            let result = soft_canonicalize(&link)?;
            let expected = std::fs::canonicalize(&link)?;
            assert_eq!(result, expected);
        }
        Ok(())
    }

    #[test]
    fn multiple_symlinks_through_system_paths() -> io::Result<()> {
        // Chain: link1 → /tmp/dir → (resolves to /private/tmp/dir) → link_inside → target
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("target_dir");
        fs::create_dir(&dir)?;
        let target_file = dir.join("goal.txt");
        fs::write(&target_file, b"goal")?;

        // Create an inner symlink to the file
        let inner_link = dir.join("inner_link");
        std::os::unix::fs::symlink(&target_file, &inner_link)?;

        // Create an outer symlink to inner_link
        let outer_link = tmp.path().join("outer_link");
        std::os::unix::fs::symlink(&inner_link, &outer_link)?;

        let result = soft_canonicalize(&outer_link)?;
        let expected = std::fs::canonicalize(&outer_link)?;
        assert_eq!(result, expected);
        Ok(())
    }
}
