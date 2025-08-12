//! Extra black-box UNC tests for unicode obfuscation and long paths (Windows-only)

#[cfg(windows)]
mod windows_unc_tests {
    use soft_canonicalize::soft_canonicalize;
    use std::ffi::OsString;
    use std::path::{Component, PathBuf, Prefix};

    #[test]
    fn unc_unicode_server_share_preserved_no_normalization() {
        // Zero-width joiner and zero-width space embedded to ensure we do not normalize or strip
        let server = OsString::from("ser\u{200d}ver"); // ZWJ inside server name
        let share = OsString::from("sh\u{200b}are"); // ZWSP inside share name

        let base = format!(
            "\\\\{}\\{}",
            server.to_string_lossy(),
            share.to_string_lossy()
        );
        let input = PathBuf::from(base).join("folder").join("file.txt");

        let got = soft_canonicalize(input).expect("soft_canonicalize unicode UNC");

        // Expect extended-length verbatim UNC prefix with the exact same server/share bytes
        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimUNC(srv, shr) => {
                    assert_eq!(srv, server.as_os_str(), "server component mutated");
                    assert_eq!(shr, share.as_os_str(), "share component mutated");
                }
                k => panic!("expected VerbatimUNC prefix, got {k:?}"),
            },
            other => panic!("expected UNC prefix, got {other:?}"),
        }

        assert!(got.ends_with(PathBuf::from(r"folder\file.txt")));
    }

    #[test]
    fn unc_very_long_path_uses_extended_length_and_preserves_suffix() {
        let server = "server";
        let share = "share";
        let mut input = PathBuf::from(format!("\\\\{server}\\{share}"));

        // Build a long suffix (> 260 chars) using repeated 10-char segments
        for _ in 0..40 {
            // ~400 chars plus separators
            input.push("abcdefghij");
        }

        let got = soft_canonicalize(&input).expect("soft_canonicalize long UNC");

        // Ensure extended-length prefix is present and server/share are preserved
        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimUNC(srv, shr) => {
                    assert_eq!(srv, server, "server mismatch");
                    assert_eq!(shr, share, "share mismatch");
                }
                k => panic!("expected VerbatimUNC prefix, got {k:?}"),
            },
            other => panic!("expected UNC prefix, got {other:?}"),
        }

        // Long path should exceed MAX_PATH (260) when stringified
        assert!(got.to_string_lossy().len() > 260);

        // Suffix integrity check: last segment remains intact
        assert!(got.ends_with(PathBuf::from("abcdefghij")));
    }

    #[test]
    fn unc_unicode_normalization_forms_preserved() {
        // NFC vs NFD: ensure we do not normalize or fold these
        let server_nfc = String::from("serv\u{00E9}r"); // 'ré' composed
        let share_nfd = String::from("sha\u{0072}\u{0065}\u{0301}"); // 'ré' decomposed

        let input = PathBuf::from(format!("\\\\{server_nfc}\\{share_nfd}"))
            .join("dir")
            .join("file.txt");

        let got = soft_canonicalize(input).expect("soft_canonicalize unicode forms");

        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimUNC(srv, shr) => {
                    assert_eq!(srv.to_string_lossy(), server_nfc, "server NFC mutated");
                    assert_eq!(shr.to_string_lossy(), share_nfd, "share NFD mutated");
                }
                k => panic!("expected VerbatimUNC prefix, got {k:?}"),
            },
            other => panic!("expected UNC prefix, got {other:?}"),
        }

        assert!(got.ends_with(PathBuf::from(r"dir\file.txt")));
    }

    #[test]
    fn verbatim_disk_very_long_path_preserves_prefix_and_suffix() {
        // Build a long verbatim disk path (>260 chars)
        let mut input = PathBuf::from(r"\\?\C:\");
        for _ in 0..40 {
            // ~400 chars plus separators
            input.push("abcdefghij");
        }

        let got = soft_canonicalize(&input).expect("soft_canonicalize long verbatim disk");

        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimDisk(d) => {
                    // Expect some drive letter; commonly 'C'
                    assert!(d.is_ascii_alphabetic());
                }
                k => panic!("expected VerbatimDisk prefix, got {k:?}"),
            },
            other => panic!("expected Disk prefix, got {other:?}"),
        }

        assert!(got.to_string_lossy().len() > 260);
        assert!(got.ends_with(PathBuf::from("abcdefghij")));
    }

    #[test]
    fn unc_homoglyph_and_zwnj_server_share_preserved() {
        // Use ZWNJ in server and a Cyrillic 'а' (U+0430) homoglyph in share
        let server = String::from("ser\u{200c}ver"); // ZWNJ between 'r' and 'v'
        let share = String::from("sh\u{0430}re"); // 'shаre' where 'а' is Cyrillic

        let input = PathBuf::from(format!("\\\\{server}\\{share}"))
            .join("x")
            .join("y.txt");

        let got = soft_canonicalize(input).expect("soft_canonicalize homoglyph/ZWNJ");

        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimUNC(srv, shr) => {
                    assert_eq!(srv.to_string_lossy(), server, "server ZWNJ mutated");
                    assert_eq!(shr.to_string_lossy(), share, "share homoglyph mutated");
                }
                k => panic!("expected VerbatimUNC prefix, got {k:?}"),
            },
            other => panic!("expected UNC prefix, got {other:?}"),
        }

        assert!(got.ends_with(PathBuf::from(r"x\y.txt")));
    }

    #[test]
    fn verbatim_unc_very_long_deep_path_preserves_prefix_and_suffix() {
        let mut input = PathBuf::from(r"\\?\UNC\server\share");
        for _ in 0..60 {
            // make it very long and deep
            input.push("abcdefghij");
        }

        let got = soft_canonicalize(&input).expect("soft_canonicalize long verbatim UNC");

        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimUNC(srv, shr) => {
                    assert_eq!(srv, "server");
                    assert_eq!(shr, "share");
                }
                k => panic!("expected VerbatimUNC prefix, got {k:?}"),
            },
            other => panic!("expected UNC prefix, got {other:?}"),
        }

        assert!(got.to_string_lossy().len() > 260);
        assert!(got.ends_with(PathBuf::from("abcdefghij")));
    }

    #[test]
    fn unc_mixed_unicode_forms_deep_suffix_preserved() {
        // Mix both NFC and NFD on server and share, then add a deep suffix
        let server = String::from("s\u{0065}\u{0301}rver"); // 'sé' decomposed (NFD)
        let share = String::from("sh\u{00E1}re"); // 'sháre' composed (NFC)

        let mut input = PathBuf::from(format!("\\\\{server}\\{share}"));
        for _ in 0..25 {
            input.push("abcdefghij");
        }
        input.push("leaf.txt");

        let got = soft_canonicalize(&input).expect("soft_canonicalize mixed unicode deep");

        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimUNC(srv, shr) => {
                    assert_eq!(
                        srv.to_string_lossy(),
                        server,
                        "server normalization happened"
                    );
                    assert_eq!(shr.to_string_lossy(), share, "share normalization happened");
                }
                k => panic!("expected VerbatimUNC prefix, got {k:?}"),
            },
            other => panic!("expected UNC prefix, got {other:?}"),
        }

        assert!(got.to_string_lossy().len() > 260);
        assert!(got.ends_with(PathBuf::from("leaf.txt")));
    }

    #[test]
    fn verbatim_unc_very_long_with_ads_suffix_preserved() {
        let mut input = PathBuf::from(r"\\?\UNC\server\share");
        for _ in 0..40 {
            input.push("abcdefghij");
        }
        input.push("target.txt:stream_data");

        let got = soft_canonicalize(&input).expect("soft_canonicalize long verbatim UNC with ADS");

        let mut comps = got.components();
        match comps.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::VerbatimUNC(srv, shr) => {
                    assert_eq!(srv, "server");
                    assert_eq!(shr, "share");
                }
                k => panic!("expected VerbatimUNC prefix, got {k:?}"),
            },
            other => panic!("expected UNC prefix, got {other:?}"),
        }

        assert!(got.to_string_lossy().len() > 260);
        assert!(
            got.ends_with(PathBuf::from("target.txt:stream_data")),
            "ADS suffix must be preserved as textual component"
        );
    }
}
