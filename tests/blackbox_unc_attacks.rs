//! Black-box UNC penetration tests (Windows-only)
//!
//! These tests avoid network access by relying on lexical behavior of soft_canonicalize.

#[cfg(windows)]
mod windows_unc_tests {
    use soft_canonicalize::soft_canonicalize;
    use std::path::PathBuf;

    #[test]
    fn unc_jail_escape_prevention_dotdot() {
        let jail_raw = r"\\server\share";
        let attacker = r"\\server\share\..\..\Windows\System32";

        let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let child = soft_canonicalize(attacker).expect("canonicalize attacker");

        let expected = jail.join("Windows").join("System32");
        assert_eq!(
            child, expected,
            "Dotdot must clamp to share root and append tail exactly"
        );
    }

    #[test]
    fn unc_mixed_separators_and_redundant_slashes() {
        let jail_raw = r"\\?\UNC\server\share";
        let tricky = r"\\?\UNC\server\share\a\.\\b\..\c\d";

        let _jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let got = soft_canonicalize(tricky).expect("canonicalize tricky");

        // Both with and without dunce: non-existing UNC paths remain in extended-length format
        // dunce does NOT simplify non-existing UNC paths (can't verify safety without filesystem access)
        let expected = PathBuf::from(r"\\?\UNC\server\share\a\c\d");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_ads_suffix_preserved_and_scoped() {
        // Alternate Data Streams should be treated textually and remain scoped under jail
        let jail_raw = r"\\server\share";
        let with_ads = r"\\server\share\folder\file.txt:secret";

        let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let got = soft_canonicalize(with_ads).expect("canonicalize with ADS");
        let expected = jail.join(r"folder\file.txt:secret");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_long_traversal_clamped_at_share() {
        // Many .. should not escape the share
        let jail_raw = r"\\server\share";
        let mut path = String::from(jail_raw);
        for _ in 0..128 {
            path.push_str("\\..\\");
        }
        path.push_str("safe\\child.txt");

        let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let got = soft_canonicalize(&path).expect("canonicalize long traversal");
        let expected = jail.join(r"safe\child.txt");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_nonfinal_ads_component_rejected() {
        // Colon-containing component before final must be rejected in UNC too
        let input = r"\\server\share\dir:stream\leaf.txt";
        let err = soft_canonicalize(input).expect_err("non-final ADS in UNC must be invalid");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn unc_directory_ads_final_preserved() {
        // ADS-like suffix on a directory as final component should be preserved textually
        let input = r"\\server\share\mydir:stream";
        let got = soft_canonicalize(input).expect("canonicalize UNC directory ADS final");
        let expected = PathBuf::from(r"\\?\UNC\server\share\mydir:stream");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_directory_ads_final_with_type_preserved() {
        // ADS-like suffix with explicit $DATA type in final component
        let input = r"\\server\share\folder:stream:$DATA";
        let got = soft_canonicalize(input).expect("canonicalize UNC directory ADS + type final");
        let expected = PathBuf::from(r"\\?\UNC\server\share\folder:stream:$DATA");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_directory_ads_type_only_final_preserved() {
        // Type-only ADS token on a directory final component is preserved textually
        let input = r"\\server\share\dir::$DATA";
        let got = soft_canonicalize(input).expect("canonicalize UNC directory ::$DATA final");
        let expected = PathBuf::from(r"\\?\UNC\server\share\dir::$DATA");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_ads_whitespace_injection_preserved_textually() {
        // Under UNC, ADS-like suffix with whitespace/control in final component is preserved textually
        let cases: [(&str, &str); 5] = [
            (
                "\\\\server\\share\\file.txt: stream",
                "\\\\?\\UNC\\server\\share\\file.txt: stream",
            ),
            (
                "\\\\server\\share\\file.txt:stream ",
                "\\\\?\\UNC\\server\\share\\file.txt:stream ",
            ),
            (
                "\\\\server\\share\\file.txt:\tstream",
                "\\\\?\\UNC\\server\\share\\file.txt:\tstream",
            ),
            (
                "\\\\server\\share\\file.txt:stream\r",
                "\\\\?\\UNC\\server\\share\\file.txt:stream\r",
            ),
            (
                "\\\\server\\share\\file.txt:stream\n",
                "\\\\?\\UNC\\server\\share\\file.txt:stream\n",
            ),
        ];
        for (input, expected) in cases {
            let got = soft_canonicalize(input).expect("canonicalize UNC ADS with whitespace");
            assert_eq!(got, PathBuf::from(expected));
        }
    }
}
