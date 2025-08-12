//! Black-box UNC penetration tests (Windows-only)
//!
//! These tests avoid network access by relying on lexical behavior of soft_canonicalize.

#[cfg(windows)]
mod tests {
    use soft_canonicalize::soft_canonicalize;
    use std::path::PathBuf;

    #[test]
    fn unc_jail_escape_prevention_dotdot() {
        let jail_raw = r"\\server\share";
        let attacker = r"\\server\share\..\..\Windows\System32";

        let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let child = soft_canonicalize(attacker).expect("canonicalize attacker");

        assert!(
            child.starts_with(&jail),
            "Dotdot must be clamped to UNC share root: child={child:?}, jail={jail:?}"
        );
        assert_eq!(child, jail.join("Windows").join("System32"));
    }

    #[test]
    fn unc_mixed_separators_and_redundant_slashes() {
        let jail_raw = r"\\?\UNC\server\share";
        let tricky = r"\\?\UNC\server\share///a\\.\\b\\..\\c/////d";

        let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let got = soft_canonicalize(tricky).expect("canonicalize tricky");

        assert!(got.starts_with(jail));
        assert!(got.ends_with(PathBuf::from(r"a\c\d")));
    }

    #[test]
    fn unc_ads_suffix_preserved_and_scoped() {
        // Alternate Data Streams should be treated textually and remain scoped under jail
        let jail_raw = r"\\server\share";
        let with_ads = r"\\server\share\folder\file.txt:secret";

        let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let got = soft_canonicalize(with_ads).expect("canonicalize with ADS");

        assert!(got.starts_with(jail));
        assert!(got.ends_with(PathBuf::from(r"folder\file.txt:secret")));
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

        assert!(got.starts_with(jail));
        assert!(got.ends_with(PathBuf::from(r"safe\child.txt")));
    }
}
