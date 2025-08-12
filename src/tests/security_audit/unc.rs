//! White-box UNC penetration tests (Windows-only)
//!
//! These tests leverage internal behavior guarantees, but do not require actual network shares.

#![cfg(windows)]

#[cfg(test)]
mod white_box_unc {
    use crate::soft_canonicalize;
    use std::path::PathBuf;

    #[test]
    fn share_root_is_floor_for_parentdir() {
        let jail_raw = r"\\server\share";
        let p = r"\\server\share\..\..\..\alpha\beta";
        let jail = soft_canonicalize(jail_raw).expect("canonicalize jail");
        let got = soft_canonicalize(p).expect("canonicalize p");
        assert_eq!(got, jail.join("alpha").join("beta"));
    }

    #[test]
    fn verbatim_unc_is_idempotent() {
        let p = PathBuf::from(r"\\?\UNC\server\share\x\y\z");
        let got = soft_canonicalize(&p).expect("canonicalize verbatim UNC");
        assert_eq!(got, p);
    }

    #[test]
    fn shortname_component_preserved_when_nonexisting() {
        let p = r"\\server\share\PROGRA~1\foo.txt";
        let got = soft_canonicalize(p).expect("canonicalize shortname");
        assert!(got.ends_with(PathBuf::from(r"PROGRA~1\foo.txt")));
    }

    #[test]
    fn trailing_dot_space_preserved_under_verbatim() {
        let p = r"\\?\UNC\server\share\dir. \file. txt";
        let got = soft_canonicalize(p).expect("canonicalize verbatim trailing dot/space");
        assert!(got.ends_with(PathBuf::from(r"dir. \file. txt")));
    }
}
