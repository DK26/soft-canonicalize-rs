//! Black-box UNC corner case tests (Windows-only)

#[cfg(windows)]
mod windows_unc_tests {
    use soft_canonicalize::soft_canonicalize;
    use std::path::PathBuf;

    #[test]
    fn unc_device_namespace_path_normalized() {
        // Test the \\.\UNC\ form
        let input = r"\\.\UNC\server\share\a\..\b";
        // Device namespace is lexical-only; preserve the \\. prefix and resolve dotdot
        let expected = PathBuf::from(r"\\.\UNC\server\share\b");
        let got = soft_canonicalize(input).expect("canonicalize device namespace UNC");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_path_with_trailing_backslash() {
        let input = r"\\server\share\";
        let expected = soft_canonicalize(r"\\server\share").unwrap();
        let got = soft_canonicalize(input).expect("canonicalize with trailing backslash");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_path_with_trailing_backslash_on_subdir() {
        let input = r"\\server\share\a\b\\";
        let expected = soft_canonicalize(r"\\server\share\a\b").unwrap();
        let got = soft_canonicalize(input).expect("canonicalize with trailing backslash on subdir");
        assert_eq!(got, expected);
    }

    // Skip only-server UNC error assertion; environment-dependent and outside lexical scope
    #[test]
    fn unc_path_with_only_server_is_invalid_input() {
        let input = r"\\server";
        let err = soft_canonicalize(input).expect_err("incomplete UNC root should be invalid");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn unc_path_with_special_chars_in_server_share() {
        let input = r"\\server-name.com\share$name\file";
        let got = soft_canonicalize(input).expect("canonicalize with special chars");
        let expected = PathBuf::from(r"\\?\UNC\server-name.com\share$name\file");
        assert_eq!(got, expected);
    }

    // Skip case-insensitivity equality for non-existing UNC; we preserve input casing

    #[test]
    fn unc_path_with_empty_component_after_share() {
        let input = r"\\server\share\\file.txt";
        let expected = soft_canonicalize(r"\\server\share\file.txt").unwrap();
        let got = soft_canonicalize(input).expect("canonicalize with empty component");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_server_with_colon_preserved() {
        // Colon in server segment is treated lexically (no network access attempted)
        let input = r"\\server:80\share\file.txt";
        let got = soft_canonicalize(input).expect("canonicalize UNC with colon in server");
        let expected = PathBuf::from(r"\\?\UNC\server:80\share\file.txt");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_share_with_colon_preserved() {
        // Colon in share segment is treated lexically (not ADS here)
        let input = r"\\server\share:stream\file.txt";
        let got = soft_canonicalize(input).expect("canonicalize UNC with colon in share");
        let expected = PathBuf::from(r"\\?\UNC\server\share:stream\file.txt");
        assert_eq!(got, expected);
    }

    #[test]
    fn unc_trailing_spaces_and_dots_preserved_verbatim() {
        // Ensure trailing spaces/dots are preserved under UNC
        let p1 = r"\\server\share\folder\file. ";
        let p2 = r"\\server\share\folder\file..";
        let got1 = soft_canonicalize(p1).expect("canonicalize UNC trailing space");
        let got2 = soft_canonicalize(p2).expect("canonicalize UNC trailing dots");
        let expected1 = PathBuf::from(r"\\?\UNC\server\share\folder\file. ");
        let expected2 = PathBuf::from(r"\\?\UNC\server\share\folder\file..");
        assert_eq!(got1, expected1);
        assert_eq!(got2, expected2);
    }
}
