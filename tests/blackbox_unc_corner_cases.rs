//! Black-box UNC corner case tests (Windows-only)

#[cfg(windows)]
mod tests {
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
        assert!(got
            .to_string_lossy()
            .starts_with(r"\\?\UNC\server-name.com\share$name"));
        assert!(got.ends_with("file"));
    }

    // Skip case-insensitivity equality for non-existing UNC; we preserve input casing

    #[test]
    fn unc_path_with_empty_component_after_share() {
        let input = r"\\server\share\\file.txt";
        let expected = soft_canonicalize(r"\\server\share\file.txt").unwrap();
        let got = soft_canonicalize(input).expect("canonicalize with empty component");
        assert_eq!(got, expected);
    }
}
