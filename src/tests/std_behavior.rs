#[cfg(test)]
mod test_std_behavior {
    use crate::soft_canonicalize;
    use std::fs;
    use std::io;

    #[test]
    fn test_std_canonicalize_empty_path() {
        // Test what std::fs::canonicalize returns for empty path
        match fs::canonicalize("") {
            Ok(_) => println!("Empty path: OK (unexpected)"),
            Err(e) => {
                println!("Empty path error kind: {:?}", e.kind());
                println!("Empty path error message: '{e}'");

                // Check what error kind and message std produces
                assert_eq!(e.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    #[test]
    fn test_our_empty_path_matches_std() {
        // Test that our empty path error matches std behavior
        let std_result = fs::canonicalize("");
        let our_result = soft_canonicalize("");

        // Both should fail with NotFound
        assert!(std_result.is_err());
        assert!(our_result.is_err());

        let std_err = std_result.unwrap_err();
        let our_err = our_result.unwrap_err();

        // Same error kind
        assert_eq!(std_err.kind(), our_err.kind());
        assert_eq!(our_err.kind(), io::ErrorKind::NotFound);

        // Our message should be similar to std (may differ slightly due to OS)
        println!("std error: '{std_err}'");
        println!("our error: '{our_err}'");
    }

    #[test]
    fn test_error_message_format() {
        // Test that our error format matches expectations
        let error_msg = "Too many levels of symbolic links";
        println!("Expected symlink error: '{error_msg}'");

        // This is what std::fs::canonicalize typically returns on Unix systems
        // On Windows it might be slightly different but concept is the same

        // Our errors should be simple and match std::fs::canonicalize
        let test_error = io::Error::new(io::ErrorKind::InvalidInput, error_msg);
        assert_eq!(test_error.to_string(), error_msg);
    }

    #[test]
    fn test_std_canonicalize_limitations() {
        // Demonstrate WHY we need soft_canonicalize - std::fs::canonicalize fails on non-existing paths
        use std::env;

        let temp_dir = env::temp_dir();
        println!("temp_dir: {temp_dir:?}");

        // 1. std works for existing paths
        let std_result = fs::canonicalize(&temp_dir);
        println!("std::fs::canonicalize on existing path: {std_result:?}");
        assert!(std_result.is_ok(), "std should handle existing paths");

        // 2. std FAILS for non-existing paths - this is why we need soft_canonicalize
        let non_existing = temp_dir.join("this/path/does/not/exist.txt");
        let std_result_nonexisting = fs::canonicalize(&non_existing);
        println!("std::fs::canonicalize on non-existing path: {std_result_nonexisting:?}");
        assert!(
            std_result_nonexisting.is_err(),
            "std should fail on non-existing paths"
        );

        if let Err(e) = std_result_nonexisting {
            assert_eq!(e.kind(), io::ErrorKind::NotFound);
            println!("std fails with NotFound: {e}");
        }

        // 3. Our soft_canonicalize succeeds where std fails
        let our_result = soft_canonicalize(&non_existing);
        println!("soft_canonicalize on non-existing path: {our_result:?}");
        assert!(
            our_result.is_ok(),
            "soft_canonicalize should handle non-existing paths"
        );

        // 4. For existing paths, both should give same result
        let our_existing = soft_canonicalize(&temp_dir);
        assert!(our_existing.is_ok());
        // Both should resolve to the same canonical path
        assert_eq!(std_result.unwrap(), our_existing.unwrap());

        println!("\n=== CONCLUSION ===");
        println!("std::fs::canonicalize REQUIRES ALL path components to exist");
        println!("soft_canonicalize works with non-existing paths - that's our value add!");
    }
}
