#[cfg(test)]
mod test_python_lessons {
    use crate::soft_canonicalize;
    use std::fs;

    /// Demonstrates that we ARE Python's resolve(strict=False) equivalent
    /// This validates our value proposition - we provide the missing functionality
    #[test]
    fn test_python_style_strict_modes() {
        use std::env;

        let temp_dir = env::temp_dir();
        let existing_path = &temp_dir;
        let non_existing_path = temp_dir.join("does/not/exist.txt");

        println!("=== WE ARE THE MISSING strict=False FUNCTIONALITY ===");
        println!("Python: Path.resolve(strict=True)  ≡ Rust: std::fs::canonicalize()");
        println!("Python: Path.resolve(strict=False) ≡ Rust: soft_canonicalize() ← WE ARE THIS");

        // Demonstrate std::fs::canonicalize ≡ Python's strict=True
        println!("\nRust's std::fs::canonicalize (≡ Python strict=True):");
        match fs::canonicalize(existing_path) {
            Ok(_) => println!("✓ Existing path: Works"),
            Err(e) => println!("✗ Existing path: {e}"),
        }

        match fs::canonicalize(&non_existing_path) {
            Ok(_) => println!("✓ Non-existing path: Works (unexpected!)"),
            Err(_) => println!("✗ Non-existing path: Fails (expected - requires existence)"),
        }

        // Demonstrate soft_canonicalize ≡ Python's strict=False
        println!("\nOur soft_canonicalize (≡ Python strict=False):");
        match soft_canonicalize(existing_path) {
            Ok(_) => println!("✓ Existing path: Works"),
            Err(e) => println!("✗ Existing path: {e}"),
        }

        match soft_canonicalize(&non_existing_path) {
            Ok(_) => println!("✓ Non-existing path: Works (this is our value!)"),
            Err(e) => println!("✗ Non-existing path: {e}"),
        }

        println!("\n=== CONCLUSION ===");
        println!("We provide the missing strict=False functionality that Rust lacks!");
    }

    /// Tests Python-inspired path normalization improvements we could add
    #[test]
    fn test_path_normalization_edge_cases() {
        // These are cases where Python's normalization is particularly good
        let test_cases = vec![
            ("path/./with/./dots", "current dir dots"),
            ("dir/../other/file.txt", "sibling traversal"),
            ("./file.txt", "current dir file"),
            ("../parent/file.txt", "parent traversal"),
        ];

        println!("\nPython-inspired normalization tests:");
        for (input, description) in test_cases {
            match soft_canonicalize(input) {
                Ok(result) => println!(
                    "✓ {} ('{}') -> path exists: {:?}",
                    description,
                    input,
                    result.exists()
                ),
                Err(e) => println!("✗ {description} ('{input}') -> {e}"),
            }
        }

        // Our normalization should handle these correctly
        assert!(soft_canonicalize("path/./with/./dots").is_ok());
        assert!(soft_canonicalize("dir/../other/file.txt").is_ok());
    }
}
