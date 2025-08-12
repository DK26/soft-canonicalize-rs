//! Windows 8.3 short filename false positive demo
//!
//! This example demonstrates that the false positive issue with filenames
//! like "hello~world.txt" has been fixed while still correctly handling
//! actual Windows 8.3 short names like "PROGRA~1".

#[cfg(windows)]
use soft_canonicalize::soft_canonicalize;

#[cfg(windows)]
fn main() {
    // Test the false positive case that was fixed
    let test_path = r"C:\Users\test\hello~world.txt";
    match soft_canonicalize(test_path) {
        Ok(result) => {
            println!("✅ Path processed successfully: {}", result.display());
            println!("   This filename with tilde is now correctly handled as a regular filename");
        }
        Err(e) => {
            println!("❌ Error: {e}");
        }
    }

    // Test a real 8.3 short name
    let short_name_path = r"C:\PROGRA~1\MyApp\config.txt";
    match soft_canonicalize(short_name_path) {
        Ok(result) => {
            println!("✅ Short name processed: {}", result.display());
            println!("   This 8.3 short name is correctly detected and handled");
        }
        Err(e) => {
            println!("❌ Error: {e}");
        }
    }
}

#[cfg(not(windows))]
fn main() {
    println!("This demo is Windows-specific (8.3 short names)");
}
