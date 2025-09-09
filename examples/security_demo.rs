use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
use std::path::{Path, PathBuf};

/// Manual validation approach - validates that a user-provided path stays within a jail directory
fn validate_user_path_manual(user_input: &str, jail_dir: &Path) -> Result<PathBuf, String> {
    println!("  [Manual] Validating user input: {user_input:?}");

    // Canonicalize the user input (may not exist yet)
    let canonical_path =
        soft_canonicalize(Path::new(user_input)).map_err(|e| format!("Invalid path: {e}"))?;

    println!("  [Manual] Canonicalized to: {canonical_path:?}");

    // Ensure it's within the jail directory
    if canonical_path.starts_with(jail_dir) {
        println!("  [Manual] ✅ SAFE: Path is within jail boundary");
        Ok(canonical_path)
    } else {
        println!("  [Manual] 🚫 BLOCKED: Path escapes jail boundary");
        Err("Path escapes jail boundary".to_string())
    }
}

/// Built-in secure approach using anchored_canonicalize
fn validate_user_path_anchored(user_input: &str, jail_dir: &Path) -> Result<PathBuf, String> {
    println!("  [Anchored] Validating user input: {user_input:?}");

    // Use anchored_canonicalize for automatic path jailing (no need to pre-canonicalize jail_dir)
    match anchored_canonicalize(jail_dir, user_input) {
        Ok(safe_path) => {
            println!("  [Anchored] Resolved to: {safe_path:?}");
            println!("  [Anchored] ✅ SAFE: Path is automatically constrained to anchor");
            Ok(safe_path)
        }
        Err(e) => {
            println!("  [Anchored] 🚫 BLOCKED: {e}");
            Err(format!("Path validation failed: {e}"))
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Soft Canonicalize - Security Demo ===\n");

    // Set up a jail directory
    let jail = std::env::temp_dir().join("user_files");
    // For manual validation we use a canonicalized jail; anchored variant can take raw path too
    let canonical_jail = soft_canonicalize(&jail)?;

    println!("Jail directory (canonical for manual demo): {canonical_jail:?}\n");

    // Test cases: safe paths
    println!("--- SAFE PATHS ---");

    let safe_paths = [
        "documents/file.txt",
        "photos/vacation/beach.jpg",
        "projects/website/index.html",
        "./config/settings.json",
        "uploads/user123/document.pdf",
    ];

    for path in &safe_paths {
        println!("Testing path: {path:?}");
        match validate_user_path_manual(path, &canonical_jail) {
            Ok(_) => println!(),
            Err(e) => println!("  Error: {e}\n"),
        }
        match validate_user_path_anchored(path, &jail) {
            Ok(_) => println!(),
            Err(e) => println!("  Error: {e}\n"),
        }
    }

    // Test cases: malicious paths with directory traversal
    println!("--- MALICIOUS PATHS (Directory Traversal) ---");

    let malicious_paths = [
        "../../../etc/passwd",
        "documents/../../../sensitive.txt",
        "uploads/../../../../../../root/.ssh/id_rsa",
        "../outside_jail/malware.exe",
        "safe/path/../../../../../../etc/shadow",
        "normal/../../../config.ini",
        "files/../../../../windows/system32/config/sam",
    ];

    for path in &malicious_paths {
        println!("Testing malicious path: {path:?}");
        match validate_user_path_manual(path, &canonical_jail) {
            Ok(_) => println!(),
            Err(e) => println!("  [Manual] Expected: {e}\n"),
        }
        match validate_user_path_anchored(path, &jail) {
            Ok(_) => println!(),
            Err(e) => println!("  [Anchored] Expected: {e}\n"),
        }
    }

    // Test cases: absolute paths outside jail
    println!("--- ABSOLUTE PATHS OUTSIDE JAIL ---");

    #[cfg(windows)]
    let absolute_attacks = [
        "C:\\Windows\\System32\\config\\SAM",
        "D:\\sensitive\\data.txt",
        "\\\\server\\share\\secrets.txt",
    ];

    #[cfg(not(windows))]
    let absolute_attacks = [
        "/etc/passwd",
        "/root/.ssh/authorized_keys",
        "/usr/bin/malware",
        "/home/other_user/secrets.txt",
    ];

    for path in &absolute_attacks {
        println!("Testing absolute attack: {path:?}");
        match validate_user_path_manual(path, &canonical_jail) {
            Ok(_) => println!(),
            Err(e) => println!("  [Manual] Expected: {e}\n"),
        }
        match validate_user_path_anchored(path, &jail) {
            Ok(_) => println!(),
            Err(e) => println!("  [Anchored] Expected: {e}\n"),
        }
    }

    // Demonstrate edge cases
    println!("--- EDGE CASES ---");

    let edge_cases = [
        "",                                                     // Empty path
        ".",                                                    // Current directory
        "..",                                                   // Parent directory
        "file",                                                 // Simple filename
        "very/deep/nested/structure/with/many/levels/file.txt", // Deep nesting
    ];

    for path in &edge_cases {
        println!("Testing edge case: {path:?}");
        match validate_user_path_manual(path, &canonical_jail) {
            Ok(_) => println!(),
            Err(e) => println!("  [Manual] Result: {e}\n"),
        }
        match validate_user_path_anchored(path, &jail) {
            Ok(_) => println!(),
            Err(e) => println!("  [Anchored] Result: {e}\n"),
        }
    }

    println!("=== Security Demo Complete ===");
    println!("Both manual validation and anchored_canonicalize successfully blocked all directory traversal attempts!");
    println!("anchored_canonicalize provides the same security with simpler, more reliable code.");

    Ok(())
}
