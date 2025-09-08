use soft_canonicalize::anchored_canonicalize;

/// Demonstrates the anchored_canonicalize feature for path canonicalization relative to an anchor
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Anchored Canonicalization Demo ===\n");

    // Set up an anchor directory
    let anchor = std::env::temp_dir().join("workspace_root");
    println!("Anchor directory: {anchor:?}\n");

    // Demo 1: Normal paths are resolved relative to the anchor
    println!("--- NORMAL PATHS ---");
    let normal_paths = [
        "documents/readme.txt",
        "data/config.json",
        "./scripts/build.sh",
        "uploads/photo.jpg",
    ];

    for path in &normal_paths {
        match anchored_canonicalize(&anchor, path) {
            Ok(resolved) => println!("✅ {path:?} → {resolved:?}"),
            Err(e) => println!("❌ {path:?} → Error: {e}"),
        }
    }

    // Demo 2: Lexical .. is clamped to anchor boundary
    println!("\n--- LEXICAL .. CLAMPING ---");
    let traversal_paths = [
        "../../../etc/passwd",
        "docs/../../../sensitive.txt",
        "uploads/../../../../../../root/.ssh/id_rsa",
        "../outside_anchor/file.txt",
        "normal/../../../../../../etc/shadow",
    ];

    for path in &traversal_paths {
        match anchored_canonicalize(&anchor, path) {
            Ok(resolved) => println!("✅ {path:?} → {resolved:?}"),
            Err(e) => println!("❌ {path:?} → Error: {e}"),
        }
    }

    // Demo 3: Absolute paths are treated relative to anchor
    println!("\n--- ABSOLUTE PATHS TREATED AS RELATIVE ---");

    #[cfg(unix)]
    let absolute_paths = [
        "/etc/passwd",
        "/home/other_user/secrets.txt",
        "/usr/bin/malware",
    ];

    #[cfg(windows)]
    let absolute_paths = [
        r"C:\Windows\System32\config\sam",
        r"C:\Users\Other\secrets.txt",
        r"D:\external\malware.exe",
    ];

    for path in &absolute_paths {
        match anchored_canonicalize(&anchor, path) {
            Ok(resolved) => println!("📁 {path:?} → {resolved:?}"),
            Err(e) => println!("❌ {path:?} → Error: {e}"),
        }
    }

    // Demo 4: Edge cases
    println!("\n--- EDGE CASES ---");
    let edge_cases = [
        "",     // Empty path
        ".",    // Current directory
        "..",   // Parent directory (clamped to anchor)
        "file", // Simple filename
    ];

    for path in &edge_cases {
        match anchored_canonicalize(&anchor, path) {
            Ok(resolved) => println!("✅ {path:?} → {resolved:?}"),
            Err(e) => println!("❌ {path:?} → Error: {e}"),
        }
    }

    println!("\n=== Demo Complete ===");
    println!("anchored_canonicalize performs path canonicalization relative to an anchor!");
    println!("Useful for resolving paths within a known root directory context.");

    Ok(())
}
