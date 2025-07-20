use soft_canonicalize::soft_canonicalize;
use std::env;
use std::fs;
use std::time::Instant;

fn main() {
    println!("=== Performance and Value Analysis ===\n");

    let temp_dir = env::temp_dir();
    let deep_non_existing = temp_dir.join("level1/level2/level3/level4/level5/file.txt");

    println!("Testing path: {deep_non_existing:?}");

    // Show what std::fs::canonicalize does
    println!("\n1. std::fs::canonicalize result:");
    match fs::canonicalize(&deep_non_existing) {
        Ok(result) => println!("   SUCCESS: {result:?}"),
        Err(e) => println!("   FAILED: {} (kind: {:?})", e, e.kind()),
    }

    // Show what soft_canonicalize does
    println!("\n2. soft_canonicalize result:");
    match soft_canonicalize(&deep_non_existing) {
        Ok(result) => println!("   SUCCESS: {result:?}"),
        Err(e) => println!("   FAILED: {} (kind: {:?})", e, e.kind()),
    }

    // Performance test
    println!("\n3. Performance comparison:");

    let iterations = 1000;

    // Time std::fs::canonicalize (will fail fast)
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = fs::canonicalize(&deep_non_existing);
    }
    let std_time = start.elapsed();

    // Time soft_canonicalize
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = soft_canonicalize(&deep_non_existing);
    }
    let soft_time = start.elapsed();

    println!("   std::fs::canonicalize: {std_time:?} ({iterations} iterations)");
    println!("   soft_canonicalize: {soft_time:?} ({iterations} iterations)");

    // Test with existing portion
    println!("\n4. Optimization test - existing portion:");
    let mixed_path = temp_dir.join("non/existing/file.txt");
    println!("   Path: {mixed_path:?}");

    match soft_canonicalize(&mixed_path) {
        Ok(result) => {
            println!("   Result: {result:?}");
            println!("   Note: The existing portion ({temp_dir:?}) was canonicalized using std::fs::canonicalize");
            println!(
                "         The non-existing portion (non/existing/file.txt) was appended lexically"
            );
        }
        Err(e) => println!("   Error: {e}"),
    }

    println!("\n=== WHY SOFT_CANONICALIZE IS NEEDED ===");
    println!("1. std::fs::canonicalize REQUIRES ALL components to exist");
    println!("2. soft_canonicalize works with non-existing paths");
    println!("3. For security validation before file creation");
    println!("4. For path preprocessing in build systems");
    println!("5. For resolving paths in configuration files");
    println!(
        "6. OPTIMIZATION: Uses std::fs::canonicalize on existing portions for maximum security"
    );
}
