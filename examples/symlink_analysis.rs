use soft_canonicalize::soft_canonicalize;
use std::fs;

fn main() -> std::io::Result<()> {
    println!("=== Symlink Traversal Analysis ===\n");

    // Create a temp directory manually
    let temp_base = std::env::temp_dir().join("symlink_test");
    let _ = fs::remove_dir_all(&temp_base); // Clean up if exists

    // Create directory structure:
    // temp/some/path/
    // temp/other/path/dir/
    let some_path = temp_base.join("some").join("path");
    let other_path = temp_base.join("other").join("path").join("dir");

    fs::create_dir_all(&some_path)?;
    fs::create_dir_all(&other_path)?;

    // Create symlink: temp/some/path/symlink -> temp/other/path/dir
    let symlink_path = some_path.join("symlink");

    let symlink_created = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&other_path, &symlink_path).is_ok()
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_dir;
            symlink_dir(&other_path, &symlink_path).is_ok()
        }
    };

    if !symlink_created {
        println!("⚠️  Symlink creation failed (likely Windows permissions)");
        println!("   Running without symlinks to demonstrate lexical resolution...\n");

        // Test lexical resolution without symlinks
        let test_path = some_path
            .join("nonexistent_dir")
            .join("subdir")
            .join("..")
            .join("..")
            .join("target.txt");

        println!("Testing path with .. resolution: {test_path:?}");

        let result = soft_canonicalize(&test_path)?;
        println!("soft_canonicalize result: {result:?}");

        println!("\n✅ LEXICAL RESOLUTION DEMONSTRATED:");
        println!("   - The .. components were resolved lexically");
        println!("   - Result shows proper path traversal handling");
        println!("   - This is standard behavior for path canonicalization");

        // Clean up
        let _ = fs::remove_dir_all(&temp_base);
        return Ok(());
    }

    println!("Created structure:");
    println!("  Base: {temp_base:?}");
    println!("  Some path: {some_path:?}");
    println!("  Other path: {other_path:?}");
    println!("  Symlink: {symlink_path:?} -> {other_path:?}");
    println!();

    // Test the problematic path: temp/some/path/symlink/hello/world/../../../
    let test_path = symlink_path
        .join("hello")
        .join("world")
        .join("..")
        .join("..")
        .join("..");

    println!("Testing path: {test_path:?}");

    let result = soft_canonicalize(&test_path)?;
    println!("soft_canonicalize result: {result:?}");

    // Analyze the result
    if result.starts_with(temp_base.join("some")) {
        println!("\n❌ CURRENT BEHAVIOR: Lexical resolution BEFORE symlink following");
        println!("   - The .. components were resolved before following the symlink");
        println!("   - Path stayed in the 'some' tree instead of following symlink to 'other'");
        println!("   - This could be a security issue in some scenarios");
    } else if result.starts_with(temp_base.join("other")) {
        println!("\n✅ Alternative behavior: Symlink following BEFORE lexical resolution");
        println!("   - The symlink was followed first, then .. components resolved");
        println!("   - This matches how std::fs::canonicalize would behave");
    } else {
        println!("\n🤔 Unexpected result location");
    }

    // For comparison, create the full structure and test std::fs::canonicalize
    let hello_world = other_path.join("hello").join("world");
    if fs::create_dir_all(&hello_world).is_ok() {
        println!("\nTesting std::fs::canonicalize for comparison...");
        match std::fs::canonicalize(&test_path) {
            Ok(std_result) => {
                println!("std::fs::canonicalize result: {std_result:?}");

                if std_result != result {
                    println!("\n⚠️  BEHAVIORAL DIFFERENCE DETECTED!");
                    println!("   soft_canonicalize: {result:?}");
                    println!("   std::fs::canonicalize: {std_result:?}");

                    if std_result.starts_with(temp_base.join("other")) {
                        println!("   -> std follows symlink first (correct symlink semantics)");
                    }
                    if result.starts_with(temp_base.join("some")) {
                        println!("   -> soft does lexical resolution first (potential issue)");
                    }
                }
            }
            Err(e) => {
                println!("std::fs::canonicalize failed: {e}");
            }
        }
    }

    // Clean up
    let _ = fs::remove_dir_all(&temp_base);

    Ok(())
}
