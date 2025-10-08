//! # Archive Extraction Security: Before & After
//!
//! Demonstrates two valid approaches for handling symlinks in untrusted archives:
//! strict rejection vs virtual filesystem clamping.
//!
//! This shows the v0.4.0 behavior where `anchored_canonicalize` clamps symlink
//! targets to create true virtual filesystem semantics. See PR #22:
//! <https://github.com/DK26/soft-canonicalize-rs/pull/22>
//!
//! **Note**: On Unix, this creates real symlinks and demonstrates actual behavior.
//! On Windows, it shows conceptual examples (symlinks require admin privileges).

use std::fs;

#[cfg(feature = "anchored")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    use soft_canonicalize::anchored_canonicalize;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  SCENARIO: Symlinks in User-Uploaded Archives                ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Setup realistic scenario
    let temp = std::env::temp_dir().join("archive_demo");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp)?;

    fs::create_dir_all(temp.join("user_123"))?;

    // Simulate sensitive files OUTSIDE user's directory
    let admin_dir = temp.join("admin");
    fs::create_dir_all(&admin_dir)?;
    fs::write(admin_dir.join("database.sql"), "DROP TABLE users; --")?;
    fs::write(temp.join("secrets.txt"), "API_KEY=secret_12345")?;

    println!("🏢 Multi-tenant file server:");
    println!("   📁 user_123/          ← User's isolated directory");
    println!("   📁 admin/database.sql ← Admin files (forbidden!)");
    println!("   📄 secrets.txt        ← Server secrets (forbidden!)\n");

    #[cfg(unix)]
    {
        let user_sandbox = temp.join("user_123");
        use std::os::unix::fs::symlink;

        println!("😈 Attacker uploads malicious.zip:");
        let archive = user_sandbox.join("uploaded");
        fs::create_dir_all(&archive)?;

        // Normal file to appear innocent
        fs::write(archive.join("invoice.pdf"), "Looks safe...")?;

        // ATTACK: Symlinks trying to escape
        symlink("../../secrets.txt", archive.join("config.txt"))?;
        symlink("../../admin/database.sql", archive.join("backup.sql"))?;

        println!("   📄 invoice.pdf     (legitimate)");
        println!("   🔗 config.txt   → ../../secrets.txt");
        println!("   🔗 backup.sql   → ../../admin/database.sql\n");

        println!("─────────────────────────────────────────────────────────────\n");

        // Show traditional approach
        println!("📋 APPROACH 1: Reject escaping symlinks (strict semantics):\n");

        match std::fs::canonicalize(archive.join("config.txt")) {
            Ok(path) => {
                // Check if symlink escaped
                if !path.starts_with(&user_sandbox) {
                    println!("   User reads: 'uploaded/config.txt'");
                    println!("   System resolves to: {path:?}");
                    println!("   ⚠️  Detected escape! Reject this file.\n");
                    println!("   Semantics: System filesystem - symlinks point to");
                    println!("              their actual targets. Reject escapees.\n");
                }
            }
            Err(e) => println!("   Error: {e}\n"),
        }

        println!("─────────────────────────────────────────────────────────────\n");

        // Show virtual filesystem approach
        println!("📋 APPROACH 2: Clamp symlinks (virtual filesystem semantics):\n");

        match anchored_canonicalize(&user_sandbox, "uploaded/config.txt") {
            Ok(safe_path) => {
                let relative = safe_path.strip_prefix(&user_sandbox).unwrap();
                println!("   User reads: 'uploaded/config.txt'");
                println!("   Symlink points to: ../../secrets.txt");
                println!("   🔒 CLAMPED to: user_123/{relative:?}");
                println!("   ✅ Symlink is valid within the virtual filesystem.\n");
                println!("   Semantics: Virtual filesystem - ALL absolute paths are");
                println!("              relative to the anchor. Accept the symlink.\n");
            }
            Err(e) => println!("   Error: {e}\n"),
        }

        match anchored_canonicalize(&user_sandbox, "uploaded/backup.sql") {
            Ok(safe_path) => {
                let relative = safe_path.strip_prefix(&user_sandbox).unwrap();
                println!("   User reads: 'uploaded/backup.sql'");
                println!("   Symlink points to: ../../admin/database.sql");
                println!("   🔒 CLAMPED to: user_123/{relative:?}");
                println!("   ✅ Admin files protected!\n");
            }
            Err(e) => println!("   Error: {e}\n"),
        }
    }

    #[cfg(windows)]
    {
        println!("😈 Attacker uploads malicious.zip:");
        println!("   📄 invoice.pdf     (legitimate)");
        println!("   🔗 config.txt   → C:\\Windows\\System32\\config");
        println!("   🔗 backup.sql   → C:\\admin\\database.sql\n");

        println!("─────────────────────────────────────────────────────────────");
        println!("ℹ️  CONCEPTUAL EXAMPLE (Windows requires admin for symlinks)");
        println!("   Run on Linux/macOS to see actual behavior with real symlinks!");
        println!("─────────────────────────────────────────────────────────────\n");

        println!("📋 APPROACH 1: Strict - reject escaping symlinks");
        println!("   → Reject config.txt (escapes sandbox)\n");

        println!("📋 APPROACH 2: Virtual - clamp symlinks to anchor");
        println!("   → Clamped to user_123\\Windows\\System32\\config");
        println!("   → Accept it (treated as relative to virtual root)\n");
    }

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  TWO VALID APPROACHES - Choose Your Semantics                ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  STRICT (reject):  System filesystem semantics               ║");
    println!("║                    Symlinks point to actual targets          ║");
    println!("║                    Use: Admin tools, system resources        ║");
    println!("║                                                              ║");
    println!("║  VIRTUAL (clamp):  Virtual filesystem semantics (v0.4.0)     ║");
    println!("║                    ALL paths relative to anchor              ║");
    println!("║                    Use: Archives, multi-tenant, sandboxes    ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let _ = fs::remove_dir_all(&temp);
    Ok(())
}

#[cfg(not(feature = "anchored"))]
fn main() {
    eprintln!("This example requires the 'anchored' feature.");
    eprintln!("Run with: cargo run --example virtual_filesystem_demo --features anchored");
    std::process::exit(1);
}
