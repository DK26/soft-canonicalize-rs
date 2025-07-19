use soft_canonicalize::soft_canonicalize;
use std::path::Path;

fn main() {
    println!("Testing empty path behavior:");

    println!(
        "std::fs::canonicalize(\"\"): {:?}",
        std::fs::canonicalize("")
    );
    println!(
        "soft_canonicalize(\"\"): {:?}",
        soft_canonicalize(Path::new(""))
    );

    let empty_path = Path::new("");
    println!("\nPath::new(\"\") details:");
    println!("  is_absolute(): {}", empty_path.is_absolute());
    println!("  as_os_str(): {:?}", empty_path.as_os_str());
    println!("  components count: {}", empty_path.components().count());

    if let Ok(cwd) = std::env::current_dir() {
        println!("\nCurrent directory handling:");
        println!("Current directory: {cwd:?}");
        let joined = cwd.join(empty_path);
        println!("current_dir().join(Path::new(\"\")): {joined:?}");
        println!(
            "std::fs::canonicalize of joined: {:?}",
            std::fs::canonicalize(&joined)
        );
        println!(
            "soft_canonicalize of joined: {:?}",
            soft_canonicalize(&joined)
        );
    }

    println!("\nComparison with current directory:");
    if let Ok(_cwd) = std::env::current_dir() {
        println!(
            "soft_canonicalize(\".\"): {:?}",
            soft_canonicalize(Path::new("."))
        );
        println!(
            "std::fs::canonicalize(\".\"): {:?}",
            std::fs::canonicalize(".")
        );
    }
}
