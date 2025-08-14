#![cfg(windows)]
// Empirical tests capturing std::fs::canonicalize behavior with NTFS ADS patterns.
// Helps justify our chosen InvalidInput policy for malformed ADS traversal attempts.

use std::fs;
use std::io;
use std::path::Path;

fn record(pattern: &str, base: &Path) -> (io::ErrorKind, Option<i32>) {
    let p = base.join(pattern);
    match std::fs::canonicalize(p) {
        Ok(_) => (io::ErrorKind::Other, None), // unexpected success marker
        Err(e) => (e.kind(), e.raw_os_error()),
    }
}

#[test]
fn std_ads_behavior_inventory() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("decoy.txt");
    fs::write(&base, b"decoy")?;
    let dir = tmp.path().to_path_buf();

    // Patterns to probe
    let cases = [
        "decoy.txt:stream",           // valid ADS syntax (stream may not exist)
        "decoy.txt:stream:$DATA",     // ADS + explicit type
        "decoy.txt:..\\..\\evil.exe", // traversal inside stream name
        "decoy.txt:stream:DATA",      // invalid type token (missing $)
        "decoy.txt:",                 // trailing colon only
    ];

    for c in cases {
        let (kind, raw) = record(c, &dir);
        println!("pattern={c} kind={kind:?} raw={raw:?}");
    }

    Ok(())
}
