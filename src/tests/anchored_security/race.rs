#![cfg(unix)]
use crate::{anchored_canonicalize, soft_canonicalize};
use std::fs;
use tempfile::TempDir;

#[test]
fn concurrent_symlink_modification_anchor() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    let td = TempDir::new()?;
    let a = td.path().join("anchor");
    fs::create_dir_all(&a)?;
    let base = soft_canonicalize(&a)?;

    let t1 = base.join("t1");
    let t2 = base.join("t2");
    fs::create_dir(&t1)?;
    fs::create_dir(&t2)?;

    let link = base.join("racing_link");
    symlink(&t1, &link)?;

    std::thread::spawn({
        let link2 = link;
        let t2b = t2;
        move || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            let _ = fs::remove_file(&link2);
            let _ = symlink(&t2b, &link2);
        }
    });

    let res = anchored_canonicalize(&base, "racing_link/nonexistent.txt");
    match res {
        Ok(p) => assert!(p.is_absolute()),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("No such file")
                    || msg.contains("symbolic links")
                    || msg.contains("not found")
                    || msg.contains("Invalid")
            );
        }
    }
    Ok(())
}
