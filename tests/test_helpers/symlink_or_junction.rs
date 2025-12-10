//! Test helper: Create directory symlinks with junction fallback on Windows
//!
//! KISS approach:
//! - Try a directory symlink first
//! - On Windows, if permission denied (1314), try an NTFS junction
//! - Return Ok(false) if neither is permitted so tests can skip

use std::io;
use std::path::Path;

#[cfg(windows)]
use std::os::windows::fs::symlink_dir;

#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_dir;

/// Create a directory symlink, with automatic fallback to junction on Windows.
/// Returns Ok(true) if created, Ok(false) to skip when not permitted, Err for other errors.
#[cfg(windows)]
pub fn create_symlink_or_junction<P: AsRef<Path>, Q: AsRef<Path>>(
    target: P,
    link: Q,
) -> io::Result<bool> {
    let target = target.as_ref();
    let link = link.as_ref();

    match symlink_dir(target, link) {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
                match junction::create(target, link) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            } else {
                Err(e)
            }
        }
    }
}

/// Unix version - always uses symlinks, no fallback needed
#[cfg(unix)]
pub fn create_symlink_or_junction<P: AsRef<Path>, Q: AsRef<Path>>(
    target: P,
    link: Q,
) -> io::Result<bool> {
    symlink_dir(target.as_ref(), link.as_ref())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_symlink_or_junction_creation() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("target");
        let link = tmp.path().join("link");

        fs::create_dir_all(&target)?;

        match create_symlink_or_junction(&target, &link) {
            Ok(true) => {
                assert!(link.exists());
                assert!(link.is_dir());
            }
            Ok(false) => {
                eprintln!("Skipping: no symlink/junction support");
            }
            Err(e) => {
                panic!("Unexpected error: {e}");
            }
        }

        Ok(())
    }
}
