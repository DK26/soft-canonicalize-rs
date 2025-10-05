/// Tests for anchored_canonicalize symlink clamping behavior
///
/// These tests define the CORRECT behavior: all absolute symlink targets
/// should be clamped to the anchor, implementing true virtual filesystem semantics.
use crate::anchored_canonicalize;
use std::fs;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn test_absolute_symlink_to_external_path_is_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create external target OUTSIDE the anchor
    let external_td = TempDir::new().unwrap();
    let external_file = external_td.path().join("external_secret.txt");
    fs::write(&external_file, b"external data").unwrap();
    let abs_external = fs::canonicalize(&external_file).unwrap();

    // Create symlink INSIDE anchor pointing to absolute external path
    let symlink_path = abs_anchor.join("link_to_external");
    symlink(&abs_external, symlink_path).unwrap();

    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "link_to_external").unwrap();

    // EXPECTED: Should clamp to anchor, not follow to external location
    assert!(
        result.starts_with(&abs_anchor),
        "Symlink target should be clamped to anchor. Got: {:?}, Anchor: {:?}",
        result,
        abs_anchor
    );

    // The clamped path should be: anchor + external_file's absolute path (stripped of root)
    // e.g., /tmp/anchor/tmp/abc123/external_secret.txt
    let external_stripped = abs_external.strip_prefix("/").unwrap();
    let expected = abs_anchor.join(external_stripped);
    assert_eq!(
        result, expected,
        "Should clamp by stripping root prefix and rejoining to anchor"
    );
}

#[cfg(unix)]
#[test]
fn test_absolute_symlink_to_root_path_is_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create symlink pointing to /etc/passwd (absolute root path)
    let symlink_path = abs_anchor.join("passwd_link");
    symlink("/etc/passwd", symlink_path).unwrap();

    // Access through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "passwd_link").unwrap();

    // Should clamp /etc/passwd to anchor/etc/passwd
    assert!(
        result.starts_with(&abs_anchor),
        "Should clamp to anchor. Got: {:?}, Anchor: {:?}",
        result,
        abs_anchor
    );
    assert!(
        result.ends_with("etc/passwd"),
        "Should clamp /etc/passwd to anchor/etc/passwd. Got: {:?}",
        result
    );

    let expected = abs_anchor.join("etc/passwd");
    assert_eq!(result, expected);
}

#[cfg(unix)]
#[test]
fn test_chained_symlinks_with_absolute_target_all_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create: link1 -> link2 (relative)
    // Create: link2 -> /absolute/target (absolute - should be clamped)
    let link1 = abs_anchor.join("link1");
    let link2 = abs_anchor.join("link2");

    symlink("link2", link1).unwrap(); // relative
    symlink("/absolute/target", link2).unwrap(); // absolute

    // Access link1
    let result = anchored_canonicalize(&abs_anchor, "link1").unwrap();

    // Should clamp to anchor/absolute/target
    assert!(result.starts_with(&abs_anchor));
    assert!(result.ends_with("absolute/target"));

    let expected = abs_anchor.join("absolute/target");
    assert_eq!(result, expected);
}

#[cfg(unix)]
#[test]
fn test_relative_symlinks_continue_working() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create target file inside anchor
    let target = abs_anchor.join("data/target.txt");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, b"target content").unwrap();

    // Create relative symlink
    let link_dir = abs_anchor.join("links");
    fs::create_dir(&link_dir).unwrap();
    let symlink_path = link_dir.join("relative_link");
    symlink("../data/target.txt", symlink_path).unwrap();

    // Access through anchored_canonicalize
    let result = anchored_canonicalize(&abs_anchor, "links/relative_link").unwrap();

    // Should resolve to the actual target location
    let expected = fs::canonicalize(&target).unwrap();
    assert_eq!(result, expected);
}

#[cfg(unix)]
#[test]
fn test_dotdot_after_absolute_symlink_stays_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create symlink: mylink -> /etc/config (absolute)
    let link = abs_anchor.join("mylink");
    symlink("/etc/config/subdir", link).unwrap();

    // Access: mylink/../../passwd
    // Should resolve as: anchor/etc/config/subdir + ../../ = anchor/etc/passwd
    let result = anchored_canonicalize(&abs_anchor, "mylink/../../passwd").unwrap();

    assert!(result.starts_with(&abs_anchor));
    assert!(result.ends_with("etc/passwd"));

    let expected = abs_anchor.join("etc/passwd");
    assert_eq!(result, expected);
}

#[cfg(unix)]
#[test]
fn test_excessive_dotdot_after_absolute_symlink_clamps_to_anchor() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create symlink: mylink -> /a/b/c (absolute)
    let link = abs_anchor.join("mylink");
    symlink("/a/b/c", link).unwrap();

    // Access: mylink/../../../../../../../../etc/passwd
    // Should clamp to anchor when going above, then resolve etc/passwd
    let result =
        anchored_canonicalize(&abs_anchor, "mylink/../../../../../../../../etc/passwd").unwrap();

    assert!(result.starts_with(&abs_anchor));
    assert!(result.ends_with("etc/passwd"));

    let expected = abs_anchor.join("etc/passwd");
    assert_eq!(result, expected);
}

#[cfg(unix)]
#[test]
fn test_symlink_to_nonexistent_absolute_path_is_clamped() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create symlink pointing to non-existent absolute path
    let link = abs_anchor.join("future_link");
    symlink("/future/file/that/does/not/exist", link).unwrap();

    // Should still clamp even though target doesn't exist (soft canonicalization)
    let result = anchored_canonicalize(&abs_anchor, "future_link").unwrap();

    assert!(result.starts_with(&abs_anchor));
    let expected = abs_anchor.join("future/file/that/does/not/exist");
    assert_eq!(result, expected);
}

#[cfg(unix)]
#[test]
fn test_mixed_absolute_and_relative_symlink_chain() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create directory structure
    fs::create_dir_all(abs_anchor.join("data")).unwrap();

    // Chain: link1 (relative) -> link2 (absolute) -> link3 (relative)
    let link1 = abs_anchor.join("link1");
    let link2 = abs_anchor.join("data/link2");
    let link3_target = abs_anchor.join("data/final");
    fs::create_dir_all(&link3_target).unwrap();

    symlink("data/link2", link1).unwrap(); // relative
    symlink("/etc/link3", link2).unwrap(); // absolute (will be clamped)

    // Create the clamped target for link3
    let link3 = abs_anchor.join("etc/link3");
    fs::create_dir_all(link3.parent().unwrap()).unwrap();
    symlink("../data/final", &link3).unwrap(); // relative

    // Access link1
    let result = anchored_canonicalize(&abs_anchor, "link1").unwrap();

    // Should follow: link1 -> data/link2 -> [clamped]/etc/link3 -> data/final
    assert!(result.starts_with(&abs_anchor));
    let expected = fs::canonicalize(&link3_target).unwrap();
    assert_eq!(result, expected);
}

#[cfg(windows)]
#[test]
fn test_windows_absolute_symlink_clamping() {
    // Note: Creating symlinks on Windows requires admin privileges or developer mode
    // This test validates the clamping logic without actually creating symlinks
    // (Windows symlink tests are typically skipped in CI)

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = crate::soft_canonicalize(&anchor).unwrap();

    // Test lexical clamping of absolute paths (without symlinks)
    let result = anchored_canonicalize(&abs_anchor, r"C:\Windows\System32").unwrap();

    // Should clamp C:\Windows\System32 to anchor\C\Windows\System32 or anchor\Windows\System32
    assert!(result.starts_with(&abs_anchor));
    assert!(result.to_string_lossy().contains("Windows"));
    assert!(result.to_string_lossy().contains("System32"));
}

#[cfg(unix)]
#[test]
fn test_archive_extraction_scenario() {
    use std::os::unix::fs::symlink;

    // Simulates extracting an archive with absolute symlinks into a sandbox
    let td = TempDir::new().unwrap();
    let sandbox = td.path().join("extract_zone");
    fs::create_dir_all(&sandbox).unwrap();
    let abs_sandbox = fs::canonicalize(&sandbox).unwrap();

    // Archive contains:
    // - data/config.txt (file)
    // - shortcuts/cfg -> /etc/config (absolute symlink)
    fs::create_dir_all(abs_sandbox.join("data")).unwrap();
    fs::write(abs_sandbox.join("data/config.txt"), b"config data").unwrap();

    fs::create_dir_all(abs_sandbox.join("shortcuts")).unwrap();
    let cfg_link = abs_sandbox.join("shortcuts/cfg");
    symlink("/etc/config", cfg_link).unwrap();

    // User tries to access the symlink
    let result = anchored_canonicalize(&abs_sandbox, "shortcuts/cfg").unwrap();

    // Should be safely clamped within sandbox
    assert!(result.starts_with(&abs_sandbox));
    let expected = abs_sandbox.join("etc/config");
    assert_eq!(result, expected);

    // Verify no escape occurred
    assert!(!result.to_string_lossy().contains("/../"));
    assert!(!result.starts_with("/etc"));
}

#[cfg(unix)]
#[test]
fn test_symlink_cycle_detection_still_works_with_clamping() {
    use std::os::unix::fs::symlink;

    let td = TempDir::new().unwrap();
    let anchor = td.path().join("virtual_root");
    fs::create_dir_all(&anchor).unwrap();
    let abs_anchor = fs::canonicalize(&anchor).unwrap();

    // Create cycle with absolute symlinks that will be clamped within anchor
    // We need the symlinks to point to absolute paths that, when clamped, point back to each other
    let link_a = abs_anchor.join("a");
    let link_b = abs_anchor.join("b");

    // Get the absolute path of link_b, then use it as target for link_a
    // When clamped, it should still resolve to the actual link_b location
    symlink(abs_anchor.join("b"), link_a).unwrap(); // points to anchor/b
    symlink(abs_anchor.join("a"), link_b).unwrap(); // points to anchor/a

    // Should detect cycle and return error
    let err = anchored_canonicalize(&abs_anchor, "a").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("symbolic link"));
}
