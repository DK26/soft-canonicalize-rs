//! Extension trait that exposes [`crate::soft_canonicalize`] as a method on
//! standard path types, paralleling the inherent
//! [`std::path::Path::canonicalize`] method.
//!
//! The trait is sealed and implemented only for [`std::path::Path`].
//! [`std::path::PathBuf`] inherits the method via `Deref` coercion, so
//! `pathbuf.soft_canonicalize()` works without a separate impl. Foreign types
//! cannot implement the trait — callers that need to pass `&str`, `String`,
//! `OsStr`, etc. should use the free function [`crate::soft_canonicalize`],
//! which accepts any `AsRef<Path>`.

use std::io;
use std::path::{Path, PathBuf};

mod sealed {
    pub trait Sealed {}
    impl Sealed for std::path::Path {}
}

/// Method-form access to [`crate::soft_canonicalize`].
///
/// This trait is sealed; downstream crates cannot implement it. Bring it into
/// scope to call [`SoftCanonicalizeExt::soft_canonicalize`] on a [`Path`] or
/// [`PathBuf`] (the latter via `Deref`).
///
/// # Example
///
/// ```
/// use soft_canonicalize::SoftCanonicalizeExt;
/// use std::path::PathBuf;
///
/// # fn example() -> std::io::Result<()> {
/// let here: PathBuf = std::env::current_dir()?;
/// let canon = here.soft_canonicalize()?;
/// assert!(canon.is_absolute());
/// # Ok(())
/// # }
/// # example().unwrap();
/// ```
pub trait SoftCanonicalizeExt: sealed::Sealed {
    /// Soft-canonicalize `self`. See [`crate::soft_canonicalize`] for the full
    /// algorithm, error semantics, and platform-specific output format.
    fn soft_canonicalize(&self) -> io::Result<PathBuf>;
}

impl SoftCanonicalizeExt for Path {
    #[inline]
    fn soft_canonicalize(&self) -> io::Result<PathBuf> {
        crate::soft_canonicalize(self)
    }
}
