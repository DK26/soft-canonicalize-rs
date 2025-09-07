use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::{fmt, io};

/// Error payload used by this crate to attach the offending path to I/O errors.
#[derive(Debug, Clone)]
pub struct SoftCanonicalizeError {
    path: PathBuf,
    detail: Cow<'static, str>,
}

impl SoftCanonicalizeError {
    pub fn new(path: PathBuf, detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            path,
            detail: detail.into(),
        }
    }
    /// Offending path that caused the error
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Human-readable error detail (without the path suffix)
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for SoftCanonicalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (path: '{}')", self.detail, self.path.display())
    }
}

impl std::error::Error for SoftCanonicalizeError {}

/// Convenience to create an io::Error with our path-aware payload.
#[inline]
pub(crate) fn error_with_path(
    kind: io::ErrorKind,
    path: &Path,
    detail: impl Into<Cow<'static, str>>,
) -> io::Error {
    io::Error::new(kind, SoftCanonicalizeError::new(path.to_path_buf(), detail))
}

/// Extension to extract our path-aware payload from io::Error.
pub trait IoErrorPathExt {
    fn offending_path(&self) -> Option<&Path>;
    fn soft_canon_detail(&self) -> Option<&str>;
}

impl IoErrorPathExt for io::Error {
    fn offending_path(&self) -> Option<&Path> {
        self.get_ref()
            .and_then(|e| e.downcast_ref::<SoftCanonicalizeError>())
            .map(|p| p.path())
    }

    fn soft_canon_detail(&self) -> Option<&str> {
        self.get_ref()
            .and_then(|e| e.downcast_ref::<SoftCanonicalizeError>())
            .map(|p| p.detail())
    }
}
