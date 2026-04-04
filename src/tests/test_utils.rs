//! Test utilities for feature-conditional assertions
//!
//! IMPORTANT: Do NOT create helpers that normalize away format differences between
//! dunce enabled/disabled. Each test MUST explicitly verify the exact format for
//! each feature configuration using separate #[cfg] blocks.
//!
//! Pattern for comparing with std::fs::canonicalize (use current_dir as a live existing path):
//!
//! ```rust
//! use soft_canonicalize::soft_canonicalize;
//!
//! # fn example() -> std::io::Result<()> {
//! let path = std::env::current_dir()?;
//! let soft_result = soft_canonicalize(&path)?;
//! let std_result = std::fs::canonicalize(&path)?;
//!
//! #[cfg(not(feature = "dunce"))]
//! assert_eq!(soft_result, std_result);
//!
//! #[cfg(feature = "dunce")]
//! {
//!     let soft_str = soft_result.to_string_lossy();
//!     let std_str = std_result.to_string_lossy();
//!     assert_eq!(soft_str.as_ref(), std_str.trim_start_matches(r"\\?\"));
//! }
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```
