//! Test utilities for feature-conditional assertions
//!
//! IMPORTANT: Do NOT create helpers that normalize away format differences between
//! dunce enabled/disabled. Each test MUST explicitly verify the exact format for
//! each feature configuration using separate #[cfg] blocks.
//!
//! Pattern for comparing with std::fs::canonicalize:
//! ```rust,ignore
//! let soft_result = soft_canonicalize(path)?;
//! let std_result = fs::canonicalize(path)?;
//!
//! #[cfg(not(feature = "dunce"))]
//! {
//!     // WITHOUT dunce: EXACT match (both UNC format on Windows)
//!     assert_eq!(soft_result, std_result);
//! }
//!
//! #[cfg(feature = "dunce")]
//! {
//!     // WITH dunce: Verify soft is simplified, std is UNC
//!     let soft_str = soft_result.to_string_lossy();
//!     let std_str = std_result.to_string_lossy();
//!     assert!(!soft_str.starts_with(r"\\?\"), "dunce should simplify");
//!     assert!(std_str.starts_with(r"\\?\"), "std returns UNC");
//! }
//! ```
