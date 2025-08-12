//! White-box security audit test suite
//!
//! This module contains comprehensive white-box security tests that examine
//! the internal algorithm and try to break it by exploiting implementation
//! details, edge cases, and potential vulnerabilities.
//!
//! Tests are organized by category:
//! - `symlink`: Symlink cycle detection, visited sets, depth limits
//! - `dotdot`: Path traversal and .. resolution attacks  
//! - `race`: Race conditions and TOCTOU vulnerabilities
//! - `unicode`: Unicode, encoding, and null byte injection
//! - `boundary`: Boundary detection and existing path edge cases
//! - `platform`: Platform-specific limits and behavior
//! - `memory`: Memory exhaustion and performance attacks
//! - `jail_escape`: High-level security validation tests
//! - `misc`: Miscellaneous white-box tests
//! - `unix`: Unix-specific security tests
//! - `windows`: Windows-specific security tests

pub mod boundary;
pub mod dotdot;
pub mod jail_escape;
pub mod memory;
pub mod misc;
pub mod platform;
pub mod race;
pub mod short_filename_bypass;
pub mod symlink;
pub mod unc;
pub mod unicode;

// Platform-specific modules
pub mod unix;
pub mod windows;
