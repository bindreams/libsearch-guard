//! Library-search hardening for Rust binaries.
//!
//! See the README for how a consumer uses [`bins`] and [`verify`].

mod bins;
mod verify;

pub use bins::bins;
pub use verify::{verify, VerifyError, Violation, ViolationKind};
