//! # gpt (gpt-partition-core)
//!
//! Pure-Rust read-only GUID Partition Table (GPT) reader — the parser layer of
//! [`gpt-partition-forensic`](https://github.com/SecurityRonin/gpt-partition-forensic).
//! It decodes the on-disk GPT structures (header, partition entries, GUIDs) and
//! validates their **CRC32** integrity, plus the four protective/legacy MBR
//! partition entries needed to reconcile the MBR against the GPT.
//!
//! It is a pure structure decoder: it carries **no forensic findings** of its
//! own (no `report::Observation`, no anomaly grading). Compose it with
//! [`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic)
//! for anomaly analysis, and with the container crates (`ewf`, `vhd`, `vmdk`, …)
//! for E01/VHD/VMDK input.
//!
//! The crates.io package is `gpt-partition-core` (the bare `gpt-core` name is
//! taken), but the import path is the ergonomic `use gpt::…`.

// Production code is panic-free (no unwrap/expect, enforced by the workspace
// lints); tests legitimately use them.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod crc32;
pub mod entry;
pub mod guid;
pub mod header;
pub mod mbr;
pub mod sha256;
#[cfg(feature = "vfs")]
pub mod vfs;

pub use entry::GptEntry;
pub use guid::Guid;
pub use header::GptHeader;

/// Crate-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The GPT header signature was not `"EFI PART"`.
    #[error("invalid GPT header signature")]
    BadSignature,
    /// A buffer was shorter than the structure it was asked to hold.
    #[error("buffer too short: need {need} bytes, got {got}")]
    TooShort {
        /// Bytes the structure requires.
        need: usize,
        /// Bytes actually available.
        got: usize,
    },
    /// I/O failure while reading the disk image.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
