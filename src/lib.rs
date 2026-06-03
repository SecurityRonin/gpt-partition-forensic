//! # gpt-forensic
//!
//! Forensic-grade GUID Partition Table (GPT) parser. A sibling to
//! [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic): where that
//! crate parses the legacy MBR, this one parses the GPT that a protective MBR
//! advertises — validating the header and partition-array **CRC32** integrity,
//! reconciling the **primary and backup** GPT (divergence is a strong tampering
//! signal), and surfacing structural anomalies.
//!
//! Like its sibling, it is a pure `Read + Seek` library with no image-format
//! decoding of its own — compose it with the container crates (`ewf`, `vhd`,
//! `vmdk`, …) for E01/VHD/VMDK input.

pub mod crc32;
pub mod entry;
pub mod guid;
pub mod header;

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
    TooShort { need: usize, got: usize },
    /// I/O failure while reading the disk image.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
