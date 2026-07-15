//! GPT header (LBA 1 / backup) parsing and self-CRC validation.
//!
//! The header is 92 bytes (the spec minimum) at the start of its sector. Its own
//! CRC-32 is computed over the first `header_size` bytes with the CRC field
//! (offset 16..20) zeroed — a mismatch indicates corruption or tampering.

use crate::crc32;
use crate::guid::Guid;
use crate::Error;
use forensic_bytes::{le_u32, le_u64};

/// The 8-byte GPT header signature.
pub const SIGNATURE: &[u8; 8] = b"EFI PART";
/// Minimum (and spec-standard) header size in bytes.
pub const MIN_HEADER_SIZE: u32 = 92;
/// Byte offset of the header's own CRC-32 field.
const HEADER_CRC_OFFSET: usize = 16;

/// A parsed GPT header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GptHeader {
    /// Header revision (e.g. `0x0001_0000` for v1.0).
    pub revision: u32,
    /// Header size in bytes (spec value: 92).
    pub header_size: u32,
    /// The CRC-32 stored in the header.
    pub header_crc32: u32,
    /// `true` when the stored CRC matches a recomputed CRC over the header.
    pub header_crc_valid: bool,
    /// LBA of this header (1 for primary; last LBA for backup).
    pub my_lba: u64,
    /// LBA of the other (backup/primary) header.
    pub alternate_lba: u64,
    /// First LBA usable by partitions.
    pub first_usable_lba: u64,
    /// Last LBA usable by partitions.
    pub last_usable_lba: u64,
    /// Disk GUID.
    pub disk_guid: Guid,
    /// LBA where the partition entry array begins.
    pub partition_entry_lba: u64,
    /// Number of entries in the partition array.
    pub num_partition_entries: u32,
    /// Size of each partition entry, in bytes (spec value: 128).
    pub partition_entry_size: u32,
    /// CRC-32 of the partition entry array.
    pub partition_array_crc32: u32,
}

impl GptHeader {
    /// Parse a GPT header from the start of `sector`.
    ///
    /// # Errors
    /// [`Error::TooShort`] if `sector` is under 92 bytes; [`Error::BadSignature`]
    /// if it does not begin with `"EFI PART"`.
    pub fn parse(sector: &[u8]) -> Result<GptHeader, Error> {
        if sector.len() < MIN_HEADER_SIZE as usize {
            return Err(Error::TooShort {
                need: MIN_HEADER_SIZE as usize,
                got: sector.len(),
            });
        }
        if &sector[0..8] != SIGNATURE {
            return Err(Error::BadSignature);
        }

        let header_size = le_u32(sector, 12);
        let header_crc32 = le_u32(sector, 16);
        let header_crc_valid = compute_header_crc(sector, header_size)
            .is_some_and(|computed| computed == header_crc32);

        let mut disk_guid = [0u8; 16];
        disk_guid.copy_from_slice(&sector[56..72]);

        Ok(GptHeader {
            revision: le_u32(sector, 8),
            header_size,
            header_crc32,
            header_crc_valid,
            my_lba: le_u64(sector, 24),
            alternate_lba: le_u64(sector, 32),
            first_usable_lba: le_u64(sector, 40),
            last_usable_lba: le_u64(sector, 48),
            disk_guid: Guid(disk_guid),
            partition_entry_lba: le_u64(sector, 72),
            num_partition_entries: le_u32(sector, 80),
            partition_entry_size: le_u32(sector, 84),
            partition_array_crc32: le_u32(sector, 88),
        })
    }
}

/// Recompute the header CRC over `header_size` bytes with the CRC field zeroed.
/// Returns `None` if `header_size` is implausible (out of `[92, sector.len()]`).
fn compute_header_crc(sector: &[u8], header_size: u32) -> Option<u32> {
    let size = header_size as usize;
    if header_size < MIN_HEADER_SIZE || size > sector.len() {
        return None;
    }
    let mut buf = sector[..size].to_vec();
    buf[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].fill(0);
    Some(crc32::checksum(&buf))
}
