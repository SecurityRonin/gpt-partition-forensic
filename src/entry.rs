//! GPT partition entry parsing.
//!
//! Each entry is `partition_entry_size` bytes (spec value 128): a type GUID, a
//! unique GUID, first/last LBA, attribute flags, and a 36-code-unit UTF-16LE
//! name. An entry whose type GUID is all-zero is an unused slot.

use crate::guid::Guid;
use crate::Error;

/// Minimum entry size the spec permits (and the default): 128 bytes.
pub const MIN_ENTRY_SIZE: usize = 128;
/// Byte offset of the UTF-16LE name within an entry.
const NAME_OFFSET: usize = 56;
/// Name length in bytes (36 UTF-16 code units).
const NAME_LEN: usize = 72;

/// A parsed GPT partition entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GptEntry {
    /// Partition type GUID (all-zero = unused).
    pub type_guid: Guid,
    /// Unique partition GUID.
    pub unique_guid: Guid,
    /// First LBA of the partition (inclusive).
    pub first_lba: u64,
    /// Last LBA of the partition (inclusive).
    pub last_lba: u64,
    /// Attribute flags bitfield.
    pub attributes: u64,
    /// Partition name (decoded from UTF-16LE, trailing NULs stripped).
    pub name: String,
}

fn u64_le(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

impl GptEntry {
    /// Parse one entry from the first 128 bytes of `bytes`.
    ///
    /// # Errors
    /// [`Error::TooShort`] if `bytes` is under [`MIN_ENTRY_SIZE`].
    pub fn parse(bytes: &[u8]) -> Result<GptEntry, Error> {
        if bytes.len() < MIN_ENTRY_SIZE {
            return Err(Error::TooShort {
                need: MIN_ENTRY_SIZE,
                got: bytes.len(),
            });
        }
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&bytes[0..16]);
        let mut unique_guid = [0u8; 16];
        unique_guid.copy_from_slice(&bytes[16..32]);
        Ok(GptEntry {
            type_guid: Guid(type_guid),
            unique_guid: Guid(unique_guid),
            first_lba: u64_le(bytes, 32),
            last_lba: u64_le(bytes, 40),
            attributes: u64_le(bytes, 48),
            name: decode_name(&bytes[NAME_OFFSET..NAME_OFFSET + NAME_LEN]),
        })
    }

    /// `true` when the entry's type GUID is non-zero (an in-use partition).
    #[must_use]
    pub fn is_used(&self) -> bool {
        !self.type_guid.is_zero()
    }
}

/// Decode a UTF-16LE name field, stopping at the first NUL code unit.
fn decode_name(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parse a partition-entry array, returning only the **used** entries.
///
/// `num_entries` and `entry_size` come from the GPT header. Entries are read at
/// `entry_size` strides; a stride beyond the buffer ends iteration. Unused
/// (all-zero type GUID) entries are skipped.
#[must_use]
pub fn parse_entry_array(array: &[u8], num_entries: u32, entry_size: u32) -> Vec<GptEntry> {
    let stride = entry_size as usize;
    if stride < MIN_ENTRY_SIZE {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..num_entries as usize {
        let start = i * stride;
        let Some(slot) = array.get(start..start + MIN_ENTRY_SIZE) else {
            break;
        };
        if let Ok(entry) = GptEntry::parse(slot) {
            if entry.is_used() {
                out.push(entry);
            }
        }
    }
    out
}
