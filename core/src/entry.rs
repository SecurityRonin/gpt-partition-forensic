//! GPT partition entry parsing.
//!
//! Each entry is `partition_entry_size` bytes (spec value 128): a type GUID, a
//! unique GUID, first/last LBA, attribute flags, and a 36-code-unit UTF-16LE
//! name. An entry whose type GUID is all-zero is an unused slot.

use crate::guid::Guid;
use crate::Error;
use safe_read::le_u64;

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
    /// The volume serial (FAT `BS_VolID` / exFAT / NTFS), from `forensicnomicon::volume_serial`.
    /// A volume property; populated by the forensic analyser from the partition's first sector
    /// (`None` from a bare [`GptEntry::parse`], and when no serial is recognizable).
    pub volume_serial: Option<forensicnomicon::volume_serial::VolumeSerial>,
    /// BitLocker volume encryption (`forensicnomicon::volume_encryption`), populated by the
    /// forensic analyser from the first sector. `None` for a plaintext volume.
    pub encryption: Option<forensicnomicon::volume_encryption::VolumeEncryption>,
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
            first_lba: le_u64(bytes, 32),
            last_lba: le_u64(bytes, 40),
            attributes: le_u64(bytes, 48),
            name: decode_name(&bytes[NAME_OFFSET..NAME_OFFSET + NAME_LEN]),
            // Volume properties are populated by the forensic analyser (which has the reader);
            // a bare byte-parse has no first-sector access.
            volume_serial: None,
            encryption: None,
        })
    }

    /// `true` when the entry's type GUID is non-zero (an in-use partition).
    #[must_use]
    pub fn is_used(&self) -> bool {
        !self.type_guid.is_zero()
    }

    /// Human-readable name for this partition's type GUID, from the
    /// `forensicnomicon` knowledge base. `None` for an unrecognised type.
    #[must_use]
    pub fn type_name(&self) -> Option<&'static str> {
        forensicnomicon::gpt::type_name(&self.type_guid.to_string())
    }

    /// Decode the entry's attribute flags into human-readable names (bit order),
    /// e.g. `["hidden", "no-automount"]`. Uses the `forensicnomicon` knowledge base.
    #[must_use]
    pub fn attribute_names(&self) -> Vec<&'static str> {
        forensicnomicon::gpt::attribute_names(self.attributes)
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
