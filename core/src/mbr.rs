//! Minimal legacy/protective MBR partition-entry reader (LBA 0).
//!
//! gpt-forensic parses *only* the four 16-byte MBR partition entries — enough to
//! reconcile the MBR's view of the disk against the GPT (protective coverage,
//! hybrid-MBR partitions hidden from the GPT). It deliberately does **not**
//! reimplement the full forensic MBR analysis (that is `mbr-forensic`'s job);
//! keeping this minimal avoids a dependency cycle and keeps the MBR↔GPT
//! cross-examination available to standalone gpt-forensic consumers.

/// Partition type code of a GPT protective / hybrid MBR entry.
pub const PROTECTIVE_TYPE: u8 = 0xEE;
/// Byte offset of the partition table within the MBR sector.
const PARTITION_TABLE_OFFSET: usize = 446;
/// Size of one MBR partition entry, in bytes.
const ENTRY_SIZE: usize = 16;

/// One decoded MBR partition entry (the fields relevant to GPT reconciliation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MbrPartitionRecord {
    /// Slot index in the MBR table (0–3).
    pub index: usize,
    /// Status byte (`0x80` = bootable, `0x00` = inactive).
    pub status: u8,
    /// Partition type code.
    pub type_code: u8,
    /// First LBA of the partition.
    pub lba_start: u32,
    /// Number of sectors in the partition.
    pub lba_count: u32,
}

impl MbrPartitionRecord {
    /// `true` when the slot is unused (type 0x00 and no extent).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.type_code == 0x00 && self.lba_start == 0 && self.lba_count == 0
    }

    /// `true` when this is a GPT protective / hybrid entry (type 0xEE).
    #[must_use]
    pub fn is_protective(&self) -> bool {
        self.type_code == PROTECTIVE_TYPE
    }

    /// Inclusive last LBA of this partition, saturating on overflow.
    #[must_use]
    pub fn lba_end(&self) -> u64 {
        u64::from(self.lba_start)
            .saturating_add(u64::from(self.lba_count))
            .saturating_sub(1)
    }
}

/// Parse the four MBR partition entries from `sector` (LBA 0).
///
/// A buffer too short to hold an entry yields an empty record for that slot;
/// this never panics.
#[must_use]
pub fn parse_mbr_entries(sector: &[u8]) -> [MbrPartitionRecord; 4] {
    core::array::from_fn(|index| {
        let off = PARTITION_TABLE_OFFSET + index * ENTRY_SIZE;
        match sector.get(off..off + ENTRY_SIZE) {
            Some(b) => MbrPartitionRecord {
                index,
                status: b[0],
                type_code: b[4],
                lba_start: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
                lba_count: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            },
            None => MbrPartitionRecord {
                index,
                status: 0,
                type_code: 0,
                lba_start: 0,
                lba_count: 0,
            },
        }
    })
}
