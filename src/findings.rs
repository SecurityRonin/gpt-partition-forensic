//! GPT forensic findings: severity, anomalies, and the analysis result.
//!
//! Mirrors `mbr-forensic`'s model — every anomaly's severity, stable code, and
//! human note are derived from its [`AnomalyKind`], so they cannot drift.

use core::fmt;

use crate::entry::GptEntry;
use crate::guid::Guid;
use crate::header::GptHeader;

/// Which GPT copy a finding pertains to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Location {
    /// The primary GPT at LBA 1.
    Primary,
    /// The backup GPT at the last LBA.
    Backup,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Location::Primary => "primary",
            Location::Backup => "backup",
        })
    }
}

/// Severity of a GPT anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        })
    }
}

/// Classification of a GPT anomaly.
// `Eq` is intentionally omitted: `HiddenEncryptedVolume` carries an `f64`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AnomalyKind {
    /// A GPT header's self-CRC does not match its contents.
    HeaderCrcInvalid { location: Location },
    /// Non-zero bytes in the GPT header LBA past `header_size` — a region the
    /// UEFI spec requires to be zero and that the header CRC does not cover, so
    /// it is a CRC-invisible place to hide data.
    HeaderSlackData { location: Location },
    /// A GPT header's `my_lba` field disagrees with the LBA it was actually read
    /// from — a relocated or forged header.
    HeaderLbaMismatch {
        location: Location,
        claimed: u64,
        actual: u64,
    },
    /// A partition entry array's CRC does not match the header's stored value.
    PartitionArrayCrcInvalid { location: Location },
    /// The backup GPT is missing or unreadable.
    BackupGptUnreadable,
    /// The disk extends past the backup GPT (`alternate_lba`) — the tail region
    /// is hidden from GPT-aware tools (e.g. a disk resized without moving the GPT).
    BackupGptNotAtDiskEnd {
        alternate_lba: u64,
        disk_last_lba: u64,
    },
    /// A header field that should match between primary and backup differs.
    PrimaryBackupDivergence { field: &'static str },
    /// Two partitions claim overlapping LBA ranges.
    OverlappingPartitions { a: usize, b: usize },
    /// Two partition entries share a unique GUID — a cloned/duplicated entry.
    DuplicatePartitionGuid { a: usize, b: usize },
    /// A non-encrypted-typed partition whose content is near-maximal entropy and
    /// has no readable filesystem structure — consistent with a hidden encrypted
    /// container (`VeraCrypt` / detached LUKS).
    HiddenEncryptedVolume { index: usize, entropy: f64 },
    /// A partition extends outside the header's usable LBA range.
    PartitionOutOfBounds {
        index: usize,
        last_lba: u64,
        last_usable: u64,
    },
    /// A partition starts before `first_usable_lba` — it sits on the reserved
    /// GPT header / entry-array region (clobbering or hiding behind metadata).
    PartitionOverlapsGptArea {
        index: usize,
        first_lba: u64,
        first_usable: u64,
    },
    /// A GPT exists but the MBR has no protective (0xEE) entry guarding it —
    /// legacy tools may clobber the disk; also a tampering indicator.
    MissingProtectiveMbr,
    /// The protective (0xEE) MBR entry does not span the whole disk, leaving a
    /// tail exposed to GPT-unaware tooling.
    ProtectiveMbrUndersized {
        covered_last_lba: u64,
        disk_last_lba: u64,
    },
    /// A hybrid-MBR partition entry describes an extent that matches no GPT
    /// partition — visible to legacy tools but hidden from the GPT.
    HybridMbrHiddenPartition {
        mbr_index: usize,
        lba_start: u32,
        lba_count: u32,
    },
}

impl AnomalyKind {
    /// Severity assigned to this kind — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        use AnomalyKind as K;
        match self {
            K::OverlappingPartitions { .. } => Severity::Critical,
            K::HeaderCrcInvalid { .. }
            | K::HeaderSlackData { .. }
            | K::HeaderLbaMismatch { .. }
            | K::PartitionArrayCrcInvalid { .. }
            | K::BackupGptUnreadable
            | K::BackupGptNotAtDiskEnd { .. }
            | K::PrimaryBackupDivergence { .. }
            | K::PartitionOutOfBounds { .. }
            | K::MissingProtectiveMbr
            | K::ProtectiveMbrUndersized { .. }
            | K::HybridMbrHiddenPartition { .. }
            | K::DuplicatePartitionGuid { .. }
            | K::PartitionOverlapsGptArea { .. }
            | K::HiddenEncryptedVolume { .. } => Severity::High,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        use AnomalyKind as K;
        match self {
            K::HeaderCrcInvalid { .. } => "GPT-HDR-CRC",
            K::HeaderSlackData { .. } => "GPT-HDR-SLACK",
            K::HeaderLbaMismatch { .. } => "GPT-HDR-LBA",
            K::PartitionArrayCrcInvalid { .. } => "GPT-ARRAY-CRC",
            K::BackupGptUnreadable => "GPT-BACKUP-MISSING",
            K::BackupGptNotAtDiskEnd { .. } => "GPT-BACKUP-NOTATEND",
            K::PrimaryBackupDivergence { .. } => "GPT-DIVERGENCE",
            K::OverlappingPartitions { .. } => "GPT-PART-OVERLAP",
            K::DuplicatePartitionGuid { .. } => "GPT-PART-DUPGUID",
            K::HiddenEncryptedVolume { .. } => "GPT-PART-ENCRYPTED",
            K::PartitionOutOfBounds { .. } => "GPT-PART-OOB",
            K::PartitionOverlapsGptArea { .. } => "GPT-PART-RESERVED",
            K::MissingProtectiveMbr => "GPT-MBR-NOPROT",
            K::ProtectiveMbrUndersized { .. } => "GPT-MBR-UNDERSIZED",
            K::HybridMbrHiddenPartition { .. } => "GPT-MBR-HYBRID-HIDDEN",
        }
    }

    /// Human-readable description.
    #[must_use]
    pub fn note(&self) -> String {
        use AnomalyKind as K;
        match self {
            K::HeaderCrcInvalid { location } => {
                format!("{location} GPT header CRC is invalid — corruption or tampering")
            }
            K::HeaderSlackData { location } => format!(
                "{location} GPT header has non-zero bytes past header_size (CRC-unprotected \
                 reserved area) — possible hidden data"
            ),
            K::HeaderLbaMismatch {
                location,
                claimed,
                actual,
            } => format!(
                "{location} GPT header claims my_lba {claimed} but was read at LBA {actual} — \
                 relocated or forged header"
            ),
            K::PartitionArrayCrcInvalid { location } => {
                format!("{location} GPT partition-array CRC is invalid — corruption or tampering")
            }
            K::BackupGptUnreadable => {
                "Backup GPT is missing or unreadable — the disk cannot self-repair".to_string()
            }
            K::BackupGptNotAtDiskEnd {
                alternate_lba,
                disk_last_lba,
            } => format!(
                "Backup GPT is at LBA {alternate_lba} but the disk ends at LBA {disk_last_lba} — \
                 trailing region hidden from GPT-aware tools"
            ),
            K::PrimaryBackupDivergence { field } => {
                format!("Primary and backup GPT headers disagree on `{field}` — possible tampering")
            }
            K::OverlappingPartitions { a, b } => {
                format!("Partitions {a} and {b} claim overlapping LBA ranges")
            }
            K::DuplicatePartitionGuid { a, b } => {
                format!("Partitions {a} and {b} share a unique GUID — cloned/duplicated entry")
            }
            K::HiddenEncryptedVolume { index, entropy } => format!(
                "Partition {index} has near-maximal entropy ({entropy:.2} bits/byte) and no readable \
                 filesystem — consistent with a hidden encrypted container"
            ),
            K::PartitionOutOfBounds {
                index,
                last_lba,
                last_usable,
            } => format!(
                "Partition {index} ends at LBA {last_lba}, beyond the usable range (last usable {last_usable})"
            ),
            K::PartitionOverlapsGptArea {
                index,
                first_lba,
                first_usable,
            } => format!(
                "Partition {index} starts at LBA {first_lba}, before first usable {first_usable} — \
                 overlaps the reserved GPT metadata region"
            ),
            K::MissingProtectiveMbr => {
                "GPT present but the MBR has no protective (0xEE) entry guarding it".to_string()
            }
            K::ProtectiveMbrUndersized {
                covered_last_lba,
                disk_last_lba,
            } => format!(
                "Protective MBR (0xEE) covers only up to LBA {covered_last_lba} but the disk ends \
                 at LBA {disk_last_lba} — tail exposed to GPT-unaware tools"
            ),
            K::HybridMbrHiddenPartition {
                mbr_index,
                lba_start,
                lba_count,
            } => format!(
                "Hybrid MBR entry {mbr_index} (LBA {lba_start}, {lba_count} sectors) matches no GPT \
                 partition — legacy-visible but hidden from the GPT"
            ),
        }
    }
}

/// A single GPT anomaly with derived severity/code/note.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly {
    pub severity: Severity,
    pub code: &'static str,
    pub kind: AnomalyKind,
    pub note: String,
}

impl Anomaly {
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.note)
    }
}

/// Result of a full GPT forensic analysis.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GptAnalysis {
    /// Parsed primary GPT header.
    pub primary: GptHeader,
    /// Parsed backup GPT header, if readable.
    pub backup: Option<GptHeader>,
    /// Disk GUID (from the primary header).
    pub disk_guid: Guid,
    /// In-use partitions parsed from the primary entry array.
    pub partitions: Vec<GptEntry>,
    /// Logical sector size auto-detected from the GPT header location (512 or 4096).
    pub sector_size: u64,
    /// SHA-256 (hex) of the primary GPT header sector + entry array — a
    /// tamper-evident fingerprint of the partition table for chain-of-custody.
    pub gpt_sha256: String,
    /// All detected anomalies, in discovery order.
    pub anomalies: Vec<Anomaly>,
}

impl GptAnalysis {
    /// The highest severity among all anomalies, or `None` when clean.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.anomalies.iter().map(|a| a.severity).max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_display_includes_code_and_severity() {
        let a = Anomaly::new(AnomalyKind::BackupGptUnreadable);
        let rendered = format!("{a}");
        assert!(rendered.contains(a.code), "{rendered}");
        // Severity's own Display impl.
        assert!(!format!("{}", a.severity).is_empty());
    }

    #[test]
    fn severity_orders_info_below_critical() {
        // Ordering is what `max_severity` relies on.
        assert!(Severity::Critical > Severity::Info);
        assert_eq!(
            [Severity::Low, Severity::Critical, Severity::Medium]
                .into_iter()
                .max(),
            Some(Severity::Critical)
        );
    }
}
