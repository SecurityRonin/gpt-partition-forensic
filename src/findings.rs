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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AnomalyKind {
    /// A GPT header's self-CRC does not match its contents.
    HeaderCrcInvalid { location: Location },
    /// A partition entry array's CRC does not match the header's stored value.
    PartitionArrayCrcInvalid { location: Location },
    /// The backup GPT is missing or unreadable.
    BackupGptUnreadable,
    /// A header field that should match between primary and backup differs.
    PrimaryBackupDivergence { field: &'static str },
    /// Two partitions claim overlapping LBA ranges.
    OverlappingPartitions { a: usize, b: usize },
    /// A partition extends outside the header's usable LBA range.
    PartitionOutOfBounds {
        index: usize,
        last_lba: u64,
        last_usable: u64,
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
            | K::PartitionArrayCrcInvalid { .. }
            | K::BackupGptUnreadable
            | K::PrimaryBackupDivergence { .. }
            | K::PartitionOutOfBounds { .. } => Severity::High,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        use AnomalyKind as K;
        match self {
            K::HeaderCrcInvalid { .. } => "GPT-HDR-CRC",
            K::PartitionArrayCrcInvalid { .. } => "GPT-ARRAY-CRC",
            K::BackupGptUnreadable => "GPT-BACKUP-MISSING",
            K::PrimaryBackupDivergence { .. } => "GPT-DIVERGENCE",
            K::OverlappingPartitions { .. } => "GPT-PART-OVERLAP",
            K::PartitionOutOfBounds { .. } => "GPT-PART-OOB",
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
            K::PartitionArrayCrcInvalid { location } => {
                format!("{location} GPT partition-array CRC is invalid — corruption or tampering")
            }
            K::BackupGptUnreadable => {
                "Backup GPT is missing or unreadable — the disk cannot self-repair".to_string()
            }
            K::PrimaryBackupDivergence { field } => {
                format!("Primary and backup GPT headers disagree on `{field}` — possible tampering")
            }
            K::OverlappingPartitions { a, b } => {
                format!("Partitions {a} and {b} claim overlapping LBA ranges")
            }
            K::PartitionOutOfBounds {
                index,
                last_lba,
                last_usable,
            } => format!(
                "Partition {index} ends at LBA {last_lba}, beyond the usable range (last usable {last_usable})"
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
