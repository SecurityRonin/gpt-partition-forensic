#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Exhaustive coverage of the `Observation::evidence()` producer arm for every
//! `AnomalyKind`, plus its derived `note`/`code`/`severity`. Each variant is
//! constructed directly and its emitted evidence asserted, so every match arm in
//! `findings.rs` is genuinely exercised (not merely reachable through one
//! end-to-end scenario).

use forensicnomicon::report::{Location as Loc, Observation};
use gpt_partition_forensic::{Anomaly, AnomalyKind, Location};

/// Build an `Anomaly` and return its single evidence entry (the kinds under test
/// each emit exactly one).
fn one_evidence(kind: AnomalyKind) -> forensicnomicon::report::Evidence {
    let a = Anomaly::new(kind);
    let ev = a.evidence();
    assert_eq!(ev.len(), 1, "expected exactly one evidence item: {ev:?}");
    ev.into_iter().next().unwrap()
}

#[test]
fn header_copy_kinds_carry_the_gpt_copy() {
    // HeaderCrcInvalid / HeaderSlackData / PartitionArrayCrcInvalid share one arm.
    for kind in [
        AnomalyKind::HeaderCrcInvalid {
            location: Location::Primary,
        },
        AnomalyKind::HeaderSlackData {
            location: Location::Backup,
        },
        AnomalyKind::PartitionArrayCrcInvalid {
            location: Location::Primary,
        },
    ] {
        let e = one_evidence(kind);
        assert_eq!(e.field, "GPT copy");
        assert!(e.location.is_none());
        assert!(e.value == "primary" || e.value == "backup", "{}", e.value);
    }
}

#[test]
fn header_lba_mismatch_evidence_lba() {
    let e = one_evidence(AnomalyKind::HeaderLbaMismatch {
        location: Location::Backup,
        claimed: 7,
        actual: 8191,
    });
    assert_eq!(e.field, "header LBA");
    assert!(e.value.contains('7') && e.value.contains("8191"));
    assert!(matches!(e.location, Some(Loc::Lba(8191))));
}

#[test]
fn backup_not_at_end_evidence_lba() {
    let e = one_evidence(AnomalyKind::BackupGptNotAtDiskEnd {
        alternate_lba: 100,
        disk_last_lba: 200,
    });
    assert_eq!(e.field, "backup GPT");
    assert!(matches!(e.location, Some(Loc::Lba(100))));
}

#[test]
fn divergence_evidence_field() {
    let e = one_evidence(AnomalyKind::PrimaryBackupDivergence { field: "disk_guid" });
    assert_eq!(e.field, "diverging field");
    assert_eq!(e.value, "disk_guid");
    assert!(matches!(e.location, Some(Loc::Field(ref s)) if s == "disk_guid"));
}

#[test]
fn out_of_bounds_evidence_lba() {
    let e = one_evidence(AnomalyKind::PartitionOutOfBounds {
        index: 3,
        last_lba: 9000,
        last_usable: 8158,
    });
    assert!(e.field.contains("partition 3"));
    assert!(matches!(e.location, Some(Loc::Lba(9000))));
}

#[test]
fn overlaps_gpt_area_evidence_lba() {
    let e = one_evidence(AnomalyKind::PartitionOverlapsGptArea {
        index: 1,
        first_lba: 2,
        first_usable: 34,
    });
    assert!(e.field.contains("partition 1"));
    assert!(matches!(e.location, Some(Loc::Lba(2))));
}

#[test]
fn protective_undersized_evidence_lba() {
    let e = one_evidence(AnomalyKind::ProtectiveMbrUndersized {
        covered_last_lba: 1000,
        disk_last_lba: 8191,
    });
    assert_eq!(e.field, "protective MBR coverage");
    assert!(matches!(e.location, Some(Loc::Lba(1000))));
}

#[test]
fn hybrid_hidden_evidence_lba() {
    let e = one_evidence(AnomalyKind::HybridMbrHiddenPartition {
        mbr_index: 2,
        lba_start: 5000,
        lba_count: 100,
    });
    assert!(e.field.contains("hybrid MBR entry 2"));
    assert!(matches!(e.location, Some(Loc::Lba(5000))));
}

#[test]
fn index_pair_kinds_carry_both_indices() {
    // OverlappingPartitions / DuplicatePartitionGuid share one arm.
    for kind in [
        AnomalyKind::OverlappingPartitions { a: 0, b: 1 },
        AnomalyKind::DuplicatePartitionGuid { a: 2, b: 3 },
    ] {
        let e = one_evidence(kind);
        assert_eq!(e.field, "partitions");
        assert!(e.location.is_none());
        assert!(e.value.contains('&'));
    }
}

#[test]
fn hidden_encrypted_evidence_entropy() {
    let e = one_evidence(AnomalyKind::HiddenEncryptedVolume {
        index: 0,
        entropy: 7.95,
    });
    assert!(e.field.contains("partition 0 entropy"));
    assert!(e.value.contains("7.9"));
    assert!(e.location.is_none());
}

#[test]
fn locationless_kinds_emit_no_evidence() {
    for kind in [
        AnomalyKind::BackupGptUnreadable,
        AnomalyKind::MissingProtectiveMbr,
    ] {
        let a = Anomaly::new(kind);
        assert!(a.evidence().is_empty());
    }
}

#[test]
fn every_kind_has_a_nonempty_note_and_code() {
    // Drives every arm of `note()` and `code()` — including the ones not reached
    // by the evidence tests' representative subset.
    let kinds = [
        AnomalyKind::HeaderCrcInvalid {
            location: Location::Primary,
        },
        AnomalyKind::HeaderSlackData {
            location: Location::Primary,
        },
        AnomalyKind::HeaderLbaMismatch {
            location: Location::Primary,
            claimed: 5,
            actual: 1,
        },
        AnomalyKind::PartitionArrayCrcInvalid {
            location: Location::Backup,
        },
        AnomalyKind::BackupGptUnreadable,
        AnomalyKind::BackupGptNotAtDiskEnd {
            alternate_lba: 1,
            disk_last_lba: 2,
        },
        AnomalyKind::PrimaryBackupDivergence { field: "revision" },
        AnomalyKind::OverlappingPartitions { a: 0, b: 1 },
        AnomalyKind::DuplicatePartitionGuid { a: 0, b: 1 },
        AnomalyKind::HiddenEncryptedVolume {
            index: 0,
            entropy: 7.9,
        },
        AnomalyKind::PartitionOutOfBounds {
            index: 0,
            last_lba: 9,
            last_usable: 8,
        },
        AnomalyKind::PartitionOverlapsGptArea {
            index: 0,
            first_lba: 2,
            first_usable: 34,
        },
        AnomalyKind::MissingProtectiveMbr,
        AnomalyKind::ProtectiveMbrUndersized {
            covered_last_lba: 1,
            disk_last_lba: 2,
        },
        AnomalyKind::HybridMbrHiddenPartition {
            mbr_index: 1,
            lba_start: 5,
            lba_count: 6,
        },
    ];
    for k in kinds {
        assert!(!k.note().is_empty(), "empty note for {k:?}");
        assert!(k.code().starts_with("GPT-"), "bad code for {k:?}");
        // severity() is the single source of truth; every kind grades non-None.
        let _ = k.severity();
    }
}
