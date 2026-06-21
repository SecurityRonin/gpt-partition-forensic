//! Real-data differential validation against independent cross-tool oracles.
//!
//! The fixture `tests/data/gpt_real_3part.img` is a real GPT disk image minted
//! with `sgdisk` (GPT fdisk 1.0.10). Its layout was independently re-decoded by
//! **The Sleuth Kit `mmls` 4.12.1** — a wholly separate codebase from both this
//! crate and sgdisk — confirming the partition offsets and lengths below. The
//! per-partition type/unique GUIDs were captured from `sgdisk -i N`.
//!
//! The values asserted here are the ANSWER KEY copied from the actual oracle
//! output, NOT computed from this crate. This lifts the GPT structural layer
//! from Tier 3 (self-authored fixtures) to Tier 1 (independent oracle on real
//! bytes). See `docs/validation.md` and `tests/data/README.md` for provenance
//! (verbatim mint commands, tool versions, MD5).
//!
//! mmls oracle output (512-byte sectors), inclusive [Start, End]:
//!   004:  000   0000002048   0000006143   0000004096   BASICDATA
//!   005:  001   0000006144   0000010239   0000004096   LINUXFS
//!   006:  002   0000010240   0000012287   0000002048   EFISYSTEM

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use gpt_partition_forensic::analyse;

const IMG: &[u8] = include_bytes!("../../tests/data/gpt_real_3part.img");

/// One partition's ground truth, captured verbatim from the oracles.
struct OraclePart {
    /// first/last LBA (inclusive) — confirmed by mmls AND sgdisk.
    first_lba: u64,
    last_lba: u64,
    /// type GUID — from `sgdisk -i N` ("Partition GUID code").
    type_guid: &'static str,
    /// unique GUID — from `sgdisk -i N` ("Partition unique GUID").
    unique_guid: &'static str,
    /// partition name — from mmls Description / `sgdisk -i N`.
    name: &'static str,
    /// type name our fleet KNOWLEDGE table is expected to resolve (secondary;
    /// the type GUID string above is the independent load-bearing check).
    type_name: &'static str,
}

/// The independent answer key. mmls supplies offsets/lengths; sgdisk -i supplies
/// the GUID details mmls does not print. NEITHER is this crate.
const ORACLE: [OraclePart; 3] = [
    OraclePart {
        first_lba: 2048,
        last_lba: 6143,
        type_guid: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
        unique_guid: "11111111-2222-3333-4444-555555555501",
        name: "BASICDATA",
        type_name: "Microsoft Basic Data",
    },
    OraclePart {
        first_lba: 6144,
        last_lba: 10239,
        type_guid: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
        unique_guid: "11111111-2222-3333-4444-555555555502",
        name: "LINUXFS",
        type_name: "Linux filesystem data",
    },
    OraclePart {
        first_lba: 10240,
        last_lba: 12287,
        type_guid: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        unique_guid: "11111111-2222-3333-4444-555555555503",
        name: "EFISYSTEM",
        type_name: "EFI System Partition",
    },
];

/// Disk GUID set at mint time and echoed by `sgdisk -p` ("Disk identifier").
const ORACLE_DISK_GUID: &str = "A1A2A3A4-B1B2-C1C2-D1D2-E1E2E3E4E5E6";

#[test]
fn real_gpt_partition_layout_matches_mmls_sgdisk_oracle() {
    let mut cur = Cursor::new(IMG);
    let analysis = analyse(&mut cur, IMG.len() as u64).expect("real GPT must parse");

    // 512-byte logical sectors (mmls: "Units are in 512-byte sectors").
    assert_eq!(analysis.sector_size, 512, "sector size vs oracle");

    // Disk GUID — independent: sgdisk -p reported it.
    assert_eq!(
        analysis.disk_guid.to_string(),
        ORACLE_DISK_GUID,
        "disk GUID vs sgdisk"
    );

    // Exactly the three partitions both oracles enumerate.
    assert_eq!(
        analysis.partitions.len(),
        ORACLE.len(),
        "partition count vs mmls/sgdisk"
    );

    for (i, (got, want)) in analysis.partitions.iter().zip(ORACLE.iter()).enumerate() {
        assert_eq!(
            got.first_lba, want.first_lba,
            "partition {i} first_lba: crate={} oracle={}",
            got.first_lba, want.first_lba
        );
        assert_eq!(
            got.last_lba, want.last_lba,
            "partition {i} last_lba: crate={} oracle={}",
            got.last_lba, want.last_lba
        );
        assert_eq!(
            got.type_guid.to_string(),
            want.type_guid,
            "partition {i} type GUID vs sgdisk -i"
        );
        assert_eq!(
            got.unique_guid.to_string(),
            want.unique_guid,
            "partition {i} unique GUID vs sgdisk -i"
        );
        assert_eq!(got.name, want.name, "partition {i} name vs oracle");
        assert_eq!(
            got.type_name(),
            Some(want.type_name),
            "partition {i} resolved type name (fleet table)"
        );
    }

    // A clean, well-formed disk minted by sgdisk must produce no anomalies:
    // primary/backup reconcile, CRCs valid, no overlaps. Real-data confirmation
    // that the happy path is silent.
    assert!(
        analysis.anomalies.is_empty(),
        "clean sgdisk-minted disk should be anomaly-free, got: {:?}",
        analysis.anomalies
    );

    // Backup GPT must be present and readable (the whole 8 MiB image, with the
    // backup table at the end, is committed).
    assert!(analysis.backup.is_some(), "backup GPT should be readable");
}
