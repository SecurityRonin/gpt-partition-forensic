#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Minimal legacy/protective MBR partition-entry reader (LBA 0).
//!
//! gpt-forensic reads just the four 16-byte MBR partition entries so it can
//! reconcile the MBR's view of the disk against the GPT — *without* depending on
//! the full mbr-forensic engine. This keeps the cross-MBR↔GPT examination
//! available to standalone gpt-forensic consumers.

use gpt_partition_forensic::mbr::{parse_mbr_entries, MbrPartitionRecord, PROTECTIVE_TYPE};

fn raw_entry(status: u8, type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0] = status;
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

fn sector_with(entries: &[(usize, [u8; 16])]) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[510] = 0x55;
    s[511] = 0xAA;
    for (slot, e) in entries {
        let off = 446 + slot * 16;
        s[off..off + 16].copy_from_slice(e);
    }
    s
}

#[test]
fn parses_four_entries() {
    let s = sector_with(&[
        (0, raw_entry(0x00, PROTECTIVE_TYPE, 1, 8191)),
        (1, raw_entry(0x80, 0x07, 2048, 1000)),
    ]);
    let recs = parse_mbr_entries(&s);
    assert_eq!(recs.len(), 4);

    let p: &MbrPartitionRecord = &recs[0];
    assert!(p.is_protective());
    assert!(!p.is_empty());
    assert_eq!(p.lba_start, 1);
    assert_eq!(p.lba_count, 8191);
    assert_eq!(p.lba_end(), 8191); // 1 + 8191 - 1

    assert!(!recs[1].is_protective());
    assert_eq!(recs[1].type_code, 0x07);
    assert_eq!(recs[1].lba_start, 2048);

    assert!(recs[2].is_empty());
    assert!(recs[3].is_empty());
}

#[test]
fn protective_constant_is_ee() {
    assert_eq!(PROTECTIVE_TYPE, 0xEE);
}

#[test]
fn short_sector_yields_empty_records() {
    // Defensive: a too-short buffer must not panic.
    let recs = parse_mbr_entries(&[0u8; 16]);
    assert!(recs.iter().all(MbrPartitionRecord::is_empty));
}
