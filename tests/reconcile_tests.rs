//! MBR ↔ GPT reconciliation (available to standalone gpt-forensic consumers).
//!
//! Reconciling the legacy MBR's view of the disk against the GPT catches the
//! strongest hiding tricks: a missing/undersized protective MBR, and hybrid-MBR
//! entries that expose partitions the GPT does not list (legacy-visible,
//! GPT-invisible).
#![allow(clippy::similar_names)]

use gpt_forensic::{analyse, crc32::checksum, findings::AnomalyKind, mbr::PROTECTIVE_TYPE};
use std::io::Cursor;

const SECTORS: u64 = 8192;
const NUM: u32 = 128;
const ESIZE: u32 = 128;
const ARRAY_SECTORS: u64 = 32;
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

fn entry_bytes(first: u64, last: u64) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&ESP_TYPE);
    // Unique GUID derived from `first` so each entry's is distinct.
    e[16..24].copy_from_slice(&first.to_le_bytes());
    e[24] = 0x22;
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    e
}

fn header_sector(my: u64, alt: u64, elba: u64, fu: u64, lu: u64, acrc: u32) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0..8].copy_from_slice(b"EFI PART");
    s[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    s[12..16].copy_from_slice(&92u32.to_le_bytes());
    s[24..32].copy_from_slice(&my.to_le_bytes());
    s[32..40].copy_from_slice(&alt.to_le_bytes());
    s[40..48].copy_from_slice(&fu.to_le_bytes());
    s[48..56].copy_from_slice(&lu.to_le_bytes());
    s[56..72].copy_from_slice(&[0x11; 16]);
    s[72..80].copy_from_slice(&elba.to_le_bytes());
    s[80..84].copy_from_slice(&NUM.to_le_bytes());
    s[84..88].copy_from_slice(&ESIZE.to_le_bytes());
    s[88..92].copy_from_slice(&acrc.to_le_bytes());
    let crc = checksum(&s[0..92]);
    s[16..20].copy_from_slice(&crc.to_le_bytes());
    s
}

/// Build a GPT disk with a caller-specified MBR (`slot`, `type`, `lba_start`,
/// `lba_count`) and GPT partitions (`first_lba`, `last_lba`).
fn build(mbr: &[(usize, u8, u32, u32)], gpt: &[(u64, u64)]) -> Vec<u8> {
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    for (slot, ty, start, count) in mbr {
        let off = 446 + slot * 16;
        disk[off + 4] = *ty;
        disk[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
        disk[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
    }

    let mut array = vec![0u8; (NUM as usize) * (ESIZE as usize)];
    for (i, (first, last)) in gpt.iter().enumerate() {
        array[i * 128..i * 128 + 128].copy_from_slice(&entry_bytes(*first, *last));
    }
    let acrc = checksum(&array);
    let fu = 2 + ARRAY_SECTORS;
    let bal = SECTORS - 1 - ARRAY_SECTORS;
    let lu = bal - 1;
    let bhl = SECTORS - 1;
    disk[512..1024].copy_from_slice(&header_sector(1, bhl, 2, fu, lu, acrc));
    disk[1024..1024 + array.len()].copy_from_slice(&array);
    let baoff = (bal * 512) as usize;
    disk[baoff..baoff + array.len()].copy_from_slice(&array);
    let bhoff = (bhl * 512) as usize;
    disk[bhoff..bhoff + 512].copy_from_slice(&header_sector(bhl, 1, bal, fu, lu, acrc));
    disk
}

fn kinds(disk: Vec<u8>) -> Vec<AnomalyKind> {
    analyse(&mut Cursor::new(disk), SECTORS * 512)
        .unwrap()
        .anomalies
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

#[test]
fn proper_protective_mbr_is_clean() {
    // Single 0xEE spanning the whole disk, GPT partition present → no recon anomaly.
    let k = kinds(build(
        &[(0, PROTECTIVE_TYPE, 1, (SECTORS - 1) as u32)],
        &[(34, 2047)],
    ));
    assert!(
        !k.iter().any(|a| matches!(
            a,
            AnomalyKind::MissingProtectiveMbr
                | AnomalyKind::ProtectiveMbrUndersized { .. }
                | AnomalyKind::HybridMbrHiddenPartition { .. }
        )),
        "got {k:?}"
    );
}

#[test]
fn missing_protective_mbr_flagged() {
    // GPT present but no 0xEE entry in the MBR.
    let k = kinds(build(&[], &[(34, 2047)]));
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::MissingProtectiveMbr)),
        "got {k:?}"
    );
}

#[test]
fn undersized_protective_mbr_flagged() {
    // 0xEE covers only LBA 1..=1000 of an 8192-sector disk.
    let k = kinds(build(&[(0, PROTECTIVE_TYPE, 1, 1000)], &[(34, 2047)]));
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::ProtectiveMbrUndersized { .. })),
        "got {k:?}"
    );
}

#[test]
fn hybrid_hidden_partition_flagged() {
    // 0xEE + a hybrid 0x83 entry at LBA 5000 that matches NO GPT partition.
    let k = kinds(build(
        &[
            (0, PROTECTIVE_TYPE, 1, (SECTORS - 1) as u32),
            (1, 0x83, 5000, 100),
        ],
        &[(34, 2047)],
    ));
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::HybridMbrHiddenPartition { .. })),
        "got {k:?}"
    );
}

#[test]
fn partition_before_first_usable_flagged() {
    // A GPT partition at LBA 2 sits on the entry-array region (first_usable=34).
    let k = kinds(build(
        &[(0, PROTECTIVE_TYPE, 1, (SECTORS - 1) as u32)],
        &[(2, 30)],
    ));
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::PartitionOverlapsGptArea { .. })),
        "got {k:?}"
    );
}

#[test]
fn hybrid_entry_overlapping_gpt_not_hidden() {
    // 0xEE + a hybrid entry that overlaps the GPT partition → not "hidden".
    let k = kinds(build(
        &[
            (0, PROTECTIVE_TYPE, 1, (SECTORS - 1) as u32),
            (1, 0x07, 34, 2014),
        ],
        &[(34, 2047)],
    ));
    assert!(
        !k.iter()
            .any(|a| matches!(a, AnomalyKind::HybridMbrHiddenPartition { .. })),
        "got {k:?}"
    );
}
