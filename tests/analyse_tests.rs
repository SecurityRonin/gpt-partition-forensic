//! End-to-end GPT analysis: CRC integrity, primary/backup divergence, overlaps.

use gpt_forensic::{analyse, crc32::checksum, findings::AnomalyKind, Location};
use std::io::Cursor;

const SECTORS: u64 = 8192;
const NUM: u32 = 128;
const ESIZE: u32 = 128;
const ARRAY_SECTORS: u64 = (NUM as u64 * ESIZE as u64) / 512; // 32
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

fn entry_bytes(type_guid: [u8; 16], first: u64, last: u64, name: &str) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&type_guid);
    e[16..32].copy_from_slice(&[0x22; 16]);
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    for (i, u) in name.encode_utf16().enumerate() {
        e[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    e
}

#[allow(clippy::too_many_arguments)]
fn header_sector(
    my_lba: u64,
    alt_lba: u64,
    entry_lba: u64,
    first_usable: u64,
    last_usable: u64,
    array_crc: u32,
) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0..8].copy_from_slice(b"EFI PART");
    s[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    s[12..16].copy_from_slice(&92u32.to_le_bytes());
    s[24..32].copy_from_slice(&my_lba.to_le_bytes());
    s[32..40].copy_from_slice(&alt_lba.to_le_bytes());
    s[40..48].copy_from_slice(&first_usable.to_le_bytes());
    s[48..56].copy_from_slice(&last_usable.to_le_bytes());
    s[56..72].copy_from_slice(&[0x11; 16]); // disk GUID
    s[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    s[80..84].copy_from_slice(&NUM.to_le_bytes());
    s[84..88].copy_from_slice(&ESIZE.to_le_bytes());
    s[88..92].copy_from_slice(&array_crc.to_le_bytes());
    let crc = checksum(&s[0..92]);
    s[16..20].copy_from_slice(&crc.to_le_bytes());
    s
}

/// Build a spec-correct GPT disk with two partitions (ESP + data).
fn build_gpt_disk() -> Vec<u8> {
    let mut disk = vec![0u8; (SECTORS * 512) as usize];

    // Partition entry array (shared by primary + backup).
    let mut array = vec![0u8; (NUM as usize) * (ESIZE as usize)];
    array[0..128].copy_from_slice(&entry_bytes(ESP_TYPE, 34, 2047, "EFI System"));
    array[128..256].copy_from_slice(&entry_bytes(ESP_TYPE, 2048, 4095, "Data"));
    let array_crc = checksum(&array);

    let first_usable = 2 + ARRAY_SECTORS; // 34
    let backup_array_lba = SECTORS - 1 - ARRAY_SECTORS; // 8159
    let last_usable = backup_array_lba - 1; // 8158
    let backup_hdr_lba = SECTORS - 1; // 8191

    // Primary header @ LBA 1, array @ LBA 2.
    let ph = header_sector(1, backup_hdr_lba, 2, first_usable, last_usable, array_crc);
    disk[512..1024].copy_from_slice(&ph);
    let aoff = 2 * 512;
    disk[aoff..aoff + array.len()].copy_from_slice(&array);

    // Backup array + header at end of disk.
    let baoff = (backup_array_lba * 512) as usize;
    disk[baoff..baoff + array.len()].copy_from_slice(&array);
    let bh = header_sector(
        backup_hdr_lba,
        1,
        backup_array_lba,
        first_usable,
        last_usable,
        array_crc,
    );
    let bhoff = (backup_hdr_lba * 512) as usize;
    disk[bhoff..bhoff + 512].copy_from_slice(&bh);

    disk
}

fn kinds(disk: &[u8]) -> Vec<AnomalyKind> {
    analyse(&mut Cursor::new(disk.to_vec()), SECTORS * 512)
        .unwrap()
        .anomalies
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

#[test]
fn well_formed_gpt_is_clean() {
    let disk = build_gpt_disk();
    let a = analyse(&mut Cursor::new(disk), SECTORS * 512).unwrap();
    assert_eq!(a.partitions.len(), 2, "two partitions");
    assert_eq!(a.partitions[0].name, "EFI System");
    assert!(
        a.anomalies.is_empty(),
        "well-formed GPT must be clean, got: {:?}",
        a.anomalies.iter().map(|x| x.code).collect::<Vec<_>>()
    );
}

#[test]
fn corrupt_primary_header_crc_flagged() {
    let mut disk = build_gpt_disk();
    disk[512 + 24] ^= 0xFF; // tamper my_lba in primary header
    let k = kinds(&disk);
    assert!(k.iter().any(|a| matches!(
        a,
        AnomalyKind::HeaderCrcInvalid { location: Location::Primary }
    )), "got {k:?}");
}

#[test]
fn corrupt_primary_array_crc_flagged() {
    let mut disk = build_gpt_disk();
    disk[2 * 512 + 40] ^= 0xFF; // tamper an entry's last_lba → array CRC breaks
    let k = kinds(&disk);
    assert!(k.iter().any(|a| matches!(
        a,
        AnomalyKind::PartitionArrayCrcInvalid { location: Location::Primary }
    )), "got {k:?}");
}

#[test]
fn missing_backup_flagged() {
    let mut disk = build_gpt_disk();
    let bhoff = ((SECTORS - 1) * 512) as usize;
    disk[bhoff..bhoff + 8].fill(0); // wipe backup signature
    let k = kinds(&disk);
    assert!(
        k.iter().any(|a| matches!(a, AnomalyKind::BackupGptUnreadable)),
        "got {k:?}"
    );
}

#[test]
fn primary_backup_divergence_flagged() {
    // Change the backup's disk GUID and re-seal its own CRC so it self-validates
    // but diverges from the primary.
    let mut disk = build_gpt_disk();
    let bhoff = ((SECTORS - 1) * 512) as usize;
    disk[bhoff + 56..bhoff + 72].copy_from_slice(&[0x99; 16]); // different disk GUID
    let new_crc = checksum(&{
        let mut h = disk[bhoff..bhoff + 92].to_vec();
        h[16..20].fill(0);
        h
    });
    disk[bhoff + 16..bhoff + 20].copy_from_slice(&new_crc.to_le_bytes());
    let k = kinds(&disk);
    assert!(
        k.iter().any(|a| matches!(a, AnomalyKind::PrimaryBackupDivergence { .. })),
        "got {k:?}"
    );
}

#[test]
fn overlapping_partitions_flagged() {
    // Rebuild with overlapping entries and matching CRCs.
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    let mut array = vec![0u8; (NUM as usize) * (ESIZE as usize)];
    array[0..128].copy_from_slice(&entry_bytes(ESP_TYPE, 34, 3000, "A"));
    array[128..256].copy_from_slice(&entry_bytes(ESP_TYPE, 2000, 4095, "B")); // overlaps A
    let array_crc = checksum(&array);
    let first_usable = 2 + ARRAY_SECTORS;
    let backup_array_lba = SECTORS - 1 - ARRAY_SECTORS;
    let last_usable = backup_array_lba - 1;
    let backup_hdr_lba = SECTORS - 1;
    disk[512..1024].copy_from_slice(&header_sector(
        1, backup_hdr_lba, 2, first_usable, last_usable, array_crc,
    ));
    disk[1024..1024 + array.len()].copy_from_slice(&array);
    let baoff = (backup_array_lba * 512) as usize;
    disk[baoff..baoff + array.len()].copy_from_slice(&array);
    let bhoff = (backup_hdr_lba * 512) as usize;
    disk[bhoff..bhoff + 512].copy_from_slice(&header_sector(
        backup_hdr_lba, 1, backup_array_lba, first_usable, last_usable, array_crc,
    ));
    let k = kinds(&disk);
    assert!(
        k.iter().any(|a| matches!(a, AnomalyKind::OverlappingPartitions { .. })),
        "got {k:?}"
    );
}
