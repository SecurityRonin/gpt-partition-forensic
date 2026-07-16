#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::similar_names)]
//! Branch coverage for the `analyse` orchestration paths not reached by the
//! happy-path / single-anomaly end-to-end tests: backup-header CRC/LBA anomalies,
//! an unreadable-because-out-of-range backup, encrypted-volume skips (LUKS type /
//! unreadable first sector), a partition past the usable range, the
//! `u32::MAX`-covering protective MBR, and the no-GPT sector-size fallback.

use gpt_partition_forensic::{
    analyse, analyse_with_options, crc32::checksum, findings::AnomalyKind, AnalyseOptions, Error,
    Location,
};
use std::io::Cursor;

const SECTORS: u64 = 8192;
const NUM: u32 = 128;
const ESIZE: u32 = 128;
const ARRAY_SECTORS: u64 = (NUM as u64 * ESIZE as u64) / 512; // 32
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
// Linux LUKS (CA7D7CCB-63ED-4C53-861C-1742536059CC), mixed-endian on-disk.
const LUKS_TYPE: [u8; 16] = [
    0xCB, 0x7C, 0x7D, 0xCA, 0xED, 0x63, 0x53, 0x4C, 0x86, 0x1C, 0x17, 0x42, 0x53, 0x60, 0x59, 0xCC,
];

fn entry_bytes(type_guid: [u8; 16], first: u64, last: u64) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&type_guid);
    e[16..24].copy_from_slice(&first.to_le_bytes()); // distinct unique GUID
    e[24] = 0x22;
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    e
}

#[allow(clippy::too_many_arguments)]
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

/// A well-formed protective-MBR GPT disk over `gpt` partitions, with a
/// caller-supplied MBR (`slot`, `type`, `lba_start`, `lba_count`).
fn build(mbr: &[(usize, u8, u32, u32)], gpt: &[([u8; 16], u64, u64)]) -> Vec<u8> {
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
    for (i, (ty, first, last)) in gpt.iter().enumerate() {
        array[i * 128..i * 128 + 128].copy_from_slice(&entry_bytes(*ty, *first, *last));
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

fn kinds(disk: Vec<u8>, disk_bytes: u64) -> Vec<AnomalyKind> {
    analyse(&mut Cursor::new(disk), disk_bytes)
        .unwrap()
        .anomalies
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

#[test]
fn no_gpt_signature_reports_bad_signature() {
    // detect_sector_size finds "EFI PART" at neither 512 nor 4096 → falls back to
    // 512, and the primary parse then fails with BadSignature.
    let disk = vec![0u8; (SECTORS * 512) as usize];
    assert!(matches!(
        analyse(&mut Cursor::new(disk), SECTORS * 512),
        Err(Error::BadSignature)
    ));
}

#[test]
fn backup_out_of_range_is_unreadable() {
    // The primary's alternate_lba points past the end of the supplied image, so
    // the backup read_sector fails (EOF) rather than parsing a bad header.
    let mut disk = build(
        &[(0, 0xEE, 1, (SECTORS - 1) as u32)],
        &[(ESP_TYPE, 34, 2047)],
    );
    // Truncate the image to just past the primary array — the backup at LBA 8191
    // no longer exists in the byte stream.
    disk.truncate(64 * 512);
    let k = kinds(disk, SECTORS * 512);
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::BackupGptUnreadable)),
        "got {k:?}"
    );
}

#[test]
fn backup_header_crc_invalid_flagged() {
    // Tamper a CRC-covered byte of the BACKUP header only → its self-CRC fails
    // while the primary stays valid.
    let mut disk = build(
        &[(0, 0xEE, 1, (SECTORS - 1) as u32)],
        &[(ESP_TYPE, 34, 2047)],
    );
    let bhoff = ((SECTORS - 1) * 512) as usize;
    disk[bhoff + 40] ^= 0xFF; // flip first_usable_lba in the backup header
    let k = kinds(disk, SECTORS * 512);
    assert!(
        k.iter().any(|a| matches!(
            a,
            AnomalyKind::HeaderCrcInvalid {
                location: Location::Backup
            }
        )),
        "got {k:?}"
    );
}

#[test]
fn backup_header_lba_mismatch_flagged() {
    // Rewrite the backup header so my_lba != alternate_lba, re-sealing its CRC so
    // it self-validates but lies about its location.
    let mut disk = build(
        &[(0, 0xEE, 1, (SECTORS - 1) as u32)],
        &[(ESP_TYPE, 34, 2047)],
    );
    let bhoff = ((SECTORS - 1) * 512) as usize;
    disk[bhoff + 24..bhoff + 32].copy_from_slice(&999u64.to_le_bytes()); // wrong my_lba
    let new_crc = checksum(&{
        let mut h = disk[bhoff..bhoff + 92].to_vec();
        h[16..20].fill(0);
        h
    });
    disk[bhoff + 16..bhoff + 20].copy_from_slice(&new_crc.to_le_bytes());
    let k = kinds(disk, SECTORS * 512);
    assert!(
        k.iter().any(|a| matches!(
            a,
            AnomalyKind::HeaderLbaMismatch {
                location: Location::Backup,
                ..
            }
        )),
        "got {k:?}"
    );
}

#[test]
fn luks_typed_partition_is_not_flagged_encrypted() {
    // A LUKS-typed partition with high-entropy first sector is expected-opaque and
    // must be skipped by the hidden-encrypted-volume check.
    let mut disk = build(
        &[(0, 0xEE, 1, (SECTORS - 1) as u32)],
        &[(LUKS_TYPE, 34, 2047)],
    );
    let off = 34 * 512;
    for (i, b) in disk[off..off + 512].iter_mut().enumerate() {
        *b = (i % 256) as u8; // full byte ramp → entropy ~8
    }
    let k = kinds(disk, SECTORS * 512);
    assert!(
        !k.iter()
            .any(|a| matches!(a, AnomalyKind::HiddenEncryptedVolume { .. })),
        "LUKS type must be skipped; got {k:?}"
    );
}

#[test]
fn partition_past_last_usable_flagged() {
    // A partition whose last_lba is beyond last_usable (8158) → out of bounds.
    let k = kinds(
        build(
            &[(0, 0xEE, 1, (SECTORS - 1) as u32)],
            &[(ESP_TYPE, 34, 8160)],
        ),
        SECTORS * 512,
    );
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::PartitionOutOfBounds { .. })),
        "got {k:?}"
    );
}

#[test]
fn maxed_protective_mbr_is_not_undersized() {
    // A protective entry with lba_count == u32::MAX (the "spans everything"
    // convention) is exempt from the undersize check — hits the accepting arm.
    let k = kinds(
        build(&[(0, 0xEE, 1, u32::MAX)], &[(ESP_TYPE, 34, 2047)]),
        SECTORS * 512,
    );
    assert!(
        !k.iter()
            .any(|a| matches!(a, AnomalyKind::ProtectiveMbrUndersized { .. })),
        "u32::MAX-covering protective MBR must not be undersized; got {k:?}"
    );
}

#[test]
fn protective_mbr_accepted_when_disk_size_unknown() {
    // disk_size_bytes == 0: the protective entry is accepted without an undersize
    // check (the `Some(_) => {}` arm).
    let disk = build(
        &[(0, 0xEE, 1, 1000)], // deliberately undersized coverage
        &[(ESP_TYPE, 34, 2047)],
    );
    let a = analyse_with_options(&mut Cursor::new(disk), 0, AnalyseOptions::default()).unwrap();
    assert!(
        !a.anomalies
            .iter()
            .any(|x| matches!(x.kind, AnomalyKind::ProtectiveMbrUndersized { .. })),
        "no disk size → no undersize verdict"
    );
}

#[test]
fn duplicate_partition_guid_flagged_end_to_end() {
    // Two GPT entries sharing one unique GUID → DuplicatePartitionGuid through the
    // full analyse path (the collision record loop).
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[450] = 0xEE;
    disk[454..458].copy_from_slice(&1u32.to_le_bytes());
    disk[458..462].copy_from_slice(&((SECTORS - 1) as u32).to_le_bytes());

    // Build two entries with the SAME unique GUID (bytes 16..32) but distinct
    // extents, so they collide on identity without overlapping.
    let mut a = entry_bytes(ESP_TYPE, 34, 100);
    let mut b = entry_bytes(ESP_TYPE, 200, 300);
    let shared = [0x77u8; 16];
    a[16..32].copy_from_slice(&shared);
    b[16..32].copy_from_slice(&shared);

    let mut array = vec![0u8; (NUM as usize) * (ESIZE as usize)];
    array[0..128].copy_from_slice(&a);
    array[128..256].copy_from_slice(&b);
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

    let k = kinds(disk, SECTORS * 512);
    assert!(
        k.iter()
            .any(|x| matches!(x, AnomalyKind::DuplicatePartitionGuid { a: 0, b: 1 })),
        "got {k:?}"
    );
}

#[test]
fn backup_array_read_failure_is_tolerated() {
    // The backup header parses and self-validates, but its `partition_entry_lba`
    // points past the end of the image, so the backup entry-array read fails —
    // the analysis skips the array comparison without panicking.
    let mut disk = build(
        &[(0, 0xEE, 1, (SECTORS - 1) as u32)],
        &[(ESP_TYPE, 34, 2047)],
    );
    let bhoff = ((SECTORS - 1) * 512) as usize;
    // Point the backup array LBA far past the disk end, then re-seal the backup
    // header's self-CRC so it still parses as a valid header.
    disk[bhoff + 72..bhoff + 80].copy_from_slice(&(SECTORS + 10_000).to_le_bytes());
    let new_crc = checksum(&{
        let mut h = disk[bhoff..bhoff + 92].to_vec();
        h[16..20].fill(0);
        h
    });
    disk[bhoff + 16..bhoff + 20].copy_from_slice(&new_crc.to_le_bytes());
    // Completes without panic; the backup header is still parsed (Some).
    let a = analyse(&mut Cursor::new(disk), SECTORS * 512).unwrap();
    assert!(a.backup.is_some(), "backup header still parsed");
}

#[test]
fn encrypted_check_tolerates_unreadable_first_sector() {
    // A partition whose first_lba is beyond the (truncated) image: the encrypted
    // check's read_sector fails and the partition is skipped, not panicked on.
    let mut disk = build(
        &[(0, 0xEE, 1, (SECTORS - 1) as u32)],
        &[(ESP_TYPE, 7000, 8000)],
    );
    // Keep the primary GPT + backup readable but drop the partition's first
    // sector (LBA 7000) region by truncating before it.
    disk.truncate(5000 * 512);
    // Backup now unreadable too; we only assert the analysis completes without a
    // spurious encrypted-volume finding for the unreadable partition.
    let a = analyse(&mut Cursor::new(disk), SECTORS * 512).unwrap();
    assert!(
        !a.anomalies
            .iter()
            .any(|x| matches!(x.kind, AnomalyKind::HiddenEncryptedVolume { index: 0, .. })),
        "unreadable first sector must be skipped, not flagged"
    );
}
