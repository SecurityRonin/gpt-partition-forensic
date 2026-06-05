//! 4Kn (4096-byte logical sector) GPT support via auto-detection.
#![allow(clippy::similar_names)]

use gpt_forensic::{analyse, crc32::checksum};
use std::io::Cursor;

const SS: usize = 4096; // 4Kn logical sector
const SECTORS: u64 = 64;
const NUM: u32 = 128;
const ESIZE: u32 = 128;
const ARRAY_SECTORS: u64 = (NUM as u64 * ESIZE as u64) / SS as u64; // 16384/4096 = 4
const LINUX_TYPE: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

fn entry(first: u64, last: u64) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&LINUX_TYPE);
    e[16..24].copy_from_slice(&first.to_le_bytes()); // distinct unique GUID
    e[24] = 0x33;
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    e
}

fn header(my: u64, alt: u64, elba: u64, fu: u64, lu: u64, acrc: u32) -> [u8; 512] {
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

/// A spec-correct GPT disk with 4096-byte logical sectors.
fn build_4kn() -> Vec<u8> {
    let mut disk = vec![0u8; SECTORS as usize * SS];
    // Protective MBR (first 512 bytes of sector 0).
    disk[450] = 0xEE;
    disk[454..458].copy_from_slice(&1u32.to_le_bytes());
    disk[458..462].copy_from_slice(&((SECTORS - 1) as u32).to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;

    let mut array = vec![0u8; (NUM as usize) * (ESIZE as usize)];
    let fu = 2 + ARRAY_SECTORS; // 6
    array[0..128].copy_from_slice(&entry(fu, fu + 10));
    let acrc = checksum(&array);
    let bal = SECTORS - 1 - ARRAY_SECTORS; // 59
    let lu = bal - 1; // 58
    let bhl = SECTORS - 1; // 63

    disk[SS..SS + 512].copy_from_slice(&header(1, bhl, 2, fu, lu, acrc)); // LBA 1 = byte 4096
    let aoff = 2 * SS;
    disk[aoff..aoff + array.len()].copy_from_slice(&array); // LBA 2 = byte 8192
    let baoff = bal as usize * SS;
    disk[baoff..baoff + array.len()].copy_from_slice(&array);
    let bhoff = bhl as usize * SS;
    disk[bhoff..bhoff + 512].copy_from_slice(&header(bhl, 1, bal, fu, lu, acrc));
    disk
}

#[test]
fn forced_sector_size_overrides_detection() {
    use gpt_forensic::{analyse_with_options, AnalyseOptions};
    let disk = build_4kn();
    // Forcing 512 on a 4Kn disk → the header at byte 512 is zero → error.
    let forced_512 = AnalyseOptions {
        sector_size: Some(512),
    };
    assert!(
        analyse_with_options(&mut Cursor::new(&disk), SECTORS * SS as u64, forced_512).is_err()
    );
    // Forcing 4096 parses correctly.
    let forced_4k = AnalyseOptions {
        sector_size: Some(4096),
    };
    let a = analyse_with_options(&mut Cursor::new(disk), SECTORS * SS as u64, forced_4k).unwrap();
    assert_eq!(a.sector_size, 4096);
}

#[test]
fn detects_4kn_and_parses_clean() {
    let a = analyse(&mut Cursor::new(build_4kn()), SECTORS * SS as u64).unwrap();
    assert_eq!(a.sector_size, 4096, "should auto-detect 4Kn");
    assert_eq!(a.partitions.len(), 1);
    assert!(
        a.anomalies.is_empty(),
        "well-formed 4Kn GPT must be clean, got: {:?}",
        a.anomalies.iter().map(|x| x.code).collect::<Vec<_>>()
    );
}
