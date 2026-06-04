//! Shared GPT fixture builder for the CLI tests.
//!
//! Synthesises a minimal but spec-faithful GPT disk image (512-byte sectors,
//! correct header and partition-array CRC-32s) entirely in memory, so the tests
//! need no committed binary blob. Layout of the 64-sector image:
//!
//!   LBA 0  : protective MBR (left zero — `analyse` reads LBA 1 directly)
//!   LBA 1  : primary GPT header
//!   LBA 2  : primary partition-entry array (4 × 128 B = 1 sector)
//!   LBA 62 : backup partition-entry array
//!   LBA 63 : backup GPT header
//!
//! Two partitions are populated: a Linux filesystem-data partition and an EFI
//! System Partition, both with recognised type GUIDs.

#![allow(dead_code)]

pub const SECTOR: usize = 512;
pub const SECTORS: usize = 64;

pub const DISK_GUID: &str = "12345678-1234-5678-1234-567812345678";
pub const LINUX_GUID: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
pub const EFI_GUID: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

/// Encode a canonical GUID string into its 16-byte GPT on-disk (mixed-endian)
/// form: groups 1–3 little-endian, groups 4–5 big-endian.
fn guid_bytes(s: &str) -> [u8; 16] {
    let g: Vec<&str> = s.split('-').collect();
    assert_eq!(g.len(), 5, "malformed GUID: {s}");
    let g1 = u32::from_str_radix(g[0], 16).unwrap();
    let g2 = u16::from_str_radix(g[1], 16).unwrap();
    let g3 = u16::from_str_radix(g[2], 16).unwrap();
    let g4 = u16::from_str_radix(g[3], 16).unwrap();
    let g5 = u64::from_str_radix(g[4], 16).unwrap(); // 48-bit, big-endian on disk
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&g1.to_le_bytes());
    b[4..6].copy_from_slice(&g2.to_le_bytes());
    b[6..8].copy_from_slice(&g3.to_le_bytes());
    b[8..10].copy_from_slice(&g4.to_be_bytes());
    b[10..16].copy_from_slice(&g5.to_be_bytes()[2..8]);
    b
}

/// Build one 128-byte partition entry.
fn entry(type_guid: &str, unique_guid: &str, first: u64, last: u64, name: &str) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&guid_bytes(type_guid));
    e[16..32].copy_from_slice(&guid_bytes(unique_guid));
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    // attributes (48..56) left zero
    for (i, u) in name.encode_utf16().enumerate() {
        let off = 56 + i * 2;
        e[off..off + 2].copy_from_slice(&u.to_le_bytes());
    }
    e
}

/// Build one 512-byte sector holding a GPT header with a valid self-CRC.
#[allow(clippy::too_many_arguments)]
fn header(
    my_lba: u64,
    alt_lba: u64,
    entry_lba: u64,
    first_usable: u64,
    last_usable: u64,
    num: u32,
    esize: u32,
    array_crc: u32,
) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0..8].copy_from_slice(b"EFI PART");
    s[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    s[12..16].copy_from_slice(&92u32.to_le_bytes());
    // header CRC (16..20) and reserved (20..24) left zero
    s[24..32].copy_from_slice(&my_lba.to_le_bytes());
    s[32..40].copy_from_slice(&alt_lba.to_le_bytes());
    s[40..48].copy_from_slice(&first_usable.to_le_bytes());
    s[48..56].copy_from_slice(&last_usable.to_le_bytes());
    s[56..72].copy_from_slice(&guid_bytes(DISK_GUID));
    s[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    s[80..84].copy_from_slice(&num.to_le_bytes());
    s[84..88].copy_from_slice(&esize.to_le_bytes());
    s[88..92].copy_from_slice(&array_crc.to_le_bytes());
    // Self-CRC over the first 92 bytes with the CRC field already zero.
    let crc = gpt_forensic::crc32::checksum(&s[..92]);
    s[16..20].copy_from_slice(&crc.to_le_bytes());
    s
}

/// Build a clean, spec-valid GPT disk image with two partitions.
pub fn build_gpt() -> Vec<u8> {
    let mut disk = vec![0u8; SECTOR * SECTORS];

    let mut array = vec![0u8; 4 * 128];
    array[0..128].copy_from_slice(&entry(
        LINUX_GUID,
        "00000000-0000-0000-0000-000000000001",
        3,
        30,
        "Linux",
    ));
    array[128..256].copy_from_slice(&entry(
        EFI_GUID,
        "00000000-0000-0000-0000-000000000002",
        31,
        50,
        "EFI System",
    ));
    let array_crc = gpt_forensic::crc32::checksum(&array);

    let primary = header(1, 63, 2, 3, 61, 4, 128, array_crc);
    let backup = header(63, 1, 62, 3, 61, 4, 128, array_crc);

    disk[SECTOR..SECTOR + 512].copy_from_slice(&primary);
    disk[2 * SECTOR..2 * SECTOR + array.len()].copy_from_slice(&array);
    disk[62 * SECTOR..62 * SECTOR + array.len()].copy_from_slice(&array);
    disk[63 * SECTOR..63 * SECTOR + 512].copy_from_slice(&backup);
    disk
}

/// Corrupt the primary header body so its stored self-CRC no longer matches —
/// the canonical `GPT-HDR-CRC` tampering signal.
pub fn corrupt_primary_header(disk: &mut [u8]) {
    disk[SECTOR + 8] ^= 0xFF; // flip a revision byte; stored CRC is now stale
}
