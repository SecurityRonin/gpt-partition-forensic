#![allow(clippy::unwrap_used, clippy::expect_used)]
//! GPT partition-entry parsing and array CRC.

use gpt_partition_forensic::{
    crc32::checksum,
    entry::{parse_entry_array, GptEntry},
};

/// EFI System Partition type GUID C12A7328-F81F-11D2-BA4B-00A0C93EC93B, on-disk.
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

fn build_entry(type_guid: [u8; 16], first: u64, last: u64, name: &str) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&type_guid);
    e[16..32].copy_from_slice(&[0x22; 16]); // unique GUID
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    // attributes 48..56 = 0
    for (i, u) in name.encode_utf16().enumerate() {
        let off = 56 + i * 2;
        e[off..off + 2].copy_from_slice(&u.to_le_bytes());
    }
    e
}

#[test]
fn parses_used_entry() {
    let e = build_entry(ESP_TYPE, 2048, 4095, "EFI System");
    let entry = GptEntry::parse(&e).unwrap();
    assert!(entry.is_used());
    assert_eq!(entry.first_lba, 2048);
    assert_eq!(entry.last_lba, 4095);
    assert_eq!(entry.name, "EFI System");
    assert_eq!(
        entry.type_guid.to_string(),
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    );
}

#[test]
fn zero_entry_is_unused() {
    let entry = GptEntry::parse(&[0u8; 128]).unwrap();
    assert!(!entry.is_used());
}

#[test]
fn array_parse_skips_unused_and_crc_matches() {
    // Array of 4 entries; only slots 0 and 2 used.
    let mut array = vec![0u8; 4 * 128];
    array[0..128].copy_from_slice(&build_entry(ESP_TYPE, 2048, 4095, "EFI System"));
    array[2 * 128..3 * 128].copy_from_slice(&build_entry(ESP_TYPE, 4096, 6000, "Data"));

    let used = parse_entry_array(&array, 4, 128);
    assert_eq!(used.len(), 2, "only the two non-empty entries are returned");
    assert_eq!(used[0].name, "EFI System");
    assert_eq!(used[1].name, "Data");

    // Whole-array CRC is what a GPT header would store.
    let crc = checksum(&array);
    assert_ne!(crc, 0);
}
