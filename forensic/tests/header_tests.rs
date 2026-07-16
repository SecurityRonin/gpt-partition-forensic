#![allow(clippy::unwrap_used, clippy::expect_used)]
//! GPT header parsing + self-CRC validation.

use gpt_partition_forensic::{crc32::checksum, header::GptHeader, Error};

/// Build a 512-byte LBA holding a GPT header with a correct self-CRC.
fn build_header(
    my_lba: u64,
    alternate_lba: u64,
    entry_lba: u64,
    num_entries: u32,
    entry_size: u32,
    array_crc: u32,
) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0..8].copy_from_slice(b"EFI PART");
    s[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    s[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
                                                     // 16..20 header_crc32 — filled last
    s[24..32].copy_from_slice(&my_lba.to_le_bytes());
    s[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    s[40..48].copy_from_slice(&34u64.to_le_bytes()); // first_usable_lba
    s[48..56].copy_from_slice(&(my_lba.max(alternate_lba)).to_le_bytes()); // last_usable (rough)
    s[56..72].copy_from_slice(&[0x11; 16]); // disk_guid
    s[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    s[80..84].copy_from_slice(&num_entries.to_le_bytes());
    s[84..88].copy_from_slice(&entry_size.to_le_bytes());
    s[88..92].copy_from_slice(&array_crc.to_le_bytes());
    let crc = checksum(&s[0..92]);
    s[16..20].copy_from_slice(&crc.to_le_bytes());
    s
}

#[test]
fn parses_fields() {
    let s = build_header(1, 8191, 2, 128, 128, 0xDEAD_BEEF);
    let h = GptHeader::parse(&s).unwrap();
    assert_eq!(h.my_lba, 1);
    assert_eq!(h.alternate_lba, 8191);
    assert_eq!(h.partition_entry_lba, 2);
    assert_eq!(h.num_partition_entries, 128);
    assert_eq!(h.partition_entry_size, 128);
    assert_eq!(h.partition_array_crc32, 0xDEAD_BEEF);
    assert_eq!(h.header_size, 92);
    assert_eq!(h.revision, 0x0001_0000);
}

#[test]
fn valid_self_crc_recognised() {
    let s = build_header(1, 8191, 2, 128, 128, 0);
    let h = GptHeader::parse(&s).unwrap();
    assert!(
        h.header_crc_valid,
        "freshly-built header must self-validate"
    );
}

#[test]
fn corrupted_header_fails_crc() {
    let mut s = build_header(1, 8191, 2, 128, 128, 0);
    s[24] ^= 0xFF; // flip a byte of my_lba — CRC no longer matches
    let h = GptHeader::parse(&s).unwrap();
    assert!(!h.header_crc_valid, "tampered header must fail self-CRC");
}

#[test]
fn bad_signature_errors() {
    let mut s = build_header(1, 8191, 2, 128, 128, 0);
    s[0] = b'X';
    assert!(matches!(GptHeader::parse(&s), Err(Error::BadSignature)));
}

#[test]
fn too_short_errors() {
    assert!(matches!(
        GptHeader::parse(&[0u8; 16]),
        Err(Error::TooShort { .. })
    ));
}

#[test]
fn implausible_header_size_marks_crc_invalid() {
    // header_size below the 92-byte minimum is implausible: compute_header_crc
    // returns None, so the header cannot self-validate (crc_valid == false).
    let mut s = build_header(1, 8191, 2, 128, 128, 0);
    s[12..16].copy_from_slice(&8u32.to_le_bytes()); // header_size = 8 (< 92)
    let h = GptHeader::parse(&s).unwrap();
    assert!(
        !h.header_crc_valid,
        "an implausible header_size cannot yield a valid self-CRC"
    );
}

#[test]
fn oversized_header_size_marks_crc_invalid() {
    // header_size larger than the buffer is equally implausible → crc None/invalid.
    let mut s = build_header(1, 8191, 2, 128, 128, 0);
    s[12..16].copy_from_slice(&1024u32.to_le_bytes()); // header_size > 512 sector
    let h = GptHeader::parse(&s).unwrap();
    assert!(!h.header_crc_valid);
}
