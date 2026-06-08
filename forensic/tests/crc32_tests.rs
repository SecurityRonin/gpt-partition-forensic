#![allow(clippy::unwrap_used, clippy::expect_used)]
//! CRC-32/ISO-HDLC known-answer tests.
//!
//! GPT integrity fields use CRC-32/ISO-HDLC (polynomial 0xEDB88320, reflected,
//! init 0xFFFFFFFF, final XOR 0xFFFFFFFF) — identical to zlib/PNG. The canonical
//! check value for the ASCII string "123456789" is 0xCBF43926.

use gpt_partition_forensic::crc32::checksum;

#[test]
fn empty_input_is_zero() {
    assert_eq!(checksum(&[]), 0);
}

#[test]
fn canonical_check_value() {
    assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
}

#[test]
fn single_byte_vectors() {
    // Independently reproducible zlib crc32 values.
    assert_eq!(checksum(b"a"), 0xE8B7_BE43);
    assert_eq!(checksum(b"abc"), 0x3524_41C2);
}
