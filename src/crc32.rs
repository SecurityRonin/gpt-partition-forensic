//! CRC-32/ISO-HDLC — the checksum GPT uses for its header and partition array.
//!
//! Polynomial `0xEDB88320` (reflected), initial value `0xFFFFFFFF`, final XOR
//! `0xFFFFFFFF` — identical to zlib/PNG. Implemented table-free (bitwise) to keep
//! the crate dependency-light; GPT integrity fields are small, so throughput is
//! not a concern.

/// Reflected CRC-32 polynomial (ISO-HDLC / zlib).
const POLY: u32 = 0xEDB8_8320;

/// Compute the CRC-32/ISO-HDLC checksum of `data`.
///
/// The canonical check value `checksum(b"123456789") == 0xCBF43926` holds.
#[must_use]
pub fn checksum(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // Branchless reflected step: subtract the polynomial when the low
            // bit is set after shifting right.
            crc = (crc >> 1) ^ (POLY & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
