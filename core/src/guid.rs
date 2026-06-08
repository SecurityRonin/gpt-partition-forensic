//! GPT GUID (mixed-endian) parsing and display.
//!
//! A GPT GUID is stored as 16 bytes where the first three groups are
//! little-endian and the last two are big-endian — the standard Microsoft GUID
//! on-disk layout. The [`Guid`] [`Display`](core::fmt::Display) impl renders the
//! canonical `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` form.

use core::fmt;

/// A 16-byte GPT GUID in on-disk (mixed-endian) byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The all-zero GUID — an unused partition entry's type GUID.
    pub const ZERO: Guid = Guid([0u8; 16]);

    /// `true` when every byte is zero (unused entry).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        // Groups 1–3 little-endian, groups 4–5 big-endian.
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            b[3], b[2], b[1], b[0],
            b[5], b[4],
            b[7], b[6],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }
}
