//! `gpt dump` — annotated hex (or raw bytes) of one 512-byte LBA.

use std::io::{Read, Seek, SeekFrom};

use gpt_forensic::Error;

/// Logical sector size (bytes). GPT addresses everything in 512-byte LBAs.
const SECTOR: u64 = 512;

/// Annotated hex dump of the 512-byte sector at `lba`.
///
/// Output is pure ASCII, fixed-width, 16 bytes per row split into two 8-byte
/// groups, with a printable-ASCII sidebar between pipe separators:
///
///   LBA 1  (offset 0x00000200)  512 bytes
///   --------------------------------------------------------------------------------
///   00000000  45 46 49 20 50 41 52 54  00 00 01 00 5C 00 00 00  | EFI PART........ |
pub fn run<R: Read + Seek>(reader: &mut R, lba: u64) -> Result<String, Error> {
    let sector = read_sector(reader, lba)?;
    let offset = lba * SECTOR;

    let mut out = String::new();
    out.push_str(&format!("LBA {lba}  (offset 0x{offset:08X})  512 bytes\n"));
    out.push_str(&"-".repeat(80));
    out.push('\n');

    for (row, chunk) in sector.chunks(16).enumerate() {
        let addr = row * 16;
        let split = chunk.len().min(8);
        let left = hex_join(&chunk[..split]);
        let right = hex_join(&chunk[split..]);
        // Printable ASCII (0x20..=0x7E) verbatim; everything else as '.'.
        let ascii: String = chunk
            .iter()
            .map(|b| if (0x20..=0x7E).contains(b) { *b as char } else { '.' })
            .collect();
        out.push_str(&format!("{addr:08X}  {left:<23}  {right:<23}  | {ascii:<16} |\n"));
    }
    Ok(out)
}

/// Raw 512-byte payload of the sector at `lba` — for piping into other tools.
pub fn run_raw<R: Read + Seek>(reader: &mut R, lba: u64) -> Result<Vec<u8>, Error> {
    Ok(read_sector(reader, lba)?.to_vec())
}

/// Read one 512-byte sector at `lba`.
fn read_sector<R: Read + Seek>(reader: &mut R, lba: u64) -> Result<[u8; 512], Error> {
    reader.seek(SeekFrom::Start(lba * SECTOR))?;
    let mut buf = [0u8; 512];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Join bytes as space-separated two-digit uppercase hex.
fn hex_join(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
