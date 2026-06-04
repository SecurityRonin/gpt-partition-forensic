//! `gpt dump` — annotated hex (or raw bytes) of one 512-byte LBA.

use std::io::{Read, Seek};

use gpt_forensic::Error;

/// Annotated hex dump of the 512-byte sector at `lba`.
pub fn run<R: Read + Seek>(reader: &mut R, lba: u64) -> Result<String, Error> {
    let _ = (reader, lba);
    unimplemented!("cmd::dump::run")
}

/// Raw 512-byte payload of the sector at `lba` — for piping into other tools.
pub fn run_raw<R: Read + Seek>(reader: &mut R, lba: u64) -> Result<Vec<u8>, Error> {
    let _ = (reader, lba);
    unimplemented!("cmd::dump::run_raw")
}
