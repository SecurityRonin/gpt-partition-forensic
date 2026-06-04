//! `gpt analyse` — render a full forensic analysis as a fixed-width ASCII report.

use std::io::{Read, Seek};

use gpt_forensic::Error;

/// Run a full GPT forensic analysis over `reader` and format an ASCII report.
///
/// `disk_size` bounds the backup-GPT read (`0` = locate it via the primary
/// header alone); `image_name` is echoed into the report header.
pub fn run<R: Read + Seek>(reader: &mut R, disk_size: u64, image_name: &str) -> Result<String, Error> {
    let _ = (reader, disk_size, image_name);
    unimplemented!("cmd::analyse::run")
}
