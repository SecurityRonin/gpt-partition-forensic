//! Fuzz target: feed arbitrary bytes as a disk image to `analyse`.
//!
//! Exercises header parsing, CRC validation, entry-array parsing (including
//! UTF-16 name decode), backup reconciliation, overlap and bounds checks.
//!
//! Invariants:
//! - Never panics.
//! - Returns `Ok` or a well-typed `Err` — no unwrap panics.
//! - All fields of `GptAnalysis` are accessible without panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let disk_size = data.len() as u64;
    let mut cursor = Cursor::new(data);

    match gpt_forensic::analyse(&mut cursor, disk_size) {
        Ok(analysis) => {
            let _ = analysis.disk_guid.to_string();
            let _ = analysis.max_severity();
            let _ = &analysis.backup;
            let _ = analysis.primary.header_crc_valid;
            for p in &analysis.partitions {
                let _ = p.first_lba;
                let _ = p.last_lba;
                let _ = &p.name;
                let _ = p.type_guid.to_string();
            }
            for a in &analysis.anomalies {
                let _ = a.severity;
                let _ = &a.note;
            }
        }
        Err(gpt_forensic::Error::BadSignature) => {}
        Err(gpt_forensic::Error::TooShort { .. }) => {}
        Err(gpt_forensic::Error::Io(_)) => {}
    }
});
