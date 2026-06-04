//! Fuzz target: parse arbitrary bytes as a GPT header.
//!
//! Invariants: never panics; CRC validation and field access stay total.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = gpt_forensic::header::GptHeader::parse(data) {
        let _ = h.header_crc_valid;
        let _ = h.my_lba;
        let _ = h.alternate_lba;
        let _ = h.num_partition_entries;
        let _ = h.partition_entry_size;
        let _ = h.disk_guid.to_string();
    }
});
