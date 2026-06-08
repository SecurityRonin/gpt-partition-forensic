//! Fuzz target: parse arbitrary bytes with the pure parser (`gpt-partition-core`).
//!
//! Invariants: never panics; CRC validation and field access stay total.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = gpt::header::GptHeader::parse(data) {
        let _ = h.header_crc_valid;
        let _ = h.my_lba;
        let _ = h.alternate_lba;
        let _ = h.num_partition_entries;
        let _ = h.partition_entry_size;
        let _ = h.disk_guid.to_string();
    }
    // Also exercise the entry-array and protective-MBR readers directly.
    let _ = gpt::entry::parse_entry_array(data, 128, 128);
    let _ = gpt::mbr::parse_mbr_entries(data);
});
