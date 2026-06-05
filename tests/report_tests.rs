//! Text report rendering (moved here from the former CLI crate).

mod common_gpt;
use common_gpt::{build_gpt, build_gpt_unknown_type};
use gpt_forensic::{analyse, report::text_report};
use std::io::Cursor;

#[test]
fn renders_full_gpt_details() {
    let disk = build_gpt();
    let a = analyse(&mut Cursor::new(&disk), disk.len() as u64).unwrap();
    let r = text_report(&a);
    assert!(r.contains("GPT Forensic Analysis"), "{r}");
    assert!(r.contains("Disk GUID:"), "{r}");
    assert!(r.contains("GPT SHA-256:"), "{r}");
    assert!(r.contains("Partitions (2)"), "{r}");
    assert!(r.contains("Linux filesystem data"), "{r}");
    assert!(r.contains("Result:          clean"), "{r}");
}

#[test]
fn renders_raw_guid_for_unknown_type() {
    let disk = build_gpt_unknown_type();
    let a = analyse(&mut Cursor::new(&disk), disk.len() as u64).unwrap();
    assert!(text_report(&a).contains("DEADBEEF"));
}
