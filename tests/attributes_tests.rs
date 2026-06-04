//! GPT partition attribute-flag decoding (knowledge from forensicnomicon).

use gpt_forensic::entry::GptEntry;

fn entry_with_attrs(attrs: u64) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0] = 0x01; // non-zero type GUID byte → in-use
    e[48..56].copy_from_slice(&attrs.to_le_bytes());
    e
}

#[test]
fn decodes_concealment_flags() {
    // Hidden (bit 62) + no-automount (bit 63).
    let attrs = (1u64 << 62) | (1u64 << 63);
    let e = GptEntry::parse(&entry_with_attrs(attrs)).unwrap();
    assert_eq!(e.attribute_names(), vec!["hidden", "no-automount"]);
}

#[test]
fn no_flags_is_empty() {
    let e = GptEntry::parse(&entry_with_attrs(0)).unwrap();
    assert!(e.attribute_names().is_empty());
}

#[test]
fn legacy_bios_bootable_flag() {
    let e = GptEntry::parse(&entry_with_attrs(1u64 << 2)).unwrap();
    assert_eq!(e.attribute_names(), vec!["legacy-bios-bootable"]);
}
