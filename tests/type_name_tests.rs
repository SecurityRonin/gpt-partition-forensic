//! GPT partition-type GUID → human-readable name (knowledge from forensicnomicon).

use gpt_forensic::entry::GptEntry;

const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
const LINUX_TYPE: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

fn entry(type_guid: [u8; 16]) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&type_guid);
    e
}

#[test]
fn resolves_known_type_names() {
    let esp = GptEntry::parse(&entry(ESP_TYPE)).unwrap();
    assert_eq!(esp.type_name(), Some("EFI System Partition"));

    let linux = GptEntry::parse(&entry(LINUX_TYPE)).unwrap();
    assert_eq!(linux.type_name(), Some("Linux filesystem data"));
}

#[test]
fn unknown_type_name_is_none() {
    let mut g = [0u8; 16];
    g[0] = 0xDE;
    g[1] = 0xAD;
    let e = GptEntry::parse(&entry(g)).unwrap();
    assert_eq!(e.type_name(), None);
}
