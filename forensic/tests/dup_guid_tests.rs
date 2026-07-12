#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Intra-disk duplicate partition unique-GUID detection.
//!
//! Every GPT partition's unique GUID is meant to be unique within the disk. Two
//! entries sharing one indicates a cloned/duplicated entry — a tampering signal.

use gpt_partition_forensic::{
    collision::find_duplicate_partition_guids, entry::GptEntry, findings::AnomalyKind, guid::Guid,
};

fn ent(unique: [u8; 16]) -> GptEntry {
    GptEntry {
        type_guid: Guid([0x11; 16]),
        unique_guid: Guid(unique),
        first_lba: 0,
        last_lba: 0,
        attributes: 0,
        name: String::new(),
        volume_serial: None,
        encryption: None,
    }
}

#[test]
fn finds_duplicate_unique_guids() {
    let g = [0xAB; 16];
    let parts = vec![ent(g), ent([0x01; 16]), ent(g)];
    assert_eq!(find_duplicate_partition_guids(&parts), vec![(0, 2)]);
}

#[test]
fn distinct_guids_have_no_duplicate() {
    let parts = vec![ent([1; 16]), ent([2; 16])];
    assert!(find_duplicate_partition_guids(&parts).is_empty());
}

#[test]
fn anomaly_kind_exists() {
    // The analysis surfaces it as DuplicatePartitionGuid.
    let _ = AnomalyKind::DuplicatePartitionGuid { a: 0, b: 1 };
}
